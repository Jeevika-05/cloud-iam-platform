use crate::client::ApiClient;
use serde::Serialize;
use std::collections::HashMap;
use totp_rs::{Algorithm, TOTP, Secret};

const BRUTE_FORCE_ATTEMPTS: usize = 8;

// ── Report ───────────────────────────────────────

#[derive(Serialize)]
pub struct MfaAttackReport {
    pub attack: String,
    pub timestamp: String,
    pub identity: String,
    pub setup_success: bool,
    pub replay: ReplayResult,
    pub brute_force: BruteForceResult,
    pub verdict: String,
}

#[derive(Serialize)]
pub struct ReplayResult {
    pub first_use_status: u16,
    pub first_use_code: String,
    pub replay_status: u16,
    pub replay_code: String,
    pub replay_blocked: bool,
}

#[derive(Serialize)]
pub struct BruteForceResult {
    pub total_attempts: usize,
    pub invalid_code_count: usize,
    pub rate_limited_count: usize,
    pub token_reuse_count: usize,
    pub rate_limit_triggered: bool,
    pub status_distribution: HashMap<u16, usize>,
    pub detection_codes: HashMap<String, usize>,
}

// ── TOTP helper ──────────────────────────────────

fn generate_totp_code(secret_base32: &str) -> Result<String, String> {
    let secret = Secret::Encoded(secret_base32.to_string())
        .to_bytes()
        .map_err(|e| format!("bad TOTP secret: {}", e))?;

    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret)
        .map_err(|e| format!("TOTP init error: {}", e))?;

    Ok(totp.generate_current()
        .map_err(|e| format!("TOTP generate error: {}", e))?)
}

// ── Attack entry point ───────────────────────────

pub async fn run(
    client: &ApiClient,
    email: &str,
    password: &str,
) -> Result<MfaAttackReport, String> {

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 0 — Setup: register + enable MFA
    //
    //  Handles both fresh and re-run scenarios:
    //  - Fresh: register → login → setup MFA → verify
    //  - Re-run: account already has MFA → skip setup
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    let mfa_email = email.to_string();
    let mfa_password = password;

    println!("[MFA] Phase 0: Setting up MFA-enabled account...");
    println!("[MFA]   Email: {}", mfa_email);

    // Register (ignore duplicate)
    match client.register(&mfa_email, mfa_password, "MFA-Attacker").await {
        Ok(()) => println!("[MFA]   Account registered"),
        Err(e) => println!("[MFA]   Registration: {}", e),
    }

    // Try normal login first — if it works, MFA isn't enabled yet
    let totp_secret = match client.login(&mfa_email, mfa_password).await {
        Ok(login) => {
            // MFA not yet enabled → set it up now
            let access_token = login.access_token.clone();
            println!("[MFA]   Logged in (MFA not yet enabled)");

            // Setup MFA — get TOTP secret
            let secret = client.mfa_setup(&access_token).await
                .map_err(|e| format!("MFA setup failed: {}", e))?;
            println!("[MFA]   TOTP secret received ({} chars)", secret.len());

            // Generate a valid code and finalize MFA enrollment
            let valid_code = generate_totp_code(&secret)?;
            client.mfa_verify(&access_token, &valid_code).await
                .map_err(|e| format!("MFA verify failed: {}", e))?;
            println!("[MFA]   MFA enabled successfully");

            secret
        }
        Err(e) => {
            if e.contains("MFA_REQUIRED") {
                // MFA already enabled from a previous run
                println!("[MFA]   MFA already enabled (re-run detected)");
                println!("[MFA]   ⚠ Cannot recover TOTP secret — using attack phases only");

                // We don't have the TOTP secret, but we can still test
                // replay and brute-force using tempTokens with wrong codes
                String::new()
            } else {
                return Err(format!("initial login failed: {}", e));
            }
        }
    };

    let has_totp_secret = !totp_secret.is_empty();

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 1 — Temp Token Replay Attack
    //
    //  Goal: prove that a tempToken cannot be used
    //  twice, even if the first use was with a
    //  wrong MFA code.
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    println!();
    println!("[MFA] Phase 1: Temp Token Replay Attack");

    // Login → MFA_REQUIRED → capture tempToken
    let mfa_login = client.login_expect_mfa(&mfa_email, mfa_password).await
        .map_err(|e| format!("MFA login failed: {}", e))?;
    let stolen_token = mfa_login.temp_token.clone();
    println!("[MFA]   Captured tempToken ({} chars)", stolen_token.len());

    // First use: submit with wrong code (consumes the JTI)
    println!("[MFA]   Use 1: wrong code (consumes token JTI)...");
    let first_use = client.mfa_validate_login(&stolen_token, "000000").await;
    println!("[MFA]     status={} code={}", first_use.status, first_use.code);

    // Second use: replay same tempToken (should be rejected)
    println!("[MFA]   Use 2: replay SAME tempToken...");
    let replay_use = client.mfa_validate_login(&stolen_token, "000000").await;
    println!("[MFA]     status={} code={}", replay_use.status, replay_use.code);

    let replay_blocked = replay_use.status == 401
        && (replay_use.code == "TOKEN_REUSE_DETECTED"
            || replay_use.code == "TOKEN_INVALID"
            || replay_use.code == "TOKEN_EXPIRED");

    let replay_result = ReplayResult {
        first_use_status: first_use.status,
        first_use_code: first_use.code,
        replay_status: replay_use.status,
        replay_code: replay_use.code,
        replay_blocked,
    };

    println!("[MFA]   Replay blocked: {}", replay_blocked);

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 2 — Brute Force Attack
    //
    //  Goal: hammer the MFA validate-login endpoint
    //  with wrong codes until the mfaLimiter kicks
    //  in (max 5 req / 15 min per user).
    //
    //  Each attempt gets a fresh tempToken via a
    //  new login, so we isolate rate-limit testing
    //  from token-reuse detection.
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    println!();
    println!("[MFA] Phase 2: Brute Force ({} attempts)", BRUTE_FORCE_ATTEMPTS);

    let mut invalid_code_count: usize = 0;
    let mut rate_limited_count: usize = 0;
    let mut token_reuse_count: usize = 0;
    let mut status_dist: HashMap<u16, usize> = HashMap::new();
    let mut code_dist: HashMap<String, usize> = HashMap::new();

    for i in 0..BRUTE_FORCE_ATTEMPTS {
        let bad_code = format!("{:06}", i);

        // Try to get a fresh token; fall back to reusing the last one
        let token = match client.login_expect_mfa(&mfa_email, mfa_password).await {
            Ok(r) => r.temp_token,
            Err(e) => {
                println!("[MFA]   Attempt {}: login blocked ({}), using stale token", i + 1, e);
                stolen_token.clone()  // reuse — will get TOKEN_REUSE_DETECTED
            }
        };

        let result = client.mfa_validate_login(&token, &bad_code).await;

        println!("[MFA]   Attempt {}: code={} → status={} resp={}",
            i + 1, bad_code, result.status, result.code);

        *status_dist.entry(result.status).or_insert(0) += 1;
        if !result.code.is_empty() {
            *code_dist.entry(result.code.clone()).or_insert(0) += 1;
        }

        match result.status {
            400 => invalid_code_count += 1,
            429 => rate_limited_count += 1,
            401 if result.code == "TOKEN_REUSE_DETECTED" => token_reuse_count += 1,
            401 => invalid_code_count += 1,
            _ => {}
        }
    }

    let rate_limit_triggered = rate_limited_count > 0;

    let brute_force_result = BruteForceResult {
        total_attempts: BRUTE_FORCE_ATTEMPTS,
        invalid_code_count,
        rate_limited_count,
        token_reuse_count,
        rate_limit_triggered,
        status_distribution: status_dist,
        detection_codes: code_dist,
    };

    println!("[MFA]   Rate limit triggered: {}", rate_limit_triggered);

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 3 (optional) — Validate correct TOTP still works
    //
    //  Only possible if we have the secret (fresh setup)
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    if has_totp_secret {
        println!();
        println!("[MFA] Phase 3: Verifying correct TOTP still works");

        // Wait a moment for TOTP counter to advance (avoid reuse of same code)
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        match client.login_expect_mfa(&mfa_email, mfa_password).await {
            Ok(fresh_login) => {
                let valid_code = generate_totp_code(&totp_secret)?;
                let valid_result = client
                    .mfa_validate_login(&fresh_login.temp_token, &valid_code)
                    .await;

                if valid_result.status == 200 {
                    println!("[MFA]   ✅ Valid TOTP accepted (system functional)");
                } else {
                    println!("[MFA]   ⚠ Valid TOTP rejected: status={} code={}",
                        valid_result.status, valid_result.code);
                    println!("[MFA]   (may be rate-limited from brute-force phase)");
                }
            }
            Err(e) => {
                println!("[MFA]   ⚠ Could not get fresh tempToken: {}", e);
            }
        }
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  VERDICT
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    let verdict = if replay_blocked && rate_limit_triggered {
        "SECURE"
    } else if !replay_blocked && !rate_limit_triggered {
        "CRITICAL"
    } else if !replay_blocked {
        "VULNERABLE — replay not blocked"
    } else {
        "PARTIAL — replay blocked but no rate limit"
    };

    println!();
    println!("[MFA] Verdict: {}", verdict);

    Ok(MfaAttackReport {
        attack: "mfa_replay_brute_force".into(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        identity: mfa_email,
        setup_success: true,
        replay: replay_result,
        brute_force: brute_force_result,
        verdict: verdict.into(),
    })
}
