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
    //  PHASE 0 — Setup: register, login, enable MFA
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    let mfa_email = format!("mfa-{}", email);
    let mfa_password = password;

    println!("[MFA] Phase 0: Setting up MFA-enabled account...");
    println!("[MFA]   Email: {}", mfa_email);

    // Register (ignore duplicate)
    match client.register(&mfa_email, mfa_password, "MFA-Attacker").await {
        Ok(()) => println!("[MFA]   Account registered"),
        Err(e) => println!("[MFA]   Registration: {}", e),
    }

    // Login (returns tokens — MFA not yet enabled)
    let login = client.login(&mfa_email, mfa_password).await
        .map_err(|e| format!("initial login failed: {}", e))?;
    let access_token = login.access_token.clone();
    println!("[MFA]   Logged in (access token obtained)");

    // Setup MFA — get TOTP secret
    let totp_secret = client.mfa_setup(&access_token).await
        .map_err(|e| format!("MFA setup failed: {}", e))?;
    println!("[MFA]   TOTP secret received ({} chars)", totp_secret.len());

    // Generate a valid code and finalize MFA enrollment
    let valid_code = generate_totp_code(&totp_secret)?;
    client.mfa_verify(&access_token, &valid_code).await
        .map_err(|e| format!("MFA verify failed: {}", e))?;
    println!("[MFA]   MFA enabled successfully");

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

    // 1st use: wrong code → consumes the JTI
    println!("[MFA]   Use 1: wrong code (consumes token JTI)...");
    let first_use = client.mfa_validate_login(&stolen_token, "000000").await;
    println!("[MFA]     status={} code={}", first_use.status, first_use.code);

    // 2nd use: replay same tempToken
    println!("[MFA]   Use 2: replay SAME tempToken...");
    let replay_use = client.mfa_validate_login(&stolen_token, "000000").await;
    println!("[MFA]     status={} code={}", replay_use.status, replay_use.code);

    let replay_blocked = replay_use.status == 401
        && (replay_use.code == "TOKEN_REUSE_DETECTED"
            || replay_use.code == "TOKEN_INVALID");

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
        setup_success: true,
        replay: replay_result,
        brute_force: brute_force_result,
        verdict: verdict.into(),
    })
}
