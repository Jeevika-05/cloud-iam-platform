use crate::event::GraphEvent;
use crate::client::ApiClient;
use serde::Serialize;
use std::collections::HashMap;

const BRUTE_FORCE_ATTEMPTS: usize = 15;

// ── Report ───────────────────────────────────────

#[derive(Serialize)]
pub struct MfaAttackReport {
    pub attack: String,
    pub total_requests: usize,
    pub blocked_count: usize,
    pub status_distribution: HashMap<u16, usize>,
    pub verdict: String,
}

// ── Attack implementation ────────────────────────

async fn mfa_brute_force_single_ip(
    client: &ApiClient,
    email: &str,
    password: &str,
) -> Result<MfaAttackReport, String> {
    println!("[MFA] Executing mfa_brute_force_single_ip");

    // 1. Perform login -> extract tempToken
    let mfa_login = client.login_expect_mfa(email, password).await
        .map_err(|e| format!("MFA login failed: {}", e))?;
    let temp_token = mfa_login.temp_token;
    
    println!("[MFA]   Captured tempToken ({} chars)", temp_token.len());

    let mut blocked_count = 0;
    let mut status_dist: HashMap<u16, usize> = HashMap::new();

    // 2. Send multiple requests to validate-login with the same tempToken
    for i in 0..BRUTE_FORCE_ATTEMPTS {
        let bad_code = format!("{:06}", i);
        let result = client.mfa_validate_login(&temp_token, &bad_code).await;

        println!("[MFA]   Attempt {}: code={} → status={}", i + 1, bad_code, result.status);

        *status_dist.entry(result.status).or_insert(0) += 1;

        if result.status == 429 {
            blocked_count += 1;
        }
    }

    let verdict = if blocked_count > 0 {
        "SECURE"
    } else {
        "VULNERABLE"
    };

    println!();
    println!("[MFA] Verdict: {}", verdict);

    Ok(MfaAttackReport {
        attack: "mfa_brute_force_single_ip".into(),
        total_requests: BRUTE_FORCE_ATTEMPTS,
        blocked_count,
        status_distribution: status_dist,
        verdict: verdict.into(),
    })
}

// ── Attack entry point ───────────────────────────

pub async fn run(
    client: &ApiClient,
    email: &str,
    password: &str,
    user_id: &str,
    correlation_id: &str,
) -> Result<(MfaAttackReport, GraphEvent), String> {

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 1 — Run New Attack
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


    println!();
    let report = mfa_brute_force_single_ip(client, email, password).await?;

    let event = GraphEvent::new(
        correlation_id,
        user_id,
        Some(email.to_string()),
        "MFA_BRUTE_FORCE_SINGLE_IP",
        "/api/v1/mfa/validate-login",
        &report.verdict,
    );

    Ok((report, event))
}
