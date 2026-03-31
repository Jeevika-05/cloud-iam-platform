use crate::event::GraphEvent;
use crate::client::ApiClient;
use serde::Serialize;
use std::collections::HashMap;
use reqwest::Client;
use std::time::Duration;
use serde_json::Value;

const BOTS_COUNT: usize = 75;
const GUESSES_PER_BOT: usize = 2;

// ── Report ───────────────────────────────────────

#[derive(Serialize)]
pub struct MfaDistributedReport {
    pub attack: String,
    pub timestamp: String,
    pub total_requests: usize,
    pub blocked_count: usize,
    pub status_distribution: HashMap<u16, usize>,
    pub verdict: String,
}

// ── Attack implementation ────────────────────────

pub async fn run(
    client: &ApiClient,
    email: &str,
    password: &str,
    user_id: &str,
    correlation_id: &str,
) -> Result<(MfaDistributedReport, GraphEvent), String> {
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 1 — Executing mfa_brute_force_distributed
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    println!();
    println!("[MFA] Phase 1: Executing mfa_brute_force_distributed");

    println!("[MFA] Spawning {} botnet tasks...", BOTS_COUNT);

    let mut handles = Vec::with_capacity(BOTS_COUNT);

    for i in 0..BOTS_COUNT {
        // Create unique bot context
        let bot_ip = format!("10.10.0.{}", i);
        let email_clone = email.to_string();
        let pass_clone = password.to_string();
        let base_url = client.base_url().to_string();

        let h = tokio::spawn(async move {
            let mut bot_blocked = 0;
            let mut bot_statuses = Vec::new();

            // Unique client instance per bot to use correct IP headers
            let bot_client = ApiClient::new(&base_url, Some(bot_ip.as_str()), Some("Botnet-Attacker"));
            println!("[BOT] Using IP: {}", bot_ip);

            // 1. Perform login
            if let Ok(mfa_login) = bot_client.login_expect_mfa(&email_clone, &pass_clone).await {
                let temp_token = mfa_login.temp_token;

                // 2. Perform N guesses
                for j in 0..GUESSES_PER_BOT {
                    // Start guesses differently per bot to avoid overlap logs identically
                    let bad_code = format!("{:06}", (i * GUESSES_PER_BOT) + j);
                    let result = bot_client.mfa_validate_login(&temp_token, &bad_code).await;

                    bot_statuses.push(result.status);
                    if result.status == 429 {
                        bot_blocked += 1;
                    }
                }
            }

            (bot_blocked, bot_statuses)
        });

        handles.push(h);
    }

    let mut total_blocked = 0;
    let mut total_requests = 0;
    let mut status_dist: HashMap<u16, usize> = HashMap::new();

    for h in handles {
        match h.await {
            Ok((bot_blocked, bot_statuses)) => {
                total_blocked += bot_blocked;
                total_requests += bot_statuses.len();
                for status in bot_statuses {
                    *status_dist.entry(status).or_insert(0) += 1;
                }
            }
            Err(e) => eprintln!("[MFA] Task panic: {}", e),
        }
    }

    let verdict = if total_blocked > 0 {
        "SECURE"
    } else {
        "VULNERABLE"
    };

    println!();
    println!("[MFA] Distributed Attack Complete");
    println!("[MFA]   Total Requests: {}", total_requests);
    println!("[MFA]   Blocked (429):  {}", total_blocked);
    println!("[MFA] Verdict: {}", verdict);

    let report = MfaDistributedReport {
        attack: "mfa_brute_force_distributed".into(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        total_requests,
        blocked_count: total_blocked,
        status_distribution: status_dist,
        verdict: verdict.into(),
    };

    let event = GraphEvent::new_with_ip(
        correlation_id,
        user_id,
        Some(email.to_string()),
        "MFA_BRUTE_FORCE_DISTRIBUTED",
        "/api/v1/auth/mfa/validate-login",
        &report.verdict,
        "10.10.0.1".to_string(), // ✅ FIX: Use a representative IP corresponding to distributed
    );

    Ok((report, event))
}
