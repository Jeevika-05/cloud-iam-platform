mod client;
mod attacks;

use std::env;
use std::time::Duration;
use client::ApiClient;

/// Which attacks to execute.
#[derive(Debug, Clone, PartialEq)]
enum AttackMode {
    All,
    TokenRace,
    MfaReplay,
    Idor,
}

impl AttackMode {
    fn from_env() -> Self {
        match env::var("ATTACK_MODE")
            .unwrap_or_else(|_| "all".into())
            .to_lowercase()
            .trim()
        {
            s if s == "token_race" || s == "atk01" || s == "atk-01" => AttackMode::TokenRace,
            s if s == "mfa_replay" || s == "atk02" || s == "atk-02" => AttackMode::MfaReplay,
            s if s == "idor" || s == "atk03" || s == "atk-03" => AttackMode::Idor,
            _ => AttackMode::All,
        }
    }

    fn should_run(&self, target: &AttackMode) -> bool {
        *self == AttackMode::All || *self == *target
    }
}

#[tokio::main]
async fn main() {
    println!("╔══════════════════════════════════════════╗");
    println!("║   CloudShield Attack Simulation Engine   ║");
    println!("╚══════════════════════════════════════════╝");
    println!();

    let target_url = env::var("TARGET_URL").unwrap_or_else(|_| "http://localhost:3000".into());
    let email = env::var("ATTACK_EMAIL").unwrap_or_else(|_| "attacker@test.com".into());
    let password = env::var("ATTACK_PASSWORD").unwrap_or_else(|_| "Attack@123".into());
    let mode = AttackMode::from_env();

    println!("[CONFIG] Target : {}", target_url);
    println!("[CONFIG] Email  : {}", email);
    println!("[CONFIG] Mode   : {:?}", mode);
    println!();

    let client = ApiClient::new(&target_url);

    wait_for_api(&client).await;

    // ── Ensure attacker account exists ───────────
    println!("[SETUP] Registering attacker account...");
    match client.register(&email, &password, "Attacker").await {
        Ok(()) => println!("[SETUP] Account registered"),
        Err(e) => println!("[SETUP] Registration skipped: {}", e),
    }

    let mut reports: Vec<serde_json::Value> = Vec::new();
    let mut any_critical = false;

    // ═══════════════════════════════════════════════
    //  ATK-01: Token Race Condition
    // ═══════════════════════════════════════════════
    if mode.should_run(&AttackMode::TokenRace) {
        println!();
        println!("═══════════════════════════════════════════");
        println!("  ATK-01 ▸ Token Race Condition");
        println!("═══════════════════════════════════════════");
        println!();

        match attacks::token_race::run(&client, &email, &password).await {
            Ok(report) => {
                if report.verdict == "CRITICAL" { any_critical = true; }
                let val = serde_json::to_value(&report).unwrap();
                println!("[ATK-01] Verdict: {}", report.verdict);
                reports.push(val);
            }
            Err(e) => {
                eprintln!("[ATK-01] FAILED: {}", e);
                reports.push(serde_json::json!({
                    "attack": "token_race_condition",
                    "verdict": "ERROR",
                    "error": e
                }));
            }
        }
    } else {
        println!();
        println!("[SKIP] ATK-01 (Token Race) — not selected");
    }

    // ═══════════════════════════════════════════════
    //  ATK-02: MFA Replay + Brute Force
    // ═══════════════════════════════════════════════
    if mode.should_run(&AttackMode::MfaReplay) {
        println!();
        println!("═══════════════════════════════════════════");
        println!("  ATK-02 ▸ MFA Replay + Brute Force");
        println!("═══════════════════════════════════════════");
        println!();

        match attacks::mfa_replay::run(&client, &email, &password).await {
            Ok(report) => {
                if report.verdict == "CRITICAL" { any_critical = true; }
                let val = serde_json::to_value(&report).unwrap();
                println!("[ATK-02] Verdict: {}", report.verdict);
                reports.push(val);
            }
            Err(e) => {
                eprintln!("[ATK-02] FAILED: {}", e);
                reports.push(serde_json::json!({
                    "attack": "mfa_replay_brute_force",
                    "verdict": "ERROR",
                    "error": e
                }));
            }
        }
    } else {
        println!();
        println!("[SKIP] ATK-02 (MFA Replay) — not selected");
    }

    // ═══════════════════════════════════════════════
    //  ATK-03: IDOR (Insecure Direct Object Reference)
    // ═══════════════════════════════════════════════
    if mode.should_run(&AttackMode::Idor) {
        println!();
        println!("═══════════════════════════════════════════");
        println!("  ATK-03 ▸ IDOR Authorization Bypass");
        println!("═══════════════════════════════════════════");
        println!();

        match attacks::idor::run(&client, &email, &password).await {
            Ok(report) => {
                if report.verdict == "CRITICAL" { any_critical = true; }
                let val = serde_json::to_value(&report).unwrap();
                println!("[ATK-03] Verdict: {}", report.verdict);
                reports.push(val);
            }
            Err(e) => {
                eprintln!("[ATK-03] FAILED: {}", e);
                reports.push(serde_json::json!({
                    "attack": "idor_authorization_bypass",
                    "verdict": "ERROR",
                    "error": e
                }));
            }
        }
    } else {
        println!();
        println!("[SKIP] ATK-03 (IDOR) — not selected");
    }

    // ═══════════════════════════════════════════════
    //  Write combined report
    // ═══════════════════════════════════════════════
    let full_report = serde_json::json!({
        "engine": "cloudshield-attacker",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "attack_mode": format!("{:?}", mode),
        "total_attacks": reports.len(),
        "results": reports
    });

    let json = serde_json::to_string_pretty(&full_report).unwrap();

    if let Err(e) = std::fs::write("/reports/results.json", &json) {
        eprintln!("[WARN] Cannot write /reports/results.json: {}", e);
        std::fs::write("results.json", &json).ok();
    } else {
        println!();
        println!("[FILE] Report -> /reports/results.json");
    }

    println!();
    println!("═══════════════════════════════════════════");
    println!("  COMBINED REPORT");
    println!("═══════════════════════════════════════════");
    println!("{}", json);

    if any_critical {
        println!();
        println!("[!!] One or more CRITICAL vulnerabilities detected!");
        std::process::exit(1);
    } else {
        println!();
        println!("[OK] All attacks completed.");
        std::process::exit(0);
    }
}

async fn wait_for_api(client: &ApiClient) {
    println!("[WAIT] Waiting for API...");
    for attempt in 1..=30 {
        if let Ok(true) = client.health_check().await {
            println!("[WAIT] API healthy (attempt {})", attempt);
            return;
        }
        if attempt % 5 == 0 { println!("[WAIT] Still waiting (attempt {})...", attempt); }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    eprintln!("[FATAL] API not healthy after 60s");
    std::process::exit(1);
}
