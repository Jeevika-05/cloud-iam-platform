mod client;
mod attacks;
mod event;
use event::GraphEvent;

use std::env;
use std::time::Duration;
use client::ApiClient;

/// Which attacks to execute.
#[derive(Debug, Clone, PartialEq)]
enum AttackMode {
    All,
    TokenRace,
    MfaReplay,
    MfaDistributed,
    Idor,
    JwtTamper,
    SessionReuse,
    PasswordBrute,
    SessionInvalidation,
    RateFlood,
    Csrf,
    MassAssignment,
    AccessTokenAbuse,
}

impl AttackMode {
    fn from_env() -> Self {
        match env::var("ATTACK_MODE")
            .unwrap_or_else(|_| "all".into())
            .to_lowercase()
            .trim()
        {
            s if s == "token_race" || s == "atk01" || s == "atk-01" => AttackMode::TokenRace,
            s if s == "mfa_replay" || s == "mfa_brute_force_single_ip" || s == "atk02" || s == "atk-02" => AttackMode::MfaReplay,
            s if s == "mfa_brute_force_distributed" || s == "atk12" || s == "atk-12" => AttackMode::MfaDistributed,
            s if s == "idor" || s == "atk03" || s == "atk-03" => AttackMode::Idor,
            s if s == "jwt_tamper" || s == "atk04" || s == "atk-04" => AttackMode::JwtTamper,
            s if s == "session_reuse" || s == "atk05" || s == "atk-05" => AttackMode::SessionReuse,
            s if s == "password_brute" || s == "atk06" || s == "atk-06" => AttackMode::PasswordBrute,
            s if s == "session_invalidation" || s == "atk07" || s == "atk-07" => AttackMode::SessionInvalidation,
            s if s == "rate_flood" || s == "atk08" || s == "atk-08" => AttackMode::RateFlood,
            s if s == "csrf" || s == "atk09" || s == "atk-09" => AttackMode::Csrf,
            s if s == "mass_assignment" || s == "atk10" || s == "atk-10" => AttackMode::MassAssignment,
            s if s == "access_token_abuse" || s == "atk11" || s == "atk-11" => AttackMode::AccessTokenAbuse,
            _ => AttackMode::All,
        }
    }

    fn should_run(&self, target: &AttackMode) -> bool {
        *self == AttackMode::All || *self == *target
    }
}

// ─────────────────────────────────────────────
// ATTACK IDENTITY ISOLATION
//
// Each attack gets its own email + password so
// that destructive attacks (brute-force, lockout)
// cannot interfere with other attacks.
// ─────────────────────────────────────────────

fn generate_attack_identity(attack_name: &str, base_password: &str) -> (String, String) {
    let email = format!("atk-{}@test.com", attack_name);
    let password = base_password.to_string();
    (email, password)
}

/// Pre-register an attack identity.
///
/// RC-2 FIX: Registration failure is now propagated, not silently ignored.
///   - 409 Conflict  -> already registered, proceed to login
///   - Other error   -> Err propagated; attack is skipped with ERROR verdict
///
/// RC-3 FIX: Returns Result<(user_id, access_token), String>.
///   No attack runs with email-as-user_id or empty token.
async fn ensure_identity(
    client: &ApiClient,
    email: &str,
    password: &str,
    name: &str,
) -> Result<(String, String), String> {
    match client.register(email, password, name).await {
        Ok(()) => {}
        Err(ref e) if e.contains("409") || e.contains("DUPLICATE_EMAIL") => {}
        Err(e) => return Err(format!("registration failed for {}: {}", email, e)),
    }
    match client.login(email, password).await {
        Ok(res) if !res.user_id.is_empty() && !res.access_token.is_empty() => {
            Ok((res.user_id, res.access_token))
        }
        Ok(_) => Err(format!("login returned empty credentials for {}", email)),
        Err(e) => Err(format!("login failed for {} ({})", email, e)),
    }
}



fn emit_graph_event(event: GraphEvent, store: &mut Vec<GraphEvent>) {
    store.push(event);
}

#[tokio::main]
async fn main() {
    println!("╔══════════════════════════════════════════╗");
    println!("║   CloudShield Attack Simulation Engine   ║");
    println!("╚══════════════════════════════════════════╝");
    println!();

    let target_url = env::var("TARGET_URL").unwrap_or_else(|_| "http://localhost:3000".into());
    let base_password = env::var("ATTACK_PASSWORD").unwrap_or_else(|_| "Attack@123".into());
    let mode = AttackMode::from_env();

    println!("[CONFIG] Target   : {}", target_url);
    println!("[CONFIG] Mode     : {:?}", mode);
    println!("[CONFIG] Isolation: per-attack identities");
    println!();

    let client = ApiClient::new(&target_url, Some("127.0.0.1"), Some("Sim-Healthcheck"), None);

    wait_for_api(&client).await;

    let mut reports: Vec<serde_json::Value> = Vec::new();
    let mut graph_events: Vec<GraphEvent> = Vec::new();
    let mut any_critical = false;
    // run_id groups the entire simulation run at the report level.
    // Each individual attack gets its OWN correlation_id so that
    // Neo4j chains are independent and attack path analysis is meaningful.
    let run_id = uuid::Uuid::new_v4().to_string();

    // ═══════════════════════════════════════════════
    //  ATK-01: Token Race Condition
    // ═══════════════════════════════════════════════
    if mode.should_run(&AttackMode::TokenRace) {
        let (email, password) = generate_attack_identity("token-race", &base_password);
        let atk01_correlation_id = uuid::Uuid::new_v4().to_string();
        let client = ApiClient::new(&target_url, Some("192.168.1.101"), Some("attack-sim-token-race"), Some(&atk01_correlation_id));
        match ensure_identity(&client, &email, &password, "ATK01-TokenRace").await {
            Err(e) => {
                eprintln!("[ATK-01] IDENTITY FAILED: {}", e);
                reports.push(serde_json::json!({
                    "attack": "token_race_condition",
                    "identity": email,
                    "verdict": "ERROR",
                    "error": format!("identity_setup_failed: {}", e)
                }));
            }
            Ok((user_id, _access_token)) => {
            match attacks::token_race::run(&client, &email, &password, &user_id, &atk01_correlation_id).await {
                Ok((report, event)) => {
                    if report.verdict == "CRITICAL" || report.verdict == "VULNERABLE" { any_critical = true; }
                    let val = serde_json::to_value(&report).unwrap();
                    emit_graph_event(event, &mut graph_events);
                    println!("[ATK] Verdict: {}", report.verdict);
                    reports.push(val);
                }
                Err(e) => {
                    eprintln!("[ATK-01] FAILED: {}", e);
                    reports.push(serde_json::json!({
                        "attack": "token_race_condition",
                        "identity": email,
                        "verdict": "ERROR",
                        "error": e
                    }));
                }
            }
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
        let email = env::var("MFA_TARGET_EMAIL").unwrap_or_else(|_| "admin_attack@example.com".into());
        let password = env::var("MFA_TARGET_PASSWORD").unwrap_or_else(|_| "Admin@1234!".into());
        let atk02_correlation_id = uuid::Uuid::new_v4().to_string();
        let client = ApiClient::new(&target_url, Some("192.168.1.102"), Some("attack-sim-mfa"), Some(&atk02_correlation_id));
        let user_id = match client.login_expect_mfa(&email, &password).await {
            Ok(res) => Some(res.user_id),
            Err(e) => {
                eprintln!("[ATK-02] IDENTITY FAILED: {}", e);
                reports.push(serde_json::json!({
                    "attack": "mfa_brute_force_single_ip",
                    "identity": email,
                    "verdict": "ERROR",
                    "error": format!("identity_setup_failed: {}", e)
                }));
                None
            }
        };

        println!();
        println!("═══════════════════════════════════════════");
        println!("  ATK-02 ▸ MFA Brute Force (Single IP)");
        println!("  Identity: {}", email);
        println!("═══════════════════════════════════════════");
        println!();


        if let Some(user_id) = user_id {
            match attacks::mfa_replay::run(&client, &email, &password, &user_id, &atk02_correlation_id).await {
                Ok((report, event)) => {
                    if report.verdict == "CRITICAL" || report.verdict == "VULNERABLE" { any_critical = true; }
                    let val = serde_json::to_value(&report).unwrap();
                    emit_graph_event(event, &mut graph_events);
                    println!("[ATK] Verdict: {}", report.verdict);
                    reports.push(val);
                }
                Err(e) => {
                    eprintln!("[ATK-02] FAILED: {}", e);
                    reports.push(serde_json::json!({
                        "attack": "mfa_brute_force_single_ip",
                        "identity": email,
                        "verdict": "ERROR",
                        "error": e
                    }));
                }
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
        // IDOR creates its own attacker+victim internally
        let (email, password) = generate_attack_identity("idor", &base_password);
        let atk03_correlation_id = uuid::Uuid::new_v4().to_string();
        let client = ApiClient::new(&target_url, Some("192.168.1.103"), Some("attack-sim-idor"), Some(&atk03_correlation_id));
  
        match ensure_identity(&client, &email, &password, "ATK03-IDOR-Attacker").await {
            Err(e) => {
                eprintln!("[ATK-03] IDENTITY FAILED: {}", e);
                reports.push(serde_json::json!({
                    "attack": "idor_authorization_bypass",
                    "identity": email,
                    "verdict": "ERROR",
                    "error": format!("identity_setup_failed: {}", e)
                }));
            }
            Ok((user_id, _access_token)) => {
            match attacks::idor::run(&client, &email, &password, &user_id, &atk03_correlation_id).await {
            Ok((report, event)) => {
                if report.verdict == "CRITICAL" || report.verdict == "VULNERABLE" { any_critical = true; }
                let val = serde_json::to_value(&report).unwrap();
                emit_graph_event(event, &mut graph_events);
                println!("[ATK] Verdict: {}", report.verdict);
                reports.push(val);
            }
            Err(e) => {
                eprintln!("[ATK-03] FAILED: {}", e);
                reports.push(serde_json::json!({
                    "attack": "idor_authorization_bypass",
                    "identity": email,
                    "verdict": "ERROR",
                    "error": e
                }));
            }
        }
            }
        }
    } else {
        println!();
        println!("[SKIP] ATK-03 (IDOR) — not selected");
    }

    // ═══════════════════════════════════════════════
    //  ATK-04: JWT Tampering / Signature Validation
    // ═══════════════════════════════════════════════
    if mode.should_run(&AttackMode::JwtTamper) {
        let (email, password) = generate_attack_identity("jwt", &base_password);
        let atk04_correlation_id = uuid::Uuid::new_v4().to_string();
        let client = ApiClient::new(&target_url, Some("192.168.1.104"), Some("attack-sim-jwt"), Some(&atk04_correlation_id));
        match ensure_identity(&client, &email, &password, "ATK04-JWT").await {
            Err(e) => {
                eprintln!("[ATK-04] IDENTITY FAILED: {}", e);
                reports.push(serde_json::json!({
                    "attack": "jwt_tampering_signature_validation",
                    "identity": email,
                    "verdict": "ERROR",
                    "error": format!("identity_setup_failed: {}", e)
                }));
            }
            Ok((user_id, _access_token)) => {
            match attacks::jwt_tamper::run(&client, &email, &password, &user_id, &atk04_correlation_id).await {
                Ok((report, event)) => {
                    if report.verdict == "CRITICAL" || report.verdict == "VULNERABLE" { any_critical = true; }
                    let val = serde_json::to_value(&report).unwrap();
                    emit_graph_event(event, &mut graph_events);
                    println!("[ATK] Verdict: {}", report.verdict);
                    reports.push(val);
                }
                Err(e) => {
                    eprintln!("[ATK-04] FAILED: {}", e);
                    reports.push(serde_json::json!({
                        "attack": "jwt_tampering_signature_validation",
                        "identity": email,
                        "verdict": "ERROR",
                        "error": e
                    }));
                }
            }
            }
        }
    } else {
        println!();
        println!("[SKIP] ATK-04 (JWT Tamper) — not selected");
    }

    // ═══════════════════════════════════════════════
    //  ATK-05: Sequential Token Reuse (Session Hijack)
    // ═══════════════════════════════════════════════
    if mode.should_run(&AttackMode::SessionReuse) {
        let (email, password) = generate_attack_identity("sess-reuse", &base_password);
        let atk05_correlation_id = uuid::Uuid::new_v4().to_string();
        let client = ApiClient::new(&target_url, Some("192.168.1.105"), Some("attack-sim-sess-reuse"), Some(&atk05_correlation_id));
        match ensure_identity(&client, &email, &password, "ATK05-SessReuse").await {
            Err(e) => {
                eprintln!("[ATK-05] IDENTITY FAILED: {}", e);
                reports.push(serde_json::json!({
                    "attack": "sequential_token_reuse",
                    "identity": email,
                    "verdict": "ERROR",
                    "error": format!("identity_setup_failed: {}", e)
                }));
            }
            Ok((user_id, _access_token)) => {
            match attacks::session_reuse::run(&client, &email, &password, &user_id, &atk05_correlation_id).await {
                Ok((report, event)) => {
                    if report.verdict == "CRITICAL" || report.verdict == "VULNERABLE" { any_critical = true; }
                    let val = serde_json::to_value(&report).unwrap();
                    emit_graph_event(event, &mut graph_events);
                    println!("[ATK] Verdict: {}", report.verdict);
                    reports.push(val);
                }
                Err(e) => {
                    eprintln!("[ATK-05] FAILED: {}", e);
                    reports.push(serde_json::json!({
                        "attack": "sequential_token_reuse",
                        "identity": email,
                        "verdict": "ERROR",
                        "error": e
                    }));
                }
            }
            }
        }
    } else {
        println!();
        println!("[SKIP] ATK-05 (Session Reuse) — not selected");
    }

    // ═══════════════════════════════════════════════
    //  ATK-06: Password Brute Force
    //  ⚠ Uses its own identity — will lock this account
    // ═══════════════════════════════════════════════
    if mode.should_run(&AttackMode::PasswordBrute) {
        let (email, password) = generate_attack_identity("brute", &base_password);
        let atk06_correlation_id = uuid::Uuid::new_v4().to_string();
        let client = ApiClient::new(&target_url, Some("192.168.1.106"), Some("attack-sim-brute"), Some(&atk06_correlation_id));
        match ensure_identity(&client, &email, &password, "ATK06-Brute").await {
            Err(e) => {
                eprintln!("[ATK-06] IDENTITY FAILED: {}", e);
                reports.push(serde_json::json!({
                    "attack": "password_brute_force",
                    "identity": email,
                    "verdict": "ERROR",
                    "error": format!("identity_setup_failed: {}", e)
                }));
            }
            Ok((user_id, _access_token)) => {
            match attacks::password_brute::run(&client, &email, &password, &user_id, &atk06_correlation_id).await {
                Ok((report, event)) => {
                    if report.verdict == "CRITICAL" || report.verdict == "VULNERABLE" { any_critical = true; }
                    let val = serde_json::to_value(&report).unwrap();
                    emit_graph_event(event, &mut graph_events);
                    println!("[ATK] Verdict: {}", report.verdict);
                    reports.push(val);
                }
                Err(e) => {
                    eprintln!("[ATK-06] FAILED: {}", e);
                    reports.push(serde_json::json!({
                        "attack": "password_brute_force",
                        "identity": email,
                        "verdict": "ERROR",
                        "error": e
                    }));
                }
            }
            }
        }
    } else {
        println!();
        println!("[SKIP] ATK-06 (Password Brute) — not selected");
    }

    // ═══════════════════════════════════════════════
    //  ATK-07: Session Invalidation (Logout Reuse)
    // ═══════════════════════════════════════════════
    if mode.should_run(&AttackMode::SessionInvalidation) {
        let (email, password) = generate_attack_identity("logout", &base_password);
        let atk07_correlation_id = uuid::Uuid::new_v4().to_string();
        let client = ApiClient::new(&target_url, Some("192.168.1.107"), Some("attack-sim-logout"), Some(&atk07_correlation_id));
        match ensure_identity(&client, &email, &password, "ATK07-Logout").await {
            Err(e) => {
                eprintln!("[ATK-07] IDENTITY FAILED: {}", e);
                reports.push(serde_json::json!({
                    "attack": "session_invalidation_logout",
                    "identity": email,
                    "verdict": "ERROR",
                    "error": format!("identity_setup_failed: {}", e)
                }));
            }
            Ok((user_id, _access_token)) => {
            match attacks::session_invalidation::run(&client, &email, &password, &user_id, &atk07_correlation_id).await {
                Ok((report, event)) => {
                    if report.verdict == "CRITICAL" || report.verdict == "VULNERABLE" { any_critical = true; }
                    let val = serde_json::to_value(&report).unwrap();
                    emit_graph_event(event, &mut graph_events);
                    println!("[ATK] Verdict: {}", report.verdict);
                    reports.push(val);
                }
                Err(e) => {
                    eprintln!("[ATK-07] FAILED: {}", e);
                    reports.push(serde_json::json!({
                        "attack": "session_invalidation_logout",
                        "identity": email,
                        "verdict": "ERROR",
                        "error": e
                    }));
                }
            }
            }
        }
    } else {
        println!();
        println!("[SKIP] ATK-07 (Session Invalidation) — not selected");
    }

    // ═══════════════════════════════════════════════
    //  ATK-08: API Rate Flood
    // ═══════════════════════════════════════════════
    if mode.should_run(&AttackMode::RateFlood) {
        let (email, password) = generate_attack_identity("flood", &base_password);
        let atk08_correlation_id = uuid::Uuid::new_v4().to_string();
        let client = ApiClient::new(&target_url, Some("192.168.1.108"), Some("attack-sim-flood"), Some(&atk08_correlation_id));
        match ensure_identity(&client, &email, &password, "ATK08-Flood").await {
            Err(e) => {
                eprintln!("[ATK-08] IDENTITY FAILED: {}", e);
                reports.push(serde_json::json!({
                    "attack": "api_rate_flood",
                    "identity": email,
                    "verdict": "ERROR",
                    "error": format!("identity_setup_failed: {}", e)
                }));
            }
            Ok((user_id, _access_token)) => {
            match attacks::rate_flood::run(&client, &email, &password, &user_id, &atk08_correlation_id).await {
                Ok((report, event)) => {
                    if report.verdict == "CRITICAL" || report.verdict == "VULNERABLE" { any_critical = true; }
                    let val = serde_json::to_value(&report).unwrap();
                    emit_graph_event(event, &mut graph_events);
                    println!("[ATK] Verdict: {}", report.verdict);
                    reports.push(val);
                }
                Err(e) => {
                    eprintln!("[ATK-08] FAILED: {}", e);
                    reports.push(serde_json::json!({
                        "attack": "api_rate_flood",
                        "identity": email,
                        "verdict": "ERROR",
                        "error": e
                    }));
                }
            }
            }
        }
    } else {
        println!();
        println!("[SKIP] ATK-08 (Rate Flood) — not selected");
    }

    // ═══════════════════════════════════════════════
    //  ATK-09: CSRF (Cross-Site Request Forgery)
    // ═══════════════════════════════════════════════
    if mode.should_run(&AttackMode::Csrf) {
        let (email, password) = generate_attack_identity("csrf", &base_password);
        let atk09_correlation_id = uuid::Uuid::new_v4().to_string();
        let client = ApiClient::new(&target_url, Some("192.168.1.109"), Some("attack-sim-csrf"), Some(&atk09_correlation_id));
        match ensure_identity(&client, &email, &password, "ATK09-Csrf").await {
            Err(e) => {
                eprintln!("[ATK-09] IDENTITY FAILED: {}", e);
                reports.push(serde_json::json!({
                    "attack": "csrf",
                    "identity": email,
                    "verdict": "ERROR",
                    "error": format!("identity_setup_failed: {}", e)
                }));
            }
            Ok((user_id, _access_token)) => {
            match attacks::csrf::run(&client, &email, &password, &user_id, &atk09_correlation_id).await {
                Ok((report, event)) => {
                    if report.verdict == "CRITICAL" || report.verdict == "VULNERABLE" { any_critical = true; }
                    let val = serde_json::to_value(&report).unwrap();
                    emit_graph_event(event, &mut graph_events);
                    println!("[ATK] Verdict: {}", report.verdict);
                    reports.push(val);
                }
                Err(e) => {
                    eprintln!("[ATK-09] FAILED: {}", e);
                    reports.push(serde_json::json!({
                        "attack": "csrf",
                        "identity": email,
                        "verdict": "ERROR",
                        "error": e
                    }));
                }
            }
            }
        }
    } else {
        println!();
        println!("[SKIP] ATK-09 (CSRF) — not selected");
    }

    // ═══════════════════════════════════════════════
    //  ATK-10: Mass Assignment Attack
    // ═══════════════════════════════════════════════
    if mode.should_run(&AttackMode::MassAssignment) {
        let (email, password) = generate_attack_identity("mass", &base_password);
        let atk10_correlation_id = uuid::Uuid::new_v4().to_string();
        let client = ApiClient::new(&target_url, Some("192.168.1.110"), Some("attack-sim-mass"), Some(&atk10_correlation_id));
        match ensure_identity(&client, &email, &password, "ATK10-MassAssign").await {
            Err(e) => {
                eprintln!("[ATK-10] IDENTITY FAILED: {}", e);
                reports.push(serde_json::json!({
                    "attack": "mass_assignment",
                    "identity": email,
                    "verdict": "ERROR",
                    "error": format!("identity_setup_failed: {}", e)
                }));
            }
            Ok((user_id, _access_token)) => {
            match attacks::mass_assignment::run(&client, &email, &password, &user_id, &atk10_correlation_id).await {
                Ok((report, event)) => {
                    if report.verdict == "CRITICAL" || report.verdict == "VULNERABLE" { any_critical = true; }
                    let val = serde_json::to_value(&report).unwrap();
                    emit_graph_event(event, &mut graph_events);
                    println!("[ATK] Verdict: {}", report.verdict);
                    reports.push(val);
                }
                Err(e) => {
                    eprintln!("[ATK-10] FAILED: {}", e);
                    reports.push(serde_json::json!({
                        "attack": "mass_assignment",
                        "identity": email,
                        "verdict": "ERROR",
                        "error": e
                    }));
                }
            }
            }
        }
    } else {
        println!();
        println!("[SKIP] ATK-10 (Mass Assignment) — not selected");
    }

    // ═══════════════════════════════════════════════
    //  ATK-11: Access Token Abuse (Post-Logout)
    // ═══════════════════════════════════════════════
    if mode.should_run(&AttackMode::AccessTokenAbuse) {
        let (email, password) = generate_attack_identity("token-abuse", &base_password);
        let atk11_correlation_id = uuid::Uuid::new_v4().to_string();
        let client = ApiClient::new(&target_url, Some("192.168.1.111"), Some("attack-sim-token-abuse"), Some(&atk11_correlation_id));
        match ensure_identity(&client, &email, &password, "ATK11-TokenAbuse").await {
            Err(e) => {
                eprintln!("[ATK-11] IDENTITY FAILED: {}", e);
                reports.push(serde_json::json!({
                    "attack": "access_token_abuse",
                    "identity": email,
                    "verdict": "ERROR",
                    "error": format!("identity_setup_failed: {}", e)
                }));
            }
            Ok((user_id, _access_token)) => {
            match attacks::access_token_abuse::run(&client, &email, &password, &user_id, &atk11_correlation_id).await {
                Ok((report, event)) => {
                    if report.verdict == "CRITICAL" || report.verdict == "VULNERABLE" { any_critical = true; }
                    let val = serde_json::to_value(&report).unwrap();
                    emit_graph_event(event, &mut graph_events);
                    println!("[ATK] Verdict: {}", report.verdict);
                    reports.push(val);
                }
                Err(e) => {
                    eprintln!("[ATK-11] FAILED: {}", e);
                    reports.push(serde_json::json!({
                        "attack": "access_token_abuse",
                        "identity": email,
                        "verdict": "ERROR",
                        "error": e
                    }));
                }
            }
            }
        }
    } else {
        println!();
        println!("[SKIP] ATK-11 (Access Token Abuse) — not selected");
    }

    // ═══════════════════════════════════════════════
    //  ATK-12: MFA Distributed Brute Force
    // ═══════════════════════════════════════════════
    if mode.should_run(&AttackMode::MfaDistributed) {
        let email = env::var("MFA_TARGET_EMAIL").unwrap_or_else(|_| "admin_attack@example.com".into());
        let password = env::var("MFA_TARGET_PASSWORD").unwrap_or_else(|_| "Admin@1234!".into());
        let atk12_correlation_id = uuid::Uuid::new_v4().to_string();
        let client = ApiClient::new(&target_url, Some("192.168.1.112"), Some("attack-sim-mfa-dist"), Some(&atk12_correlation_id));
        let user_id = match client.login_expect_mfa(&email, &password).await {
            Ok(res) => Some(res.user_id),
            Err(e) => {
                eprintln!("[ATK-12] IDENTITY FAILED: {}", e);
                reports.push(serde_json::json!({
                    "attack": "mfa_brute_force_distributed",
                    "identity": email,
                    "verdict": "ERROR",
                    "error": format!("identity_setup_failed: {}", e)
                }));
                None
            }
        };

        println!();
        println!("═══════════════════════════════════════════");
        println!("  ATK-12 ▸ MFA Distributed Brute Force");
        println!("  Identity: {}", email);
        println!("═══════════════════════════════════════════");
        println!();


        if let Some(user_id) = user_id {
            match attacks::mfa_distributed::run(&client, &email, &password, &user_id, &atk12_correlation_id).await {
                Ok((report, event)) => {
                    if report.verdict == "CRITICAL" || report.verdict == "VULNERABLE" { any_critical = true; }
                    let val = serde_json::to_value(&report).unwrap();
                    emit_graph_event(event, &mut graph_events);
                    println!("[ATK] Verdict: {}", report.verdict);
                    reports.push(val);
                }
                Err(e) => {
                    eprintln!("[ATK-12] FAILED: {}", e);
                    reports.push(serde_json::json!({
                        "attack": "mfa_brute_force_distributed",
                        "identity": email,
                        "verdict": "ERROR",
                        "error": e
                    }));
                }
            }
        }
    } else {
        println!();
        println!("[SKIP] ATK-12 (MFA Distributed) — not selected");
    }

    // ═══════════════════════════════════════════════
    //  Write combined report
    // ═══════════════════════════════════════════════
    let full_report = serde_json::json!({
        "_metadata": {
            "source": "cloudshield-attacker",
            "scope": "attack_engine_output_only",
            "description": "Contains ATTACK events and verdicts from the Rust simulation engine. Each attack type has its own correlation_id for independent chain analysis. run_id groups the entire simulation run. DEFENSE events (STRIKE_RECORDED, IP_BANNED) are stored in the backend AuditLog database and available via GET /api/v1/audit/events/defense. Use scripts/neo4j_ingest.js to merge both for Neo4j ingestion.",
            "version": "2.1.0"
        },
        "engine": "cloudshield-attacker",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "attack_mode": format!("{:?}", mode),
        "isolation": "per-attack-identity",
        // run_id groups all attacks from this execution run for report-level correlation.
        // It is NOT used as a graph correlation_id — each attack has its own.
        "run_id": run_id,
        "total_attacks": reports.len(),
        "results": reports,
        "graph_events": graph_events
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
