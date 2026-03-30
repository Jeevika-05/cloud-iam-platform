use crate::event::GraphEvent;
use crate::client::ApiClient;
use serde::Serialize;

// ── Report structures ────────────────────────────

#[derive(Serialize)]
pub struct CsrfReport {
    pub attack: String,
    pub endpoint: String,
    pub used_cookie_only: bool,
    pub status: u16,
    pub request_success: bool,
    pub verdict: String,
}

// ── Attack execution ─────────────────────────────

pub async fn run(
    client: &ApiClient,
    email: &str,
    password: &str,
    user_id: &str,
    correlation_id: &str,
) -> Result<(CsrfReport, GraphEvent), String> {

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 1 — Login to get a valid refresh token cookie
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    println!("[CSRF] Phase 1: Logging in to obtain session cookies");

    let login = client.login(email, password).await
        .map_err(|e| format!("login failed: {}", e))?;

    let refresh_token = login.refresh_token.clone();
    println!("[CSRF]   Got cookie: refreshToken ({} chars)", refresh_token.len());

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 2 — Execute unauthenticated POST with cookie only
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    let target_endpoint = "/api/v1/auth/logout";

    println!("[CSRF] Phase 2: Sending POST to {} WITHOUT Authorization header...", target_endpoint);
    println!("[CSRF]   (Simulating cross-site request where browser automatically attaches cookie)");

    let result = client
        .post_with_cookie(target_endpoint, "refreshToken", &refresh_token)
        .await;

    println!("[CSRF]   Response status: {}", result.status);
    println!("[CSRF]   Response code  : {}", result.code);

    let request_success = result.status == 200 || result.status == 201;

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  VERDICT
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    let verdict = if request_success {
        "VULNERABLE" // Endpoint allowed action with only a cookie (no explicit auth/CSRF token)
    } else {
        "SECURE"     // Rejected properly (likely 401/403 looking for Bearer token)
    };

    println!();
    println!("[CSRF] Verdict: {}", verdict);

    let report = CsrfReport {
        attack: "csrf".into(),
        endpoint: target_endpoint.into(),
        used_cookie_only: true,
        status: result.status,
        request_success,
        verdict: verdict.into(),
    };

    let event = GraphEvent::new(
        correlation_id,
        user_id,
        Some(email.to_string()),
        "CSRF",
        "/api/v1/auth/logout",
        &report.verdict,
    );

    Ok((report, event))
}
