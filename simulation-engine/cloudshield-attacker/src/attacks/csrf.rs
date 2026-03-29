use crate::client::ApiClient;
use serde::Serialize;
use serde_json::Value;

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
) -> Result<CsrfReport, String> {

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

    let Result = client
        .post_with_cookie(target_endpoint, "refreshToken", &refresh_token)
        .await;

    println!("[CSRF]   Response status: {}", Result.status);
    println!("[CSRF]   Response code  : {}", Result.code);

    let request_success = Result.status == 200 || Result.status == 201;

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

    Ok(CsrfReport {
        attack: "csrf".into(),
        endpoint: target_endpoint.into(),
        used_cookie_only: true,
        status: Result.status,
        request_success,
        verdict: verdict.into(),
    })
}
