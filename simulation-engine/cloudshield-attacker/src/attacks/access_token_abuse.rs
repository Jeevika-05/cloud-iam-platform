use crate::client::ApiClient;
use serde::Serialize;

// ── Report structures ────────────────────────────

#[derive(Serialize)]
pub struct AccessTokenAbuseReport {
    pub attack: String,
    pub valid_before_logout: bool,
    pub valid_after_logout: bool,
    pub after_logout_status: u16,
    pub after_logout_code: String,
    pub verdict: String,
}

// ── Attack execution ─────────────────────────────

pub async fn run(
    client: &ApiClient,
    email: &str,
    password: &str,
) -> Result<AccessTokenAbuseReport, String> {

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 1 — Login and establish session
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    println!("[ACCESS_ABUSE] Phase 1: Logging in to get access token");

    let login = client.login(email, password).await
        .map_err(|e| format!("login failed: {}", e))?;

    let access_token = login.access_token.clone();
    let refresh_token = login.refresh_token.clone();

    // Verify token works initially
    let profile_before = client.get_authenticated("/api/v1/auth/profile", &access_token).await;
    let valid_before_logout = profile_before.status == 200;

    println!("[ACCESS_ABUSE]   Access Token obtained: {} chars", access_token.len());
    println!("[ACCESS_ABUSE]   Valid before logout: {}", valid_before_logout);

    if !valid_before_logout {
        return Err("Access token did not work even before logout".into());
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 2 — Logout
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    println!();
    println!("[ACCESS_ABUSE] Phase 2: Calling logout endpoint");

    let logout_res = client.logout(&access_token, &refresh_token).await;
    
    if logout_res.status != 200 {
        println!("[ACCESS_ABUSE]   Warning: Logout returned status {}", logout_res.status);
    } else {
        println!("[ACCESS_ABUSE]   Logged out successfully");
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 3 — Attempt Access Token Abuse
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    println!();
    println!("[ACCESS_ABUSE] Phase 3: Abusing Access Token after logout");

    let profile_after = client.get_authenticated("/api/v1/auth/profile", &access_token).await;
    let valid_after_logout = profile_after.status == 200;

    println!("[ACCESS_ABUSE]   Reuse Status: {}", profile_after.status);
    println!("[ACCESS_ABUSE]   Reuse Code  : {}", profile_after.code);
    println!("[ACCESS_ABUSE]   Action Success: {}", valid_after_logout);

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  VERDICT
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    // If using stateless JWTs without a blocklist, access tokens remain
    // valid until natural expiration even after the user logs out.
    // The user requested to mark this as "WEAK" rather than "CRITICAL", 
    // unless the endpoint returns 401 which makes it "SECURE".
    let verdict = if valid_after_logout {
        "WEAK"
    } else {
        "SECURE"
    };

    println!();
    println!("[ACCESS_ABUSE] Verdict: {}", verdict);

    Ok(AccessTokenAbuseReport {
        attack: "access_token_abuse".into(),
        valid_before_logout,
        valid_after_logout,
        after_logout_status: profile_after.status,
        after_logout_code: profile_after.code,
        verdict: verdict.into(),
    })
}
