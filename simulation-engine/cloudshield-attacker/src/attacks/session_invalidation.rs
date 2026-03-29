use crate::client::ApiClient;
use serde::Serialize;
use std::collections::HashMap;

// ── Report structures ────────────────────────────

#[derive(Serialize)]
pub struct SessionInvalidationReport {
    pub attack: String,
    pub timestamp: String,
    pub total_requests: usize,
    pub success_count: usize,
    pub blocked_count: usize,
    pub error_count: usize,
    pub status_distribution: HashMap<u16, usize>,
    pub detection_codes: HashMap<String, usize>,
    pub latency: LatencyStats,
    pub phases: LogoutPhases,
    pub verdict: String,
}

#[derive(Serialize)]
pub struct LogoutPhases {
    pub login_ok: bool,
    pub profile_before_logout: bool,
    pub logout_ok: bool,
    pub logout_status: u16,
    pub access_token_after_logout_status: u16,
    pub access_token_still_works: bool,
    pub refresh_token_after_logout_status: u16,
    pub refresh_token_still_works: bool,
}

#[derive(Serialize)]
pub struct LatencyStats {
    pub min_ms: u64,
    pub max_ms: u64,
    pub avg_ms: u64,
}

// ── Attack execution ─────────────────────────────

pub async fn run(
    client: &ApiClient,
    email: &str,
    password: &str,
) -> Result<SessionInvalidationReport, String> {

    let mut latencies: Vec<u64> = Vec::new();
    let mut status_dist: HashMap<u16, usize> = HashMap::new();
    let mut code_dist: HashMap<String, usize> = HashMap::new();
    let mut success_count: usize = 0;
    let mut blocked_count: usize = 0;
    let mut error_count: usize = 0;

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 1 — Login and verify we can access profile
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    println!("[LOGOUT] Phase 1: Logging in");

    let login = client.login(email, password).await
        .map_err(|e| format!("login failed: {}", e))?;

    let access_token = login.access_token.clone();
    let refresh_token = login.refresh_token.clone();

    println!("[LOGOUT]   Access token: {} chars", access_token.len());
    println!("[LOGOUT]   Refresh token: {} chars", refresh_token.len());

    // Verify profile works before logout
    let pre_check = client
        .get_authenticated("/api/v1/auth/profile", &access_token)
        .await;

    latencies.push(pre_check.latency_ms);
    *status_dist.entry(pre_check.status).or_insert(0) += 1;

    let profile_before_logout = pre_check.status == 200;

    if pre_check.status == 200 {
        success_count += 1;
    } else {
        error_count += 1;
    }

    println!("[LOGOUT]   Pre-logout profile: status={} ok={}", pre_check.status, profile_before_logout);

    if !profile_before_logout {
        return Err(format!(
            "cannot access profile before logout (status {}), test invalid",
            pre_check.status
        ));
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 2 — Perform logout
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    println!("[LOGOUT] Phase 2: Logging out");

    let logout_result = client.logout(&access_token, &refresh_token).await;
    latencies.push(logout_result.latency_ms);
    *status_dist.entry(logout_result.status).or_insert(0) += 1;

    if !logout_result.code.is_empty() {
        *code_dist.entry(logout_result.code.clone()).or_insert(0) += 1;
    }

    let logout_ok = logout_result.status == 200;
    println!("[LOGOUT]   Logout result: status={} code={}", logout_result.status, logout_result.code);

    // Small delay to ensure session revocation is committed
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 3 — Try reusing access token after logout
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    println!("[LOGOUT] Phase 3: Attempting to use ACCESS token after logout");

    let post_access = client
        .get_authenticated("/api/v1/auth/profile", &access_token)
        .await;

    latencies.push(post_access.latency_ms);
    *status_dist.entry(post_access.status).or_insert(0) += 1;

    if !post_access.code.is_empty() {
        *code_dist.entry(post_access.code.clone()).or_insert(0) += 1;
    }

    let access_token_still_works = post_access.status == 200;

    if access_token_still_works {
        success_count += 1;
        println!("[LOGOUT]   🚨 Access token STILL WORKS after logout! status={}", post_access.status);
    } else {
        blocked_count += 1;
        println!("[LOGOUT]   ✅ Access token rejected: status={} code={}", post_access.status, post_access.code);
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 4 — Try reusing refresh token after logout
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    println!("[LOGOUT] Phase 4: Attempting to use REFRESH token after logout");

    let post_refresh = client.refresh_with_token(&refresh_token).await;
    latencies.push(post_refresh.latency_ms);
    *status_dist.entry(post_refresh.status).or_insert(0) += 1;

    if !post_refresh.code.is_empty() {
        *code_dist.entry(post_refresh.code.clone()).or_insert(0) += 1;
    }

    let refresh_token_still_works = post_refresh.status == 200;

    if refresh_token_still_works {
        success_count += 1;
        println!("[LOGOUT]   🚨 Refresh token STILL WORKS after logout! status={}", post_refresh.status);
    } else {
        blocked_count += 1;
        println!("[LOGOUT]   ✅ Refresh token rejected: status={} code={}", post_refresh.status, post_refresh.code);
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 5 — Multiple reuse attempts
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    println!("[LOGOUT] Phase 5: 3 additional reuse attempts for confirmation");

    for attempt in 1..=3 {
        let r = client
            .get_authenticated("/api/v1/auth/profile", &access_token)
            .await;

        latencies.push(r.latency_ms);
        *status_dist.entry(r.status).or_insert(0) += 1;

        if r.status == 200 {
            success_count += 1;
            println!("[LOGOUT]   Attempt {}: 🚨 ACCEPTED", attempt);
        } else {
            blocked_count += 1;
            println!("[LOGOUT]   Attempt {}: blocked ({})", attempt, r.status);
        }
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  VERDICT
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    let verdict = if refresh_token_still_works {
        "CRITICAL"    // refresh token survives logout = session persist
    } else if access_token_still_works {
        "VULNERABLE"  // access token works but refresh doesn't
    } else {
        "SECURE"      // both tokens properly invalidated
    };

    let total_requests = success_count + blocked_count + error_count;
    let latency = compute_latency(&latencies);

    println!();
    println!("[LOGOUT] ═══════════════════════════════════════════");
    println!("[LOGOUT] Access token after logout : {}", if access_token_still_works { "🚨 WORKS" } else { "✅ REJECTED" });
    println!("[LOGOUT] Refresh token after logout: {}", if refresh_token_still_works { "🚨 WORKS" } else { "✅ REJECTED" });
    println!("[LOGOUT] Verdict                   : {}", verdict);

    Ok(SessionInvalidationReport {
        attack: "session_invalidation_logout".into(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        total_requests,
        success_count,
        blocked_count,
        error_count,
        status_distribution: status_dist,
        detection_codes: code_dist,
        latency,
        phases: LogoutPhases {
            login_ok: true,
            profile_before_logout,
            logout_ok,
            logout_status: logout_result.status,
            access_token_after_logout_status: post_access.status,
            access_token_still_works,
            refresh_token_after_logout_status: post_refresh.status,
            refresh_token_still_works,
        },
        verdict: verdict.into(),
    })
}

fn compute_latency(latencies: &[u64]) -> LatencyStats {
    if latencies.is_empty() {
        return LatencyStats { min_ms: 0, max_ms: 0, avg_ms: 0 };
    }
    LatencyStats {
        min_ms: *latencies.iter().min().unwrap(),
        max_ms: *latencies.iter().max().unwrap(),
        avg_ms: latencies.iter().sum::<u64>() / latencies.len() as u64,
    }
}
