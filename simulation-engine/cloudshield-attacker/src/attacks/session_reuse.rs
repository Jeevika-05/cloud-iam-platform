use crate::client::ApiClient;
use serde::Serialize;
use std::collections::HashMap;

// ── Report structures ────────────────────────────

#[derive(Serialize)]
pub struct SessionReuseReport {
    pub attack: String,
    pub timestamp: String,
    pub total_requests: usize,
    pub success_count: usize,
    pub blocked_count: usize,
    pub error_count: usize,
    pub status_distribution: HashMap<u16, usize>,
    pub detection_codes: HashMap<String, usize>,
    pub latency: LatencyStats,
    pub phases: SessionReusePhases,
    pub verdict: String,
}

#[derive(Serialize)]
pub struct SessionReusePhases {
    pub login_ok: bool,
    pub first_refresh_ok: bool,
    pub old_token_rejected: bool,
    pub old_token_status: u16,
    pub old_token_code: String,
    pub new_token_works: bool,
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
) -> Result<SessionReuseReport, String> {

    let mut latencies: Vec<u64> = Vec::new();
    let mut status_dist: HashMap<u16, usize> = HashMap::new();
    let mut code_dist: HashMap<String, usize> = HashMap::new();
    let mut success_count: usize = 0;
    let mut blocked_count: usize = 0;
    let mut error_count: usize = 0;

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 1 — Login → get refreshToken A
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    println!("[SESS] Phase 1: Logging in to get refresh token A");

    let login = client.login(email, password).await
        .map_err(|e| format!("login failed: {}", e))?;

    let token_a = login.refresh_token.clone();
    println!("[SESS]   Token A obtained ({} chars)", token_a.len());

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 2 — Refresh with A → get refreshToken B
    //  This should rotate the token, invalidating A.
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    println!("[SESS] Phase 2: Refreshing with token A to get token B");

    let refresh_result = client.refresh_with_token(&token_a).await;
    latencies.push(refresh_result.latency_ms);
    *status_dist.entry(refresh_result.status).or_insert(0) += 1;

    let first_refresh_ok = refresh_result.status == 200;

    if refresh_result.status == 200 {
        success_count += 1;
    } else {
        error_count += 1;
    }

    if !refresh_result.code.is_empty() {
        *code_dist.entry(refresh_result.code.clone()).or_insert(0) += 1;
    }

    println!("[SESS]   Refresh result: status={} code={}", refresh_result.status, refresh_result.code);

    if !first_refresh_ok {
        return Err(format!(
            "first refresh failed (status {}), cannot test reuse",
            refresh_result.status
        ));
    }

    // Small delay to ensure rotation is committed
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 3 — Reuse old token A (should be rejected)
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    println!("[SESS] Phase 3: Attempting to reuse OLD token A (should fail)");

    let reuse_result = client.refresh_with_token(&token_a).await;
    latencies.push(reuse_result.latency_ms);
    *status_dist.entry(reuse_result.status).or_insert(0) += 1;

    if !reuse_result.code.is_empty() {
        *code_dist.entry(reuse_result.code.clone()).or_insert(0) += 1;
    }

    let old_token_rejected = reuse_result.status != 200;

    if reuse_result.status == 200 {
        success_count += 1;
    } else {
        blocked_count += 1;
    }

    println!("[SESS]   Reuse result: status={} code={} rejected={}",
        reuse_result.status, reuse_result.code, old_token_rejected);

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 4 — Try multiple reuse attempts
    //  (attackers often retry)
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    println!("[SESS] Phase 4: 5 additional reuse attempts with old token A");

    for attempt in 1..=5 {
        let r = client.refresh_with_token(&token_a).await;
        latencies.push(r.latency_ms);
        *status_dist.entry(r.status).or_insert(0) += 1;

        if !r.code.is_empty() {
            *code_dist.entry(r.code.clone()).or_insert(0) += 1;
        }

        if r.status == 200 {
            success_count += 1;
            println!("[SESS]   Attempt {}: 🚨 ACCEPTED (status {})", attempt, r.status);
        } else {
            blocked_count += 1;
            println!("[SESS]   Attempt {}: blocked (status={} code={})", attempt, r.status, r.code);
        }
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  VERDICT
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    // success_count includes the first legitimate refresh (1) +
    // any reuses that shouldn't have worked
    let reuse_successes = if success_count > 1 { success_count - 1 } else { 0 };

    let verdict = if reuse_successes > 0 {
        "CRITICAL"   // old token accepted = session hijack possible
    } else if old_token_rejected {
        "SECURE"     // token rotation + reuse detection working
    } else {
        "INCONCLUSIVE"
    };

    let latency = compute_latency(&latencies);

    println!();
    println!("[SESS] Reuse successes: {} (should be 0)", reuse_successes);
    println!("[SESS] Verdict: {}", verdict);

    let total_requests = success_count + blocked_count + error_count;

    Ok(SessionReuseReport {
        attack: "sequential_token_reuse".into(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        total_requests,
        success_count,
        blocked_count,
        error_count,
        status_distribution: status_dist,
        detection_codes: code_dist,
        latency,
        phases: SessionReusePhases {
            login_ok: true,
            first_refresh_ok,
            old_token_rejected,
            old_token_status: reuse_result.status,
            old_token_code: reuse_result.code,
            new_token_works: first_refresh_ok,
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
