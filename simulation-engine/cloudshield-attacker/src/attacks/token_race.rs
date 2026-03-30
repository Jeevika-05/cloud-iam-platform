use crate::event::GraphEvent;
use crate::client::ApiClient;
use serde::Serialize;
use std::collections::HashMap;

const CONCURRENCY: usize = 50;

// ── Report structures ────────────────────────────

#[derive(Serialize)]
pub struct AttackReport {
    pub attack: String,
    pub timestamp: String,
    pub total_requests: usize,
    pub success_count: usize,
    pub blocked_count: usize,
    pub error_count: usize,
    pub verdict: String,
    pub status_distribution: HashMap<u16, usize>,
    pub detection_codes: HashMap<String, usize>,
    pub latency: LatencyStats,
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
    user_id: &str,
    correlation_id: &str,
) -> Result<(AttackReport, GraphEvent), String> {
    // Step 1 — Login to obtain a valid refresh token
    println!("[RACE] Step 1: Logging in...");
    let login = client.login(email, password).await?;
    let stolen_token = login.refresh_token.clone();
    println!("[RACE] Got refresh token ({} chars)", stolen_token.len());

    // Step 2 — Fire CONCURRENCY requests with the SAME token
    println!("[RACE] Step 2: Launching {} concurrent refresh requests...", CONCURRENCY);

    let mut handles = Vec::with_capacity(CONCURRENCY);
    for _ in 0..CONCURRENCY {
        let c = client.clone();
        let t = stolen_token.clone();
        handles.push(tokio::spawn(async move {
            c.refresh_with_token(&t).await
        }));
    }

    // Collect results
    let mut results = Vec::with_capacity(CONCURRENCY);
    let mut error_count: usize = 0;
    for h in handles {
        match h.await {
            Ok(r) => results.push(r),
            Err(e) => {
                eprintln!("[RACE] task panic: {}", e);
                error_count += 1;
            }
        }
    }

    // Step 3 — Analyse
    println!("[RACE] Step 3: Analysing {} responses...", results.len());

    let mut success_count: usize = 0;
    let mut blocked_count: usize = 0;
    let mut status_dist: HashMap<u16, usize> = HashMap::new();
    let mut code_dist: HashMap<String, usize> = HashMap::new();
    let mut latencies: Vec<u64> = Vec::new();

    for r in &results {
        if r.status == 0 {
            error_count += 1;
            continue;
        }

        *status_dist.entry(r.status).or_insert(0) += 1;
        latencies.push(r.latency_ms);

        if !r.code.is_empty() {
            *code_dist.entry(r.code.clone()).or_insert(0) += 1;
        }

        match r.status {
            200 => success_count += 1,
            401 => blocked_count += 1,
            429 => blocked_count += 1, // rate-limited counts as blocked
            _ => {}
        }
    }

    // Latency stats
    let latency = if latencies.is_empty() {
        LatencyStats { min_ms: 0, max_ms: 0, avg_ms: 0 }
    } else {
        let min = *latencies.iter().min().unwrap();
        let max = *latencies.iter().max().unwrap();
        let avg = latencies.iter().sum::<u64>() / latencies.len() as u64;
        LatencyStats { min_ms: min, max_ms: max, avg_ms: avg }
    };

    // Verdict
    let verdict = if success_count >= 2 {
        "CRITICAL"    // race condition: multiple refreshes accepted
    } else if success_count <= 1 && blocked_count > 0 {
        "SECURE"      // reuse correctly detected
    } else {
        "INCONCLUSIVE"
    };

    println!("[RACE] Results: {} ok, {} blocked, {} errors", success_count, blocked_count, error_count);
    println!("[RACE] Verdict: {}", verdict);

    let report = AttackReport {
        attack: "token_race_condition".into(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        total_requests: CONCURRENCY,
        success_count,
        blocked_count,
        error_count,
        verdict: verdict.into(),
        status_distribution: status_dist,
        detection_codes: code_dist,
        latency,
    };

    let event = GraphEvent::new(
        correlation_id,
        user_id,
        Some(email.to_string()),
        "TOKEN_RACE",
        "/api/v1/auth/refresh",
        &report.verdict,
    );

    Ok((report, event))
}
