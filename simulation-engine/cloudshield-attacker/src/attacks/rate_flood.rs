use crate::client::ApiClient;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const TOTAL_REQUESTS: usize = 200;
const CONCURRENCY: usize = 50;

// ── Report structures ────────────────────────────

#[derive(Serialize)]
pub struct RateFloodReport {
    pub attack: String,
    pub timestamp: String,
    pub total_requests: usize,
    pub success_count: usize,
    pub blocked_count: usize,
    pub error_count: usize,
    pub status_distribution: HashMap<u16, usize>,
    pub detection_codes: HashMap<String, usize>,
    pub latency: LatencyStats,
    pub flood_details: FloodDetails,
    pub verdict: String,
}

#[derive(Serialize)]
pub struct FloodDetails {
    pub target_endpoint: String,
    pub concurrency: usize,
    pub total_sent: usize,
    pub rate_limit_triggered: bool,
    pub first_429_at_request: usize,
    pub p95_latency_ms: u64,
    pub p99_latency_ms: u64,
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
) -> Result<RateFloodReport, String> {

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 1 — Login to get a valid access token
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    println!("[FLOOD] Phase 1: Logging in to obtain access token");

    let login = client.login(email, password).await
        .map_err(|e| format!("login failed: {}", e))?;

    let access_token = login.access_token.clone();
    println!("[FLOOD]   Token obtained ({} chars)", access_token.len());

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 2 — Fire concurrent requests
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    let target = "/api/v1/auth/profile";
    println!("[FLOOD] Phase 2: Sending {} requests ({} concurrent) to {}",
        TOTAL_REQUESTS, CONCURRENCY, target);

    let counter = Arc::new(AtomicUsize::new(0));
    let first_429 = Arc::new(AtomicUsize::new(0));

    // Launch in batches to control concurrency
    let mut all_results: Vec<RequestResult> = Vec::with_capacity(TOTAL_REQUESTS);
    let batches = (TOTAL_REQUESTS + CONCURRENCY - 1) / CONCURRENCY;

    for batch in 0..batches {
        let batch_size = CONCURRENCY.min(TOTAL_REQUESTS - batch * CONCURRENCY);
        let mut handles = Vec::with_capacity(batch_size);

        for _ in 0..batch_size {
            let c = client.clone();
            let token = access_token.clone();
            let cnt = Arc::clone(&counter);
            let f429 = Arc::clone(&first_429);
            let tgt = target.to_string();

            handles.push(tokio::spawn(async move {
                let req_num = cnt.fetch_add(1, Ordering::SeqCst) + 1;
                let r = c.get_authenticated(&tgt, &token).await;

                if r.status == 429 {
                    // Record the first request that got 429
                    f429.compare_exchange(0, req_num, Ordering::SeqCst, Ordering::SeqCst).ok();
                }

                RequestResult {
                    request_num: req_num,
                    status: r.status,
                    code: r.code,
                    latency_ms: r.latency_ms,
                }
            }));
        }

        for h in handles {
            match h.await {
                Ok(rr) => all_results.push(rr),
                Err(e) => {
                    eprintln!("[FLOOD] Task panic: {}", e);
                    all_results.push(RequestResult {
                        request_num: 0,
                        status: 0,
                        code: "TASK_PANIC".into(),
                        latency_ms: 0,
                    });
                }
            }
        }

        // Progress
        let done = (batch + 1) * CONCURRENCY;
        if done % 50 == 0 || batch == batches - 1 {
            println!("[FLOOD]   Sent {}/{}", done.min(TOTAL_REQUESTS), TOTAL_REQUESTS);
        }
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 3 — Analyze results
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    println!("[FLOOD] Phase 3: Analyzing {} responses", all_results.len());

    let mut success_count: usize = 0;
    let mut blocked_count: usize = 0;
    let mut error_count: usize = 0;
    let mut status_dist: HashMap<u16, usize> = HashMap::new();
    let mut code_dist: HashMap<String, usize> = HashMap::new();
    let mut latencies: Vec<u64> = Vec::new();

    for r in &all_results {
        *status_dist.entry(r.status).or_insert(0) += 1;

        if !r.code.is_empty() {
            *code_dist.entry(r.code.clone()).or_insert(0) += 1;
        }

        if r.status > 0 {
            latencies.push(r.latency_ms);
        }

        match r.status {
            200 => success_count += 1,
            429 => blocked_count += 1,
            401 | 403 => blocked_count += 1,
            0 => error_count += 1,
            _ => error_count += 1,
        }
    }

    // Latency percentiles
    latencies.sort_unstable();
    let p95 = percentile(&latencies, 95);
    let p99 = percentile(&latencies, 99);

    let latency = compute_latency(&latencies);

    let first_429_at = first_429.load(Ordering::SeqCst);
    let rate_limit_triggered = blocked_count > 0;

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  VERDICT
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    let total = all_results.len();
    let success_ratio = if total > 0 { success_count as f64 / total as f64 } else { 0.0 };

    let verdict = if blocked_count > 0 && success_ratio < 0.9 {
        "SECURE"       // rate limiter engaged and is effective
    } else if blocked_count > 0 && success_ratio >= 0.9 {
        "WEAK"         // some blocking but most requests pass
    } else if success_count == total {
        "VULNERABLE"   // no rate limiting at all
    } else {
        "INCONCLUSIVE"
    };

    println!();
    println!("[FLOOD] ═══════════════════════════════════════════");
    println!("[FLOOD] Total       : {}", total);
    println!("[FLOOD] Succeeded   : {} ({:.1}%)", success_count, success_ratio * 100.0);
    println!("[FLOOD] Blocked     : {}", blocked_count);
    println!("[FLOOD] Errors      : {}", error_count);
    if first_429_at > 0 {
        println!("[FLOOD] First 429   : at request #{}", first_429_at);
    }
    println!("[FLOOD] Latency avg : {}ms", latency.avg_ms);
    println!("[FLOOD] Latency p95 : {}ms", p95);
    println!("[FLOOD] Latency p99 : {}ms", p99);
    println!("[FLOOD] Verdict     : {}", verdict);

    Ok(RateFloodReport {
        attack: "api_rate_flood".into(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        total_requests: total,
        success_count,
        blocked_count,
        error_count,
        status_distribution: status_dist,
        detection_codes: code_dist,
        latency,
        flood_details: FloodDetails {
            target_endpoint: target.into(),
            concurrency: CONCURRENCY,
            total_sent: total,
            rate_limit_triggered,
            first_429_at_request: first_429_at,
            p95_latency_ms: p95,
            p99_latency_ms: p99,
        },
        verdict: verdict.into(),
    })
}

struct RequestResult {
    #[allow(dead_code)]
    request_num: usize,
    status: u16,
    code: String,
    latency_ms: u64,
}

fn percentile(sorted: &[u64], p: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = (p * sorted.len() / 100).min(sorted.len() - 1);
    sorted[idx]
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
