use crate::client::ApiClient;
use serde::Serialize;
use std::collections::HashMap;

const MAX_ATTEMPTS: usize = 50;

// ── Report structures ────────────────────────────

#[derive(Serialize)]
pub struct PasswordBruteReport {
    pub attack: String,
    pub timestamp: String,
    pub total_requests: usize,
    pub success_count: usize,
    pub blocked_count: usize,
    pub error_count: usize,
    pub status_distribution: HashMap<u16, usize>,
    pub detection_codes: HashMap<String, usize>,
    pub latency: LatencyStats,
    pub brute_details: BruteDetails,
    pub verdict: String,
}

#[derive(Serialize)]
pub struct BruteDetails {
    pub target_email: String,
    pub total_attempts: usize,
    pub attempts_before_block: usize,
    pub rate_limited: bool,
    pub account_locked: bool,
    pub block_status: u16,
    pub block_code: String,
}

#[derive(Serialize)]
pub struct LatencyStats {
    pub min_ms: u64,
    pub max_ms: u64,
    pub avg_ms: u64,
}

// ── Password corpus ──────────────────────────────

fn bad_passwords() -> Vec<String> {
    let base = vec![
        "password", "123456", "admin123", "qwerty", "letmein",
        "welcome1", "monkey", "dragon", "master", "abc123",
        "password1", "iloveyou", "trustno1", "sunshine", "princess",
        "football", "shadow", "michael", "login", "starwars",
        "passw0rd", "hello", "charlie", "donald", "batman",
        "access", "thunder", "superman", "qwerty123", "123123",
        "654321", "bailey", "joshua", "mustang", "winter",
        "pokemon", "robert", "hunter", "freedom", "thomas",
        "secret", "buster", "pepper", "ginger", "matrix",
        "111111", "000000", "zxcvbn", "asdfgh", "1q2w3e",
    ];
    base.into_iter().map(|s| s.to_string()).collect()
}

// ── Attack execution ─────────────────────────────

pub async fn run(
    client: &ApiClient,
    email: &str,
    _password: &str,
) -> Result<PasswordBruteReport, String> {

    let passwords = bad_passwords();
    let attempt_count = passwords.len().min(MAX_ATTEMPTS);

    let mut latencies: Vec<u64> = Vec::new();
    let mut status_dist: HashMap<u16, usize> = HashMap::new();
    let mut code_dist: HashMap<String, usize> = HashMap::new();
    let mut success_count: usize = 0;
    let mut blocked_count: usize = 0;
    let mut error_count: usize = 0;
    let mut attempts_before_block: usize = 0;
    let mut rate_limited = false;
    let mut account_locked = false;
    let mut block_status: u16 = 0;
    let mut block_code = String::new();

    println!("[BRUTE] Starting password brute-force against: {}", email);
    println!("[BRUTE] Will attempt {} passwords sequentially", attempt_count);
    println!();

    for (i, pwd) in passwords.iter().take(attempt_count).enumerate() {
        let attempt_num = i + 1;

        let r = client.login_raw(email, pwd).await;
        latencies.push(r.latency_ms);
        *status_dist.entry(r.status).or_insert(0) += 1;

        if !r.code.is_empty() {
            *code_dist.entry(r.code.clone()).or_insert(0) += 1;
        }

        match r.status {
            200 => {
                // This shouldn't happen with wrong passwords
                success_count += 1;
                println!("[BRUTE]   #{:02}: 🚨 LOGIN SUCCEEDED with '{}' (status=200)", attempt_num, pwd);
            }
            429 => {
                blocked_count += 1;
                if !rate_limited {
                    rate_limited = true;
                    attempts_before_block = attempt_num;
                    block_status = r.status;
                    block_code = r.code.clone();
                    println!("[BRUTE]   #{:02}: ✅ RATE LIMITED (429) — after {} attempts", attempt_num, attempt_num);
                }
            }
            423 => {
                // Account locked
                blocked_count += 1;
                if !account_locked {
                    account_locked = true;
                    attempts_before_block = attempt_num;
                    block_status = r.status;
                    block_code = r.code.clone();
                    println!("[BRUTE]   #{:02}: ✅ ACCOUNT LOCKED (423) — after {} attempts", attempt_num, attempt_num);
                }
            }
            401 => {
                // Normal rejection — expected for wrong passwords
                error_count += 1;
                if attempt_num <= 5 || attempt_num % 10 == 0 {
                    println!("[BRUTE]   #{:02}: Rejected (401) code={} latency={}ms",
                        attempt_num, r.code, r.latency_ms);
                }
            }
            _ => {
                error_count += 1;
                if !rate_limited && !account_locked {
                    println!("[BRUTE]   #{:02}: Unexpected status={} code={}", attempt_num, r.status, r.code);
                }
                // Treat any non-200 non-401 as potential blocking
                if r.status == 403 {
                    blocked_count += 1;
                    if !rate_limited {
                        rate_limited = true;
                        attempts_before_block = attempt_num;
                        block_status = r.status;
                        block_code = r.code.clone();
                    }
                }
            }
        }

        // If we're already blocked, do a few more to confirm, then stop
        if (rate_limited || account_locked) && blocked_count >= 3 {
            println!("[BRUTE]   Stopping early — blocking confirmed after {} total attempts", attempt_num);
            break;
        }

        // Small delay to simulate realistic brute-force cadence
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  VERDICT
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    let total_requests = success_count + blocked_count + error_count;

    let verdict = if success_count > 0 {
        "CRITICAL"     // wrong password was accepted = auth bypass
    } else if rate_limited || account_locked {
        "SECURE"       // rate limiting or lockout engaged
    } else if total_requests >= attempt_count {
        "CRITICAL"     // all attempts ran without any blocking
    } else {
        "INCONCLUSIVE"
    };

    let latency = compute_latency(&latencies);

    println!();
    println!("[BRUTE] ═══════════════════════════════════════════");
    println!("[BRUTE] Total attempts : {}", total_requests);
    println!("[BRUTE] Successes      : {} (should be 0)", success_count);
    println!("[BRUTE] Rate limited   : {}", rate_limited);
    println!("[BRUTE] Account locked : {}", account_locked);
    if attempts_before_block > 0 {
        println!("[BRUTE] Blocked after  : {} attempts", attempts_before_block);
    }
    println!("[BRUTE] Avg latency    : {}ms", latency.avg_ms);
    println!("[BRUTE] Verdict        : {}", verdict);

    Ok(PasswordBruteReport {
        attack: "password_brute_force".into(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        total_requests,
        success_count,
        blocked_count,
        error_count,
        status_distribution: status_dist,
        detection_codes: code_dist,
        latency,
        brute_details: BruteDetails {
            target_email: email.to_string(),
            total_attempts: total_requests,
            attempts_before_block,
            rate_limited,
            account_locked,
            block_status,
            block_code,
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
