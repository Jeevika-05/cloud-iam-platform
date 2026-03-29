# Rust Attack Simulation Engine — Architecture Design

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        HOST MACHINE                             │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                   Docker Network: backend                 │  │
│  │                                                           │  │
│  │  ┌─────────────┐    ┌─────────────┐    ┌──────────────┐  │  │
│  │  │  postgres    │    │  api        │    │  attacker    │  │  │
│  │  │  (authdb)    │◄───│  (Node.js)  │◄───│  (Rust CLI)  │  │  │
│  │  │  :5432       │    │  :3000      │    │  one-shot    │  │  │
│  │  └─────────────┘    └──────┬──────┘    └──────┬───────┘  │  │
│  │                            │                   │          │  │
│  │                            │ HTTP only          │          │  │
│  │                            │ (no DB access)     │          │  │
│  │                            ▼                   ▼          │  │
│  │                     ┌─────────────────────────────┐       │  │
│  │                     │  shared volume: /reports     │       │  │
│  │                     │  (JSON attack results)      │       │  │
│  │                     └─────────────────────────────┘       │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

> [!IMPORTANT]
> The Rust attacker container has **zero** access to PostgreSQL or any internal service. It communicates **exclusively** over HTTP to `http://api:3000`. This is a hard architectural constraint — the simulator is a true external adversary.

---

## 1. Rust CLI Structure

### Project Layout

```
simulation-engine/
├── Cargo.toml
├── Dockerfile
├── config/
│   └── default.toml          # target URL, credentials, thresholds
├── src/
│   ├── main.rs               # CLI entry point (clap)
│   ├── config.rs             # config loader (toml + env overlay)
│   ├── client.rs             # shared HTTP client (reqwest + cookie jar)
│   ├── reporter.rs           # result aggregation + JSON/table output
│   ├── attacks/
│   │   ├── mod.rs            # attack trait + registry
│   │   ├── token_race.rs     # ATK-01: refresh token concurrency race
│   │   ├── mfa_replay.rs     # ATK-02: MFA temp token replay
│   │   ├── rate_flood.rs     # ATK-03: rate limit validation
│   │   └── idor.rs           # ATK-04: IDOR via user ID enumeration
│   └── auth.rs               # helper: login flow + obtain valid tokens
```

### CLI Interface (via `clap`)

```
cloudshield-attacker [OPTIONS] <COMMAND>

COMMANDS:
  run         Run all attack modules
  attack      Run a specific attack module
  list        List available attack modules
  report      View last run results

OPTIONS:
  --target <URL>           Target API base URL [default: http://api:3000]
  --config <PATH>          Config file path [default: config/default.toml]
  --concurrency <N>        Max concurrent tasks [default: 50]
  --output <PATH>          Report output path [default: /reports/results.json]
  --format <FORMAT>        Output format: json | table [default: table]
  --verbose                Enable debug logging

EXAMPLES:
  cloudshield-attacker run --target http://api:3000
  cloudshield-attacker attack token-race --concurrency 100
  cloudshield-attacker attack rate-flood --target http://localhost:3000
```

### Crate Dependencies

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
reqwest = { version = "0.12", features = ["json", "cookies"] }
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
comfy-table = "7"
chrono = "0.4"
tracing = "0.1"
tracing-subscriber = "0.3"
colored = "2"
uuid = { version = "1", features = ["v4"] }
```

---

## 2. Configuration System

### `config/default.toml`

```toml
[target]
base_url = "http://api:3000"
api_prefix = "/api/v1"
internal_prefix = "/api/internal"

[credentials]
# Seed user for authenticated attack flows
email = "attacker@test.com"
password = "AttackTest123!"
name = "Attack Simulator"

[internal]
# For zero-trust endpoint testing
service_token = "test-internal-token-value"

[thresholds]
# Expected limits from your rateLimiter.js
auth_limit = 20           # authLimiter max
mfa_limit = 5             # mfaLimiter max
internal_limit = 5         # internalLimiter max (testing value)
api_limit = 500            # apiLimiter max (dev mode)

[concurrency]
token_race_tasks = 50      # simultaneous refresh requests
rate_flood_burst = 30      # requests to exceed limit
```

> [!TIP]
> Environment variables override config values. Example: `TARGET_BASE_URL=http://localhost:3000` overrides `[target].base_url`. This lets the same image work in Docker and local dev.

---

## 3. Attack Modules — Detailed Design

### Common Attack Trait

```rust
// src/attacks/mod.rs

#[async_trait]
pub trait Attack: Send + Sync {
    /// Unique identifier (e.g., "token-race")
    fn id(&self) -> &str;

    /// Human-readable description
    fn description(&self) -> &str;

    /// Execute the attack, return structured result
    async fn execute(&self, client: &AttackClient, config: &Config) -> AttackResult;
}

pub struct AttackResult {
    pub attack_id: String,
    pub passed: bool,              // did the IAM defend correctly?
    pub total_requests: u32,
    pub expected_blocks: u32,
    pub actual_blocks: u32,
    pub status_distribution: HashMap<u16, u32>,  // status_code -> count
    pub duration_ms: u64,
    pub details: Vec<RequestLog>,
    pub verdict: String,           // human-readable conclusion
}

pub struct RequestLog {
    pub request_num: u32,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub response_code: Option<String>,  // e.g., "SESSION_COMPROMISED"
    pub latency_ms: u64,
}
```

---

### ATK-01: Token Rotation Race (`token_race.rs`)

**Goal:** Verify that concurrent refresh token reuse triggers `SESSION_COMPROMISED` and revokes all sessions.

**Maps to your code:** `auth.service.js` → `refresh()` → atomic `updateMany` with `isUsed: false` guard.

```
FLOW:
  1. POST /api/v1/auth/register  → create test user
  2. POST /api/v1/auth/login     → obtain refreshToken (from Set-Cookie)
  3. Capture the raw refreshToken cookie value
  4. Spawn 50 concurrent tasks, ALL using the SAME refreshToken
     → Each sends POST /api/v1/auth/refresh with Cookie: refreshToken=<captured>
  5. Collect all responses

EXPECTED:
  - Exactly 1 request returns 200 (new tokens issued)
  - Remaining 49 return 401 with code: "SESSION_COMPROMISED"
  - After attack: ALL sessions for this user are revoked

VALIDATION:
  - Count 200s == 1
  - Count 401s with SESSION_COMPROMISED >= 48
  - Post-attack: POST /api/v1/auth/refresh with the NEW token also fails
    (because all sessions were revoked by the reuse detection)

VERDICT LOGIC:
  if (count_200 == 1 && count_compromised >= (total - 2)):
    PASS — "Atomic rotation held. Reuse correctly detected."
  else if (count_200 > 1):
    FAIL — "Multiple tokens issued from same refresh token. Race condition exists."
  else:
    FAIL — "Unexpected response distribution."
```

---

### ATK-02: MFA Temp Token Replay (`mfa_replay.rs`)

**Goal:** Verify that replaying a used `tempToken` is rejected, and that brute-forcing MFA codes triggers rate limiting.

**Maps to your code:** `auth.service.js` → `validateMfaLogin()` → `lastTempTokenJti` atomic check + `mfaLimiter` (5 req/15min).

```
FLOW:
  Phase A — Replay Detection:
    1. Register user + enable MFA (POST /api/v1/mfa/setup + /api/v1/mfa/verify)
    2. POST /api/v1/auth/login → receive { status: "MFA_REQUIRED", tempToken }
    3. Send tempToken with INVALID code (to consume the jti without completing login)
    4. Re-login to get a FRESH tempToken
    5. Now replay the OLD tempToken from step 2
       → POST /api/v1/auth/mfa/validate-login { tempToken: OLD, code: "000000" }

  EXPECTED: 401 with code "TOKEN_REUSE_DETECTED" or "TOKEN_INVALID"

  Phase B — Rate Limit:
    1. Login → get fresh tempToken
    2. Send 8 rapid requests to POST /api/v1/auth/mfa/validate-login
       with valid tempToken but wrong codes

  EXPECTED: First 5 return 400 (INVALID_MFA_CODE), requests 6+ return 429 (MFA_RATE_LIMITED)

VERDICT LOGIC:
  Phase A PASS: old tempToken rejected
  Phase B PASS: 429 triggered at request 6
```

---

### ATK-03: Rate Limit Flood (`rate_flood.rs`)

**Goal:** Verify all rate limiters fire correctly at their configured thresholds.

**Maps to your code:** `rateLimiter.js` → `authLimiter` (20), `internalLimiter` (5), `apiLimiter` (500/100).

```
FLOW:
  Sub-test A — Auth Endpoint Flood:
    1. Send 25 POST /api/v1/auth/login with garbage credentials
    2. Track when 429 appears

  EXPECTED: Requests 1-20 return 401, requests 21+ return 429

  Sub-test B — Internal Endpoint Flood:
    1. Send 8 GET /api/internal/users/<any-uuid>
       with header x-internal-token: <valid-token>
    2. Track when 429 appears

  EXPECTED: Requests 1-5 return 200, requests 6+ return 429

  Sub-test C — Global API Flood (optional):
    1. Send 510 GET /health requests
    2. Track when 429 appears

  EXPECTED: 429 after request 500 (dev mode)

VERDICT LOGIC:
  PASS per sub-test: 429 triggers within ±1 of configured max
```

---

### ATK-04: IDOR via User ID Enumeration (`idor.rs`)

**Goal:** Verify that authenticated users cannot access other users' data, and that the ABAC policy engine blocks cross-user reads.

**Maps to your code:** `user.routes.js` → `authorizePolicy({ action: 'read', resource: 'user' })`.

```
FLOW:
  1. Register User A → login → get accessToken_A
  2. Register User B → login → get accessToken_B
  3. GET /api/v1/users/<User_B_ID> with Authorization: Bearer <accessToken_A>

  EXPECTED: 403 Forbidden (ABAC policy denies cross-user read)

  4. GET /api/v1/users/<User_A_ID> with Authorization: Bearer <accessToken_A>

  EXPECTED: 200 OK (own resource)

  5. GET /api/v1/users/<random-uuid> with Authorization: Bearer <accessToken_A>

  EXPECTED: 403 or 404 (not 500)

  6. GET /api/v1/users/<sql-injection-string> with Authorization: Bearer <accessToken_A>

  EXPECTED: 400 (validation catches malformed ID)

VERDICT LOGIC:
  PASS: cross-user blocked, own-user allowed, invalid IDs handled gracefully
```

---

## 4. Execution Flow & Concurrency Model

```
┌─────────────┐
│   main.rs   │
│  (CLI parse)│
└──────┬──────┘
       │
       ▼
┌──────────────┐     ┌────────────────────────────────────────┐
│  config.rs   │────►│  Load TOML + env overrides             │
└──────┬───────┘     └────────────────────────────────────────┘
       │
       ▼
┌──────────────┐     ┌────────────────────────────────────────┐
│  auth.rs     │────►│  Register seed user, login, get tokens │
│  (bootstrap) │     │  Store: access_token, refresh_cookie   │
└──────┬───────┘     └────────────────────────────────────────┘
       │
       ▼
┌──────────────┐     ┌────────────────────────────────────────┐
│  Attack      │────►│  For each attack module:               │
│  Runner      │     │    1. Print attack header               │
│              │     │    2. Call attack.execute()              │
│              │     │    3. Collect AttackResult               │
│              │     │    4. Print live pass/fail               │
└──────┬───────┘     └────────────────────────────────────────┘
       │
       ▼
┌──────────────┐     ┌────────────────────────────────────────┐
│  reporter.rs │────►│  Aggregate all AttackResults            │
│              │     │  Output: CLI table + JSON file          │
└──────────────┘     └────────────────────────────────────────┘
```

### Concurrency via Tokio

```rust
// Inside token_race.rs execute()

let refresh_cookie = client.login(&config.credentials).await?;

let mut handles = Vec::new();

for i in 0..config.concurrency.token_race_tasks {
    let client = client.clone();
    let cookie = refresh_cookie.clone();

    handles.push(tokio::spawn(async move {
        let start = Instant::now();
        let resp = client
            .post(&format!("{}/api/v1/auth/refresh", config.target.base_url))
            .header("Cookie", format!("refreshToken={}", cookie))
            .send()
            .await;

        RequestLog {
            request_num: i,
            status: resp.status().as_u16(),
            response_code: resp.json::<Value>().await.ok()
                .and_then(|v| v["code"].as_str().map(String::from)),
            latency_ms: start.elapsed().as_millis() as u64,
            ..Default::default()
        }
    }));
}

let results = futures::future::join_all(handles).await;
```

---

## 5. Shared HTTP Client Design

```rust
// src/client.rs

pub struct AttackClient {
    inner: reqwest::Client,
    base_url: String,
}

impl AttackClient {
    pub fn new(base_url: &str) -> Self {
        let client = reqwest::Client::builder()
            .cookie_store(true)           // automatic cookie jar
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(false)
            .user_agent("CloudShield-Attacker/1.0")
            .build()
            .expect("Failed to build HTTP client");

        Self {
            inner: client,
            base_url: base_url.to_string(),
        }
    }

    /// Login and return the raw refreshToken cookie value
    pub async fn login(&self, creds: &Credentials) -> Result<String> {
        let resp = self.inner
            .post(format!("{}/api/v1/auth/login", self.base_url))
            .json(&json!({
                "email": creds.email,
                "password": creds.password
            }))
            .send()
            .await?;

        // Extract refreshToken from Set-Cookie header
        let cookie = resp.cookies()
            .find(|c| c.name() == "refreshToken")
            .map(|c| c.value().to_string())
            .ok_or_else(|| anyhow!("No refreshToken cookie in login response"))?;

        Ok(cookie)
    }

    /// Register a new user (idempotent — ignores 409)
    pub async fn register(&self, creds: &Credentials) -> Result<()> {
        let resp = self.inner
            .post(format!("{}/api/v1/auth/register", self.base_url))
            .json(&json!({
                "name": creds.name,
                "email": creds.email,
                "password": creds.password
            }))
            .send()
            .await?;

        match resp.status().as_u16() {
            201 | 409 => Ok(()),  // created or already exists
            s => Err(anyhow!("Registration failed with status {}", s)),
        }
    }
}
```

---

## 6. Reporter Output

### CLI Table Output (via `comfy-table`)

```
╔══════════════════════════════════════════════════════════════════════╗
║              CloudShield Attack Simulation Report                   ║
║              Target: http://api:3000                                ║
║              Time: 2026-03-29T17:30:00Z                             ║
╠══════════════════════════════════════════════════════════════════════╣

┌────────┬──────────────────────┬────────┬──────────┬────────┬────────┐
│ ID     │ Attack               │ Result │ Requests │ Blocks │ Time   │
├────────┼──────────────────────┼────────┼──────────┼────────┼────────┤
│ ATK-01 │ Token Rotation Race  │ ✅ PASS │ 50       │ 49/49  │ 342ms  │
│ ATK-02 │ MFA Temp Replay      │ ✅ PASS │ 10       │ 10/10  │ 127ms  │
│ ATK-03 │ Rate Limit Flood     │ ✅ PASS │ 33       │ 8/8    │ 891ms  │
│ ATK-04 │ IDOR Enumeration     │ ⚠️ WARN │ 4        │ 2/3    │ 56ms   │
└────────┴──────────────────────┴────────┴──────────┴────────┴────────┘

Overall: 3/4 PASSED | 1 WARNING | 0 FAILED
```

### JSON Report (`/reports/results.json`)

```json
{
  "target": "http://api:3000",
  "timestamp": "2026-03-29T17:30:00Z",
  "summary": { "passed": 3, "warned": 1, "failed": 0 },
  "attacks": [
    {
      "attack_id": "token-race",
      "passed": true,
      "total_requests": 50,
      "expected_blocks": 49,
      "actual_blocks": 49,
      "status_distribution": { "200": 1, "401": 49 },
      "duration_ms": 342,
      "verdict": "Atomic rotation held. Reuse correctly detected."
    }
  ]
}
```

---

## 7. Docker Integration

### Updated `docker-compose.yml`

```yaml
services:
  postgres:
    # ... existing config unchanged ...

  api:
    # ... existing config unchanged ...

  migrate:
    # ... existing config unchanged ...

  # ─── NEW: Rust Attack Simulator ───
  attacker:
    build:
      context: ../simulation-engine
      dockerfile: Dockerfile
    container_name: cloudshield_attacker
    depends_on:
      api:
        condition: service_healthy
    environment:
      TARGET_BASE_URL: "http://api:3000"
      INTERNAL_SERVICE_TOKEN: "${INTERNAL_SERVICE_TOKEN}"
    volumes:
      - attack_reports:/reports
    networks:
      - backend
    # One-shot: run attacks, then exit
    restart: "no"

volumes:
  postgres_data:
  attack_reports:      # shared volume for JSON results

networks:
  backend:
```

### Rust Dockerfile (`simulation-engine/Dockerfile`)

```dockerfile
# ─── Stage 1: Build ───
FROM rust:1.82-slim AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src
COPY src/ src/
COPY config/ config/
RUN cargo build --release

# ─── Stage 2: Runtime ───
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/cloudshield-attacker /usr/local/bin/
COPY --from=builder /app/config /config
RUN mkdir /reports
ENTRYPOINT ["cloudshield-attacker"]
CMD ["run", "--config", "/config/default.toml", "--output", "/reports/results.json"]
```

### Network Isolation

```
┌─────────────────────── backend network ──────────────────────┐
│                                                               │
│   attacker ──HTTP──► api ──SQL──► postgres                   │
│      │                 │                                      │
│      │                 │  attacker has NO route to postgres   │
│      ╳ ◄───────────── ╳  (enforced by Docker networking)     │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

> [!NOTE]
> The `attacker` container can resolve `api:3000` via Docker DNS but **cannot** resolve `postgres:5432` because it has no PostgreSQL client and no connection string. This is black-box by design, not by convention.

---

## 8. Observability — Verifying Detection Without Prometheus

Since full Prometheus/Grafana is a future phase, here is a minimal observability bridge:

### Option A: Structured Log File (Recommended Now)

Add a file transport to your existing Winston logger:

```javascript
// api/src/shared/utils/logger.js — add file transport
import { createLogger, format, transports } from 'winston';

const logger = createLogger({
  // ... existing config ...
  transports: [
    // ... existing console transport ...
    new transports.File({
      filename: '/app/logs/security.jsonl',   // mount as Docker volume
      level: 'warn',                          // only security events
      format: format.combine(format.timestamp(), format.json()),
    }),
  ],
});
```

Mount a shared volume between `api` and `attacker`:

```yaml
# docker-compose.yml additions
api:
  volumes:
    - security_logs:/app/logs

attacker:
  volumes:
    - security_logs:/logs:ro    # read-only access to API logs
```

The Rust engine can then **read** `/logs/security.jsonl` after an attack run and correlate:

```rust
// src/reporter.rs — log correlation
fn correlate_logs(attack_result: &AttackResult, log_path: &Path) -> CorrelationReport {
    let logs: Vec<LogEntry> = read_jsonl(log_path);

    let detected = logs.iter()
        .filter(|l| l.message.contains("TOKEN_REUSE_DETECTED")
                  || l.message.contains("SESSION_COMPROMISED"))
        .count();

    CorrelationReport {
        attacks_fired: attack_result.total_requests,
        attacks_detected_in_logs: detected,
        detection_rate: detected as f64 / attack_result.total_requests as f64,
    }
}
```

### Option B: Dedicated Detection Endpoint (Quick Addition)

Add a lightweight endpoint to your Node API that the Rust engine can query:

```
GET /api/v1/analytics/security-events?since=<ISO_TIMESTAMP>&action=TOKEN_REUSE_DETECTED
```

This already aligns with your existing `analytics.routes.js` module — you would query the `AuditLog` model directly.

---

## 9. Future Expansion Path

### Phase 1 → Phase 2: Prometheus + Grafana

```
attacker ──► api ──► prometheus (scrape /metrics)
                          │
                          ▼
                     grafana dashboard
                     "Attack Detection Rate"
                     "Response Latency Under Attack"
                     "Session Compromises / min"
```

**What changes:**
- Add `prom-client` to Node API, expose `/metrics`
- Rust reporter pushes results to Pushgateway
- Grafana dashboard visualizes attack vs. detection correlation

### Phase 2 → Phase 3: Neo4j Attack Graph

```rust
// Future: Rust writes attack paths to Neo4j
neo4j_client.execute(
    "CREATE (a:Attack {id: $id, type: $type})-[:TARGETED]->(e:Endpoint {path: $path})"
        "-[:RESULTED_IN]->(r:Response {status: $status, code: $code})",
    params
).await;
```

**Graph queries:**
- "Which endpoints have the highest attack surface?"
- "What attack chains lead to SESSION_COMPROMISED?"
- "Show all paths from anonymous access to admin data"

### Phase 3 → Phase 4: Kubernetes Deployment

```yaml
# k8s/attack-job.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: cloudshield-attacker
spec:
  template:
    spec:
      containers:
      - name: attacker
        image: cloudshield-attacker:latest
        env:
        - name: TARGET_BASE_URL
          value: "http://iam-api-service.iam.svc.cluster.local:3000"
      restartPolicy: Never
      # Network policy: only allow egress to iam-api-service
```

---

## 10. Implementation Order

| Step | Task | Estimated Effort |
|------|------|-----------------|
| 1 | Scaffold Rust project with `cargo init`, add dependencies | 30 min |
| 2 | Implement `config.rs` + `client.rs` (login/register helpers) | 1 hour |
| 3 | Implement `ATK-01: token_race.rs` — most critical attack | 2 hours |
| 4 | Implement `reporter.rs` with CLI table output | 1 hour |
| 5 | Add Dockerfile + docker-compose integration | 30 min |
| 6 | Implement `ATK-03: rate_flood.rs` — validates all limiters | 1 hour |
| 7 | Implement `ATK-02: mfa_replay.rs` | 1.5 hours |
| 8 | Implement `ATK-04: idor.rs` | 1 hour |
| 9 | Add log correlation (Option A) | 1 hour |
| 10 | End-to-end Docker test run | 30 min |

**Total estimated: ~10 hours of focused work.**

---

## Open Questions

> [!WARNING]
> **Rate Limiter Reset:** Your `internalLimiter` is currently set to `max: 5` for testing. The Rust engine needs this value in its config to calculate expected thresholds. Before production runs, reset to `max: 50` and update `config/default.toml` accordingly.

> [!IMPORTANT]
> **MFA Testing Complexity:** ATK-02 requires a test user with MFA enabled. This means the Rust engine must call `/api/v1/mfa/setup` and `/api/v1/mfa/verify` during bootstrap. This requires generating valid TOTP codes in Rust — you'll need the `totp-rs` crate and the TOTP secret from the setup response. Confirm: does your `/api/v1/mfa/setup` response include the raw TOTP secret (for QR generation)? If so, Rust can capture it and generate valid codes.

> [!IMPORTANT]
> **Seed User Cleanup:** Should the Rust engine clean up test users after each run, or should they persist for log correlation? Recommend: persist, and use a naming convention (`attacker-*@test.com`) so they're easily identifiable.
