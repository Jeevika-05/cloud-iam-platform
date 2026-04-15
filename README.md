# Cloud IAM Security Platform

A cloud-native, production-grade **Identity and Access Management (IAM) Security Platform** featuring JWT-based authentication with RS256 key rotation, fine-grained RBAC/ABAC authorization, TOTP multi-factor authentication, real-time threat detection, an adaptive IP defense pipeline, a graph-based security intelligence layer powered by Neo4j, a full Prometheus/Grafana observability stack, and a Rust-powered external attack simulation engine.

---

## Overview

### What It Does

The Cloud IAM Security Platform is a full-stack security system that handles the complete lifecycle of user identity, session management, and threat response for a cloud environment. It is simultaneously:

- A **hardened authentication service** — handling local credential auth, Google OAuth 2.0, TOTP-based MFA, and JWT token issuance/rotation/revocation with RS256 asymmetric keys.
- A **real-time security analytics engine** — ingesting all security events into a Redis stream, scoring them with a risk engine, and persisting them into both PostgreSQL (structured storage) and Neo4j (graph intelligence).
- An **adaptive active defense system** — automatically detecting attack patterns, recording strikes against offending IPs, and escalating bans (10 min → 1 hour → 24 hours) using a progressive ban escalation strategy.
- A **security simulation and training platform** — allowing admins to trigger realistic attack scenarios (brute force, JWT tampering, session hijack, IDOR, CSRF, and more) against the live system to validate detection coverage.
- A **graph-based threat intelligence visualizer** — rendering attack chains, defense events, IP relationships, and user behavior as an interactive force-directed graph using Neo4j and React.

### Problem It Solves

Traditional IAM solutions handle authentication and authorization but do not provide real-time visibility into attack patterns, automated response, or a live attack simulation capability. This platform closes that gap by combining security operations (SecOps) tooling directly into the IAM layer — eliminating the need for a separate SIEM for most IAM-level threats.

### Key Highlights

- **Zero-trust internal routing** — internal service endpoints require a separate `x-internal-token` header; they are never reachable through the public API prefix.
- **Progressive security pipeline** — every event flows through: API → Redis stream → Risk Engine → Defense Worker → Neo4j graph, with full idempotency and dead-letter queue (DLQ) protection at each stage.
- **Multi-environment secrets management** — pluggable `SecretProvider` interface supports `.env` (development), Docker file secrets (`/run/secrets/*`), and a documented HashiCorp Vault stub.
- **Atomic risk scoring** — a Lua script executes risk updates atomically in Redis, preventing race conditions in multi-instance deployments.
- **Full Kubernetes deployment manifests** — with namespaces, network policies, RBAC, HPA, PVCs, secrets, and a kustomize overlay.
- **Rust-powered external attack simulator** — the `cloudshield-attacker` binary is a standalone, fully async Rust binary with isolated attack identities and 13 distinct attack modules.

---

## Features

### Authentication

- Local email/password registration with velocity limiting (max 5 registrations/IP/hour)
- Argon2id password hashing with configurable memory/time/parallelism cost factors
- Constant-time dummy hash verification on unknown email addresses (prevents user enumeration)
- Account lockout after configurable failed login attempts (all sessions revoked on lock)
- JWT access tokens (15-minute TTL) and refresh tokens (7-day TTL), both RS256-signed
- KID (Key ID)-based JWT header injection for seamless key rotation
- Multiple concurrent key pairs supported — old tokens remain valid during rotation window
- Short-lived temporary tokens (5-minute TTL) for MFA challenge gating
- Refresh token reuse detection (database-tracked `isUsed` flag + `refreshTokenHash`)
- Configurable maximum concurrent sessions per user
- Token version field (`tokenVersion`) on users for global session invalidation
- Session metadata tracked: user agent, IP, creation time, last used, MFA verification status
- CSRF double-submit cookie pattern — all state-mutating routes require `x-csrf-token` header
- Cookie flags: `HttpOnly`, `Secure`, `SameSite=Lax` (configurable to `SameSite=None` for cross-domain)

### Google OAuth 2.0

- Authorization code flow with PKCE-like state parameter CSRF protection
- State cookie validated before code exchange
- ID token accepted either via redirect query param or `x-google-id-token` header (mobile support)
- Automatic user provisioning for new OAuth users
- Configurable role assignment for OAuth users: `OAUTH_ADMIN_ENABLED`, `ADMIN_EMAILS` allowlist, `ADMIN_DOMAIN` with optional `ADMIN_DOMAIN_STRICT`
- OAuth-provisioned admin accounts enter a `PENDING_ADMIN` state (explicit promotion required)
- OAuth users without a password cannot disable MFA via password path (steered to TOTP)

### Multi-Factor Authentication (TOTP)

- TOTP secret generation via `speakeasy` with QR code delivery (`qrcode` library)
- Secrets encrypted at rest with AES-256-GCM before database storage
- Key-version tracking per user (`totpSecretKeyVersion`) for encryption key rotation
- Two-phase setup: `tempTotpSecret` stored first, promoted to `totpSecret` only after first successful verification
- 30-second time window tolerance (±1 window)
- MFA session flag (`mfaVerified`) tracked per session for ABAC policy gating
- Distributed MFA brute-force protection (5-attempt rate limit keyed per user via temp token, not IP)
- MFA disable requires re-authentication: either current TOTP code or account password
- Audit events emitted for MFA enable, disable, and failure

### Role-Based Access Control (RBAC)

- Four roles: `ADMIN`, `SECURITY_ANALYST`, `USER`, `PENDING_ADMIN`
- 22 atomic, named permissions (e.g., `users:list`, `audit:view`, `security:simulate`, `sensitive:delete`)
- Permissions stored in `Set` objects per role for O(1) lookup at request time
- `requirePermission()` middleware enforces permissions before any route handler executes
- RBAC grant/deny tracked per-role, per-permission, per-route via Prometheus counters (`iam_rbac_allowed_total`, `iam_rbac_denied_total`)
- Role-to-permission mapping is explicit (no inheritance chain) — ADMIN permissions are listed, not implied

### Attribute-Based Access Control (ABAC)

- Policy engine evaluates contextual conditions beyond role membership
- ADMIN access restricted to RFC 1918 + loopback IP ranges (network-level ABAC)
- `sensitive:modify` and `sensitive:delete` require TOTP enabled AND current session MFA-verified
- `USER` role scoped to own resources only (profile read/update, session revoke limited to `user.id === resource.id`)
- `SECURITY_ANALYST` policy: read-only across users, audit, metrics, security, graph, RBAC resources
- Policy failure emits `ABAC_DENIED` Prometheus counter label

### Session Management

- Full session CRUD: list all own sessions, get current session, revoke single session by ID, revoke all sessions
- Sessions stored in PostgreSQL with indexed `userId` foreign key
- Cascade delete: sessions deleted when user is deleted
- `lastUsedAt` timestamp updated on each authenticated request
- Sessions page in frontend shows active sessions with IP, user agent, and last active time

### Rate Limiting

- Global API limiter: 300 requests/15 min per user/IP composite key (Redis-backed)
- Auth limiter: 20 requests/15 min (applied to login, register, refresh)
- Per-user login limiter: 10 attempts/15 min keyed on email address (cross-IP brute-force protection)
- MFA limiter: 5 attempts/15 min keyed on temp token subject (falls back to IP)
- CSRF limiter: 30 requests/minute (exempt from global limiter to prevent bootstrap deadlock)
- Internal service limiter: 50 requests/15 min by IP
- All limiters use Redis store for distributed correctness across multiple API instances
- Rate limit hits tracked per type via Prometheus counter `iam_rate_limit_hits_total`

### Active Defense System

- IP strike tracking using Redis sliding window (5-minute TTL auto-decay)
- Ban triggered after 5 strikes within the window
- Progressive ban escalation: first ban = 10 min, second = 1 hour, third+ = 24 hours
- Ban metadata stored in Redis (`ban:meta:<ip>`) with strike count and escalation state
- Ban enforcement at Express middleware level — banned requests rejected before any route handler runs
- Safe IP allowlist: localhost, `::1`, `::ffff:127.0.0.1`, Docker internal CIDRs (172.16.0.0/12)
- Simulation mode bypass: 192.168.x.x and 10.x.x.x CIDRs allowlisted when `SIMULATION_MODE=true`
- Defense events emitted to `defense_events` Redis stream for reliable, async processing
- Defense events carry `agent_type: SYSTEM` to prevent circular risk amplification
- `ACTIVE_DEFENDER` feature flag — system degrades gracefully to per-request rejection when disabled
- Active bans tracked as Prometheus gauge (`iam_active_bans`)

### Risk Engine

- Lua script executes atomic multi-key risk updates in Redis (prevents race conditions)
- Severity weights: `CRITICAL=25`, `HIGH=15`, `MEDIUM=8`, `LOW=2`
- Configurable risk thresholds via environment: `RISK_THRESHOLD_LOW`, `_MEDIUM`, `_HIGH`
- Multi-entity scoring: risk computed independently for IP, user, session, and endpoint
- High-risk events trigger defense task push to `defense_events` stream
- Escalation path: risk score exceeds high threshold → `XADD` to defense stream → defense worker → `recordStrike`
- Risk score distribution tracked via Prometheus histogram `iam_risk_score_distribution`

### Event Pipeline (Redis Streams)

- All security events published to Redis stream via `logSecurityEvent()`
- `eventWorker.js` consumes events using `XREADGROUP` (consumer group, at-least-once delivery)
- Events carry: `event_priority` (ATTACK=1, DEFENSE=2), `event_sequence_index` (monotonic per correlation), `parent_event_id`
- Event deduplication via Redis `SET NX` on `dedup:<correlationId>:<eventSignature>` (30-second window)
- Atomic idempotency guard: `processed:<event_id>` key set before write; skipped if already exists
- `XAUTOCLAIM` reclaims PEL messages idle >30s (crash recovery)
- Dead-letter queue: after `MAX_RETRIES` delivery failures, event sent to `security_events_dlq` stream + `XACK`
- `defenseWorker.js` separately consumes `defense_events` stream with identical reliability guarantees
- Defense deduplication: `defense:dedup:<ip>:<slot>:<severity>` SET NX (10-minute window, prevents double-strike)
- Both workers expose their own Prometheus metrics HTTP server on separate ports (9091, 9092)

### Neo4j Graph Intelligence

- All security events ingested into Neo4j as a labeled property graph
- Node labels: `Event`, `IP`, `User`, `Session`, `AttackGroup`, `AttackType`, `Endpoint`, `DefenseAction`, `RiskBucket`
- Relationships: `TRIGGERED`, `ACTED`, `CONTAINS`, `GROUPS`, `OF_TYPE`, `TARGETED`, `NEXT`, `TRIGGERED_DEFENSE`, `APPLIED`, `IN_RISK_BUCKET`
- Single Cypher statement per event (no multi-query sessions)
- `MERGE` on unique constraints — full idempotency on re-ingestion
- `ON CREATE / ON MATCH` SET patterns for all node property updates
- FOREACH-guarded conditional writes (no OPTIONAL MATCH inside write units)
- Indexes: unique on `event_id`, `IP.address`, `User.user_id`, `User.user_email`, `Session.session_id`, `AttackGroup.correlation_id`, `AttackType.action`, `Endpoint.path`, `DefenseAction.defense_type`, `RiskBucket.level`; extra indexes on `Event.parent_event_id`, `Event.timestamp`, `Event.event_signature`, `Event.correlation_id`
- Graph query modes: `attack-defense`, `attack-chain`, `user-attack`, `recent`
- Graph filterable by severity, correlation ID, and result limit (max 100)

### Security Simulation (Server-Side)

- Admin-only attack simulation registry with named attack types
- Attack types: `BRUTE_FORCE`, `SESSION_HIJACK_CHAIN`, `CREDENTIAL_STUFFING`, `JWT_ALGORITHM_CONFUSION`, `PRIVILEGE_ESCALATION`, `DISTRIBUTED_MFA_BRUTE`, `TOKEN_REPLAY`, `IDOR_PROBE`, `CSRF_BYPASS`, `MASS_ASSIGNMENT`, `API_RATE_FLOOD`
- Simulated events use random private IPs (10.x.x.x range) and `agent_type: SIMULATED`
- Events routed through the same audit/risk/Neo4j pipeline as real events
- Attack simulation counter tracked via Prometheus (`iam_attack_simulations_total`)
- Simulation mode flag bypasses active defense banning for simulation IPs

### Audit Log

- PostgreSQL `AuditLog` table with unique `event_id` constraint (prevents duplicate inserts at DB level)
- Metadata stored as JSONB with GIN index for efficient querying
- Filterable audit log API: by action, status, severity, date range, IP
- Paginated responses with `cursor`-based navigation
- Internal-only debug endpoint: counts defense events by type
- Users can view their own audit events; ADMIN/ANALYST can view all

### Observability (Prometheus + Grafana)

- `prom-client` default process metrics (CPU, memory, event loop lag, GC)
- Custom counters, histograms, and gauges:
  - `iam_login_requests_total` (by status)
  - `iam_login_duration_seconds` (histogram)
  - `iam_account_locks_total` (by reason)
  - `iam_mfa_login_attempts_total` (by status)
  - `iam_mfa_failures_total`, `iam_distributed_mfa_lock_total`
  - `iam_jwt_verification_failures_total` (by reason)
  - `iam_jwt_tamper_detected_total`
  - `iam_rate_limit_hits_total` (by type)
  - `iam_session_security_events_total` (reuse, compromise, revocation)
  - `iam_authorization_failures_total` (by type: RBAC, ABAC, IDOR)
  - `iam_rbac_allowed_total`, `iam_rbac_denied_total` (by role, permission, route)
  - `iam_ip_bans_total`, `iam_strikes_recorded_total`, `iam_bans_triggered_total`
  - `iam_blocked_requests_total`, `iam_active_bans` (gauge)
  - `iam_http_requests_total`, `iam_http_response_duration_seconds`, `iam_http_error_rate_total`
  - `iam_security_events_ingested_total`, `iam_security_events_processed_total`
  - `iam_risk_score_computed_total`, `iam_risk_score_distribution`, `iam_high_risk_events_total`
  - `iam_neo4j_write_total`, `iam_neo4j_write_latency_ms`
  - `iam_events_processing_latency_ms`, `iam_stream_consumer_lag`
  - `iam_worker_alive` (gauge), `iam_redis_connection_status`, `iam_neo4j_connection_status`
  - `iam_attack_simulations_total`
- `/metrics` endpoint protected by `internalAuth` middleware (requires `x-internal-token` header)
- Three pre-built Grafana dashboards: IAM System Overview, IAM Security Analytics, IAM Defense Pipeline
- Grafana dashboards auto-provisioned via `provisioning/dashboards/` and `provisioning/datasources/`

### Frontend (React SPA)

- Pages: Login, Register, MFA Challenge, Dashboard, Profile, Sessions, Users (list), Admin Users (role management), Audit Log, Security Simulation, Graph View, OAuth Callback
- Route protection: `ProtectedRoute` (authentication gate), `RoleGuard` (permission gate)
- Global `auth:forbidden` event listener — permission errors from any API call redirect to `/forbidden`
- `AuthContext` manages access token in memory (not localStorage), handles silent refresh via HTTP-only cookie
- `RbacContext` exposes permission checks to any component via `usePermission()` hook
- `useMetrics()` hook polls system health endpoint
- Attack simulation UI groups attacks by category with step-by-step timeline rendering
- `AttackTimeline` component renders each simulation step with severity badges
- `GraphView` renders Neo4j data as interactive force-directed graph using `react-force-graph-2d`
- `GrafanaEmbed` component embeds Grafana dashboards via proxied embed URL (permission-gated)
- `ActivityFeed` component renders real-time recent audit events on dashboard
- `SystemStatus` component polls `/health` endpoint and displays uptime
- Tailwind CSS v4 for styling; Vite 8 for build tooling

### Rust Attack Simulation Engine (`cloudshield-attacker`)

- Standalone async Rust binary using `tokio` runtime and `reqwest` HTTP client
- 13 attack modules selectable via `ATTACK_MODE` environment variable (or `all`)
- Each attack module runs with an isolated identity (`atk-<name>@test.com`) to prevent interference between attacks
- Identity lifecycle: register → login → execute attack → report result
- Attack mode aliases support both human names (`brute_force`) and numeric codes (`atk06`)
- Attack modules:
  - `password_brute` — credential stuffing / brute-force login
  - `jwt_tamper` — algorithm confusion, signature stripping, claim manipulation
  - `session_reuse` — refresh token replay after logout
  - `session_invalidation` — concurrent session revocation race
  - `token_race` — concurrent refresh token race condition
  - `mfa_replay` — TOTP code replay within validity window (single IP)
  - `mfa_distributed` — distributed MFA brute-force across multiple IPs
  - `idor` — insecure direct object reference (accessing other users' resources)
  - `csrf` — cross-site request forgery simulation
  - `mass_assignment` — HTTP parameter pollution / mass assignment
  - `access_token_abuse` — access token used after session revocation
  - `rate_flood` — API rate limit exhaustion
- Graph event emission: attack results serialized to structured `GraphEvent` objects for Neo4j ingestion
- Built as a Docker container and deployable as a Kubernetes `Job` (see `k8s/attack-sim/`)

### Secrets Management

- Pluggable `SecretProvider` interface with three implementations:
  - `EnvProvider` — reads from process environment variables (local dev)
  - `DockerSecretsProvider` — reads from `/run/secrets/<name>` (Docker Compose / Swarm)
  - `VaultProvider` — documented stub for HashiCorp Vault (not yet implemented)
- `SECRET_PROVIDER` env var selects the active provider at startup
- `validate-secrets.js` script validates all required secrets are present and correctly formatted before startup

### Kubernetes Deployment

- Full `k8s/` manifests managed via `kustomize`
- Namespaces: `iam-system` and `iam-monitoring`
- Network policies: ingress/egress rules per service (backend, workers, databases, monitoring)
- RBAC: Kubernetes ServiceAccounts with least-privilege `Role`/`RoleBinding`
- HPA (Horizontal Pod Autoscaler) for backend deployment
- PersistentVolumeClaims for PostgreSQL, Redis, and Neo4j data
- Secrets: JWT keys, encryption keys, database URLs, Google OAuth credentials
- Separate worker deployment (`workers-deployment.yaml`) with both `eventWorker` and `defenseWorker` containers
- Kubernetes `Job` manifest for running the Rust attack simulator

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Backend runtime** | Node.js (ES Modules) |
| **Backend framework** | Express.js 4 |
| **Primary database** | PostgreSQL 16 (via Prisma ORM) |
| **Cache / Streams** | Redis 7 (ioredis client) |
| **Graph database** | Neo4j 5 (neo4j-driver) |
| **Password hashing** | Argon2id (argon2), bcryptjs (fallback) |
| **JWT** | jsonwebtoken (RS256, KID-based) |
| **MFA** | speakeasy (TOTP), qrcode (QR generation) |
| **Encryption** | Node.js `crypto` (AES-256-GCM) |
| **OAuth** | google-auth-library |
| **HTTP security** | helmet, hpp, cors, cookie-parser, compression |
| **Rate limiting** | express-rate-limit + rate-limit-redis |
| **Validation** | express-validator |
| **XSS sanitization** | xss |
| **Logging** | winston, morgan |
| **Metrics** | prom-client (Prometheus) |
| **Monitoring** | Prometheus, Grafana |
| **Frontend framework** | React 19 |
| **Frontend build** | Vite 8 |
| **Frontend routing** | react-router-dom v7 |
| **Frontend HTTP** | axios |
| **Frontend graph** | react-force-graph-2d |
| **Frontend CSS** | Tailwind CSS v4 |
| **Frontend date** | dayjs |
| **Frontend icons** | react-icons |
| **ORM** | Prisma 5 |
| **Attack simulator** | Rust (tokio, reqwest, serde, totp-rs, uuid) |
| **Containerization** | Docker, Docker Compose v2 |
| **Orchestration** | Kubernetes + kustomize |
| **Reverse proxy** | Nginx (Docker Compose) |
| **Dev tooling** | nodemon |

---

## Project Structure

```
cloud-iam-platform-main/
├── api/                              # Backend Node.js service
│   ├── src/
│   │   ├── app.js                    # Express app factory: middleware, routes, metrics
│   │   ├── server.js                 # HTTP server bootstrap, graceful shutdown
│   │   ├── metrics/
│   │   │   └── metrics.js            # All Prometheus metric definitions
│   │   ├── modules/
│   │   │   ├── admin/
│   │   │   │   ├── admin.controller.js   # Admin role management handlers
│   │   │   │   └── admin.routes.js       # /api/v1/admin routes
│   │   │   ├── analytics/
│   │   │   │   └── analytics.routes.js   # /api/v1/analytics (summary, internal demo)
│   │   │   ├── audit/
│   │   │   │   └── audit.routes.js       # /api/v1/audit (events, defense, debug)
│   │   │   ├── auth/
│   │   │   │   ├── auth.controller.js    # HTTP handlers: login, register, OAuth, sessions
│   │   │   │   ├── auth.routes.js        # /api/v1/auth routes
│   │   │   │   ├── auth.service.js       # Core auth logic, token issuance, session mgmt
│   │   │   │   ├── audit.service.js      # Security event logging, dedup, risk correlation
│   │   │   │   ├── googleAuth.service.js # Google OAuth token exchange
│   │   │   │   ├── mfa.controller.js     # MFA HTTP handlers
│   │   │   │   ├── mfa.routes.js         # /api/v1/mfa routes
│   │   │   │   ├── mfa.service.js        # TOTP setup, verify, disable logic
│   │   │   │   ├── policies.js           # ABAC policy definitions
│   │   │   │   └── policyEngine.js       # ABAC policy evaluator
│   │   │   ├── graph/
│   │   │   │   └── graph.routes.js       # /api/v1/graph (Neo4j query endpoints)
│   │   │   ├── metrics/
│   │   │   │   └── metrics.routes.js     # /api/v1/metrics (proxied Prometheus data)
│   │   │   ├── rbac/
│   │   │   │   └── rbac.routes.js        # /api/v1/rbac (role/permission inspection)
│   │   │   ├── security/
│   │   │   │   ├── security.controller.js # Attack simulation handlers
│   │   │   │   ├── security.routes.js    # /api/v1/security routes
│   │   │   │   └── security.service.js   # Attack registry and execution logic
│   │   │   └── user/
│   │   │       ├── user.controller.js    # User CRUD handlers
│   │   │       ├── user.routes.js        # /api/v1/users routes (+ internal router)
│   │   │       └── user.service.js       # User management business logic
│   │   └── shared/
│   │       ├── config/
│   │       │   ├── database.js           # Prisma client singleton
│   │       │   ├── index.js              # Centralized config (all env vars parsed here)
│   │       │   ├── redis.js              # ioredis client singleton
│   │       │   └── security.js          # Security constants (lock thresholds etc.)
│   │       ├── db/
│   │       │   └── neo4j.js              # Neo4j driver, schema init, mergeEventToGraph()
│   │       ├── middleware/
│   │       │   ├── activeDefender.js     # IP strike/ban enforcement middleware
│   │       │   ├── authenticate.js       # JWT verification, session validation
│   │       │   ├── authorizePolicy.js    # ABAC policy middleware
│   │       │   ├── authorizeRoles.js     # Role-based route guard
│   │       │   ├── correlationId.js      # Request correlation ID injection
│   │       │   ├── errorHandler.js       # Global error handler + 404 handler
│   │       │   ├── internalAuth.js       # x-internal-token service-to-service auth
│   │       │   ├── rateLimiter.js        # All rate limiter instances
│   │       │   ├── requireCsrf.js        # CSRF double-submit cookie validation
│   │       │   ├── requirePermission.js  # Permission check middleware
│   │       │   └── validate.js           # express-validator rule sets
│   │       ├── providers/
│   │       │   └── SecretProvider.js     # Env / Docker secrets / Vault providers
│   │       ├── rbac/
│   │       │   ├── permissions.js        # PERMISSIONS constants (22 permissions)
│   │       │   └── rolePermissions.js    # Role → permission Set mappings
│   │       └── utils/
│   │           ├── AppError.js           # Custom error class with code + status
│   │           ├── cipher.js             # AES-256-GCM encrypt/decrypt
│   │           ├── clientInfo.js         # IP + user agent extraction (trust proxy)
│   │           ├── ipClassifier.js       # Classifies IPs (public, private, loopback)
│   │           ├── jwt.js                # Token generation and verification (RS256, KID)
│   │           ├── logger.js             # winston logger instance
│   │           ├── password.js           # Argon2id hash/verify + dummy verify
│   │           └── response.js           # Standardized successResponse/errorResponse
│   ├── workers/
│   │   ├── eventWorker.js               # Redis stream consumer: risk scoring, Neo4j write
│   │   ├── defenseWorker.js             # Defense stream consumer: strike/ban execution
│   │   ├── riskEngine.js                # Lua-based atomic risk scoring engine
│   │   └── lua/
│   │       └── atomicRiskUpdate.lua     # Atomic Lua script for risk score updates
│   ├── prisma/
│   │   ├── schema.prisma                # Data models: User, Session, AuditLog, Role enum
│   │   ├── seed.js                      # Seeds admin, analyst, user, and MFA test accounts
│   │   └── migrations/                  # Versioned SQL migrations (9 migrations)
│   ├── scripts/
│   │   ├── generate-keys.js             # RSA-2048 key pair generator with KID support
│   │   ├── validate-secrets.js          # Pre-startup secrets validation
│   │   ├── ingestAttackEvents.js        # Backfills attack events into Neo4j
│   │   └── neo4j_ingest.js             # Bulk Neo4j event ingestion script
│   ├── grafana/
│   │   ├── dashboards/                  # Three pre-built Grafana dashboard JSONs
│   │   └── provisioning/               # Auto-provisioning config for dashboards + datasources
│   ├── prometheus.yml                   # Prometheus scrape config
│   ├── docker-compose.yml              # Full stack Docker Compose (14 services)
│   ├── Dockerfile                       # Multi-stage Node.js image
│   └── .env.example                    # All environment variables documented
│
├── frontend/                            # React SPA
│   ├── src/
│   │   ├── main.jsx                     # React entry point
│   │   ├── routes/
│   │   │   └── AppRouter.jsx            # BrowserRouter + all routes + guards
│   │   ├── pages/
│   │   │   ├── Login.jsx                # Email/password + Google OAuth login
│   │   │   ├── Register.jsx             # User registration form
│   │   │   ├── MfaPage.jsx              # TOTP code entry during login
│   │   │   ├── Dashboard.jsx            # Analytics summary + activity feed
│   │   │   ├── Profile.jsx              # Profile view/edit + MFA management
│   │   │   ├── Sessions.jsx             # Session list + revocation
│   │   │   ├── Users.jsx                # User list (ADMIN/ANALYST)
│   │   │   ├── AdminUsers.jsx           # Role promotion/demotion (ADMIN)
│   │   │   ├── Audit.jsx                # Filterable audit log viewer
│   │   │   ├── SecuritySimulation.jsx   # Attack simulation launcher + timeline
│   │   │   ├── GraphPage.jsx            # Neo4j graph visualization
│   │   │   └── AuthCallback.jsx         # Google OAuth redirect handler
│   │   ├── components/
│   │   │   ├── ActivityFeed.jsx         # Recent audit events widget
│   │   │   ├── AttackTimeline.jsx       # Simulation step-by-step timeline
│   │   │   ├── GrafanaEmbed.jsx         # Grafana dashboard iframe embed
│   │   │   ├── GraphView.jsx            # react-force-graph-2d wrapper
│   │   │   ├── Navbar.jsx               # Navigation + auth state
│   │   │   ├── PasswordInput.jsx        # Password field with show/hide toggle
│   │   │   ├── ProtectedRoute.jsx       # Auth gate (redirects to /login)
│   │   │   ├── RoleGuard.jsx            # Permission gate (redirects to /forbidden)
│   │   │   └── SimulationPanel.jsx      # Attack selection and launch panel
│   │   ├── context/
│   │   │   ├── AuthContext.jsx          # Auth state, token refresh, login/logout
│   │   │   ├── RbacContext.jsx          # Permission resolution from auth state
│   │   │   ├── auth-context.js          # Context export shim
│   │   │   └── rbac-context.js          # Context export shim
│   │   ├── hooks/
│   │   │   ├── useAuth.js               # Consumes AuthContext
│   │   │   ├── useMetrics.js            # Polls system metrics endpoint
│   │   │   └── usePermission.js         # Per-permission boolean check
│   │   └── utils/
│   │       └── attackExplanations.js    # Human-readable attack type explanations
│   └── vite.config.js                   # Vite config with React plugin
│
├── simulation-engine/
│   └── cloudshield-attacker/           # Rust external attack simulator
│       ├── src/
│       │   ├── main.rs                  # Entry point, attack orchestration, identity mgmt
│       │   ├── client.rs                # Typed HTTP API client (register, login, attack calls)
│       │   ├── event.rs                 # GraphEvent struct for Neo4j output
│       │   └── attacks/
│       │       ├── mod.rs               # Attack module registry
│       │       ├── password_brute.rs    # Brute-force / credential stuffing
│       │       ├── jwt_tamper.rs        # JWT algorithm confusion + tampering
│       │       ├── session_reuse.rs     # Refresh token replay
│       │       ├── session_invalidation.rs # Concurrent session revocation race
│       │       ├── token_race.rs        # Refresh token race condition
│       │       ├── mfa_replay.rs        # TOTP replay (single IP)
│       │       ├── mfa_distributed.rs   # Distributed MFA brute-force
│       │       ├── idor.rs              # Insecure direct object reference
│       │       ├── csrf.rs              # CSRF bypass simulation
│       │       ├── mass_assignment.rs   # HTTP parameter pollution
│       │       ├── access_token_abuse.rs # Post-revocation token use
│       │       └── rate_flood.rs        # API rate limit exhaustion
│       ├── Cargo.toml                   # Rust dependencies
│       └── Dockerfile                   # Rust builder image
│
└── k8s/                                 # Kubernetes manifests
    ├── kustomization.yaml               # kustomize overlay (ordered resource list)
    ├── namespaces/namespaces.yaml       # iam-system, iam-monitoring namespaces
    ├── rbac/rbac.yaml                   # K8s ServiceAccounts, Roles, RoleBindings
    ├── network-policies/network-policies.yaml # Ingress/egress rules per service
    ├── secrets/                         # JWT key secrets, app secrets templates
    ├── storage/pvcs.yaml                # PersistentVolumeClaims
    ├── backend/
    │   ├── configmap.yaml               # Non-secret environment config
    │   ├── backend-deployment.yaml      # API server Deployment + Service
    │   ├── workers-deployment.yaml      # eventWorker + defenseWorker Deployment
    │   └── hpa.yaml                     # HorizontalPodAutoscaler for backend
    ├── database/postgres.yaml           # PostgreSQL StatefulSet + Service
    ├── redis/redis.yaml                 # Redis Deployment + Service
    ├── neo4j/neo4j.yaml                 # Neo4j Deployment + Service
    ├── monitoring/
    │   ├── prometheus.yaml              # Prometheus Deployment + ServiceMonitor
    │   └── grafana.yaml                 # Grafana Deployment + Service
    └── attack-sim/attack-sim-job.yaml   # Kubernetes Job for Rust attack simulator
```

---

## Installation

### Prerequisites

- Node.js >= 20.x
- npm >= 10.x
- Docker and Docker Compose v2
- Rust toolchain (for attack simulator only; optional)
- PostgreSQL 16, Redis 7, Neo4j 5 (or use the provided Docker Compose)

### 1. Clone the Repository

```bash
git clone <repository-url>
cd cloud-iam-platform-main
```

### 2. Generate RSA Key Pairs

JWT signing requires RSA-2048 key pairs. Run the key generator:

```bash
cd api
node scripts/generate-keys.js key1 key2
```

This creates:
```
api/keys/
  key1/private.pem
  key1/public.pem
  key2/private.pem
  key2/public.pem
```

### 3. Configure Environment Variables

```bash
cp api/.env.example api/.env
```

Edit `api/.env` with your values (see [Configuration](#configuration) section for all variables).

At minimum for local development, set:
```env
SECRET_PROVIDER=env
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/authdb
REDIS_URL=redis://localhost:6379
NEO4J_URL=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=yourpassword
JWT_ACTIVE_KID=key1
JWT_KIDS=key1,key2
JWT_KEY_KEY1_PRIVATE=<content of keys/key1/private.pem with \n for newlines>
JWT_KEY_KEY1_PUBLIC=<content of keys/key1/public.pem with \n for newlines>
ENCRYPTION_KEY_V1=<64 hex characters>
ACTIVE_KEY_VERSION=1
INTERNAL_SERVICE_TOKEN=<32+ byte random hex>
```

Validate your secrets before starting:
```bash
node scripts/validate-secrets.js
```

### 4. Run with Docker Compose (Recommended)

Docker Compose manages all 14 services. First, create the required secrets files:

```bash
mkdir -p api/secrets api/keys/key1 api/keys/key2

# Write secret files (Docker reads these at runtime)
echo "postgresql://postgres:postgres@postgres:5432/authdb" > api/secrets/DATABASE_URL
echo "redis://redis:6379" > api/secrets/REDIS_URL
echo "your_google_client_id" > api/secrets/GOOGLE_CLIENT_ID
echo "your_google_client_secret" > api/secrets/GOOGLE_CLIENT_SECRET
echo "$(openssl rand -hex 32)" > api/secrets/INTERNAL_SERVICE_TOKEN
echo "yourneo4jpassword" > api/secrets/NEO4J_PASSWORD
openssl rand -hex 32 > api/keys/encryption_v1.key

# Copy generated JWT keys
cp api/keys/key1/private.pem api/keys/key1/
cp api/keys/key1/public.pem api/keys/key1/
cp api/keys/key2/private.pem api/keys/key2/
cp api/keys/key2/public.pem api/keys/key2/
```

Then start the stack:

```bash
cd api
docker compose up --build -d
```

### 5. Run Database Migrations and Seed

```bash
# If using Docker Compose, the migrate service runs automatically.
# For manual execution:
docker exec auth_api npm run db:migrate
docker exec auth_api npm run db:seed
```

The seed creates four default accounts (see [Usage](#usage) for credentials).

### 6. Install and Run Frontend (Local Development)

```bash
cd frontend
npm install
npm run dev
```

The frontend starts on `http://localhost:5173`.

### 7. Local Backend Development (Without Docker)

```bash
cd api
npm install
npm run db:migrate
npm run db:seed
npm run dev          # API server on port 3000
npm run worker       # Event worker (separate terminal)
npm run worker:defense  # Defense worker (separate terminal)
```

---

## Usage

### Default Seed Accounts

| Role | Email | Password | MFA |
|---|---|---|---|
| `ADMIN` | `admin@example.com` | From `SEED_ADMIN_PASSWORD` env | Enabled (TOTP) |
| `SECURITY_ANALYST` | `analyst@example.com` | From `SEED_ANALYST_PASSWORD` env | Disabled |
| `USER` | `user@example.com` | From `SEED_USER_PASSWORD` env | Disabled |
| `ADMIN` (MFA test) | From `MFA_TARGET_EMAIL` env | From `MFA_TARGET_PASSWORD` env | Enabled (TOTP) |

When seeding in non-production mode, the TOTP manual setup key and QR URI are printed to the console.

### Logging In

```bash
# Get CSRF token first (required for all state-mutating requests)
curl -c cookies.txt http://localhost:3000/api/v1/auth/csrf

# Login
curl -b cookies.txt -c cookies.txt \
  -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -H "x-csrf-token: <csrf_token_from_above>" \
  -d '{"email":"admin@example.com","password":"yourpassword"}'
```

If MFA is enabled, the response returns `{ status: "MFA_REQUIRED", tempToken: "..." }`. Submit the TOTP code:

```bash
curl -b cookies.txt -c cookies.txt \
  -X POST http://localhost:3000/api/v1/auth/mfa/validate-login \
  -H "Content-Type: application/json" \
  -d '{"tempToken":"<temp_token>","code":"123456"}'
```

### Running Attack Simulations (Admin only)

Via the frontend at `/simulation`, or via the API:

```bash
# Get available attack types
curl -H "Authorization: Bearer <access_token>" \
  http://localhost:3000/api/v1/security/attacks

# Trigger an attack simulation
curl -X POST \
  -H "Authorization: Bearer <access_token>" \
  -H "x-csrf-token: <csrf_token>" \
  -H "Content-Type: application/json" \
  http://localhost:3000/api/v1/security/simulate \
  -d '{"type":"BRUTE_FORCE"}'
```

### Running the Rust Attack Simulator

```bash
cd simulation-engine/cloudshield-attacker

# Build
cargo build --release

# Run all attacks
API_BASE_URL=http://localhost:3000 \
ATTACK_MODE=all \
SIMULATION_MODE=true \
  ./target/release/cloudshield-attacker

# Run a specific attack
ATTACK_MODE=jwt_tamper ./target/release/cloudshield-attacker

# Via Docker
docker build -t cloudshield-attacker .
docker run --network host \
  -e API_BASE_URL=http://localhost:3000 \
  -e SIMULATION_MODE=true \
  cloudshield-attacker
```

### Viewing the Graph

Navigate to `/graph` in the frontend (requires `metrics:view` permission). Select query type:
- `attack-defense` — shows attack events linked to triggered defense actions
- `attack-chain` — shows event-to-event `NEXT` chains within a correlation
- `user-attack` — shows users/IPs and their associated attack events
- `recent` — latest events

Filter by severity or paste a correlation ID for deep investigation.

### Accessing Monitoring

- **Prometheus**: `http://localhost:9090`
- **Grafana**: `http://localhost:3001` (default admin/admin)
- **Neo4j Browser**: `http://localhost:7474`

---

## Configuration

All configuration is read from a single `api/src/shared/config/index.js` module and sourced from environment variables (or Docker secrets when `SECRET_PROVIDER=docker-secrets`).

| Variable | Description | Default |
|---|---|---|
| `NODE_ENV` | Environment (`development`/`production`/`test`) | `development` |
| `PORT` | API server port | `3000` |
| `WORKER_METRICS_PORT` | Event worker Prometheus port | `9091` |
| `DEFENSE_WORKER_METRICS_PORT` | Defense worker Prometheus port | `9092` |
| `LOG_LEVEL` | Winston log level | `debug` |
| `CORS_ORIGIN` | Comma-separated allowed origins | `http://localhost:5173,...` |
| `SECRET_PROVIDER` | `env` or `docker-secrets` | `env` |
| `DATABASE_URL` | PostgreSQL connection string | — |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379` |
| `NEO4J_URL` | Neo4j Bolt URL | `bolt://localhost:7687` |
| `NEO4J_USER` | Neo4j username | `neo4j` |
| `NEO4J_PASSWORD` | Neo4j password | — |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | — |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret | — |
| `INTERNAL_SERVICE_TOKEN` | Token for service-to-service auth | — |
| `ENCRYPTION_KEY_V1` | 64-char hex AES-256 key (version 1) | — |
| `ACTIVE_KEY_VERSION` | Active encryption key version number | `1` |
| `JWT_ACTIVE_KID` | Active JWT signing key ID | `key1` |
| `JWT_KIDS` | Comma-separated list of all KIDs | `key1,key2` |
| `JWT_KEY_<KID>_PRIVATE` | PEM private key for KID (literal `\n`) | — |
| `JWT_KEY_<KID>_PUBLIC` | PEM public key for KID (literal `\n`) | — |
| `JWT_PRIVATE_KEY` | Legacy single private key (fallback) | — |
| `JWT_PUBLIC_KEY` | Legacy single public key (fallback) | — |
| `RISK_THRESHOLD_LOW` | Risk score: low severity threshold | `30` |
| `RISK_THRESHOLD_MEDIUM` | Risk score: medium severity threshold | `60` |
| `RISK_THRESHOLD_HIGH` | Risk score: high severity threshold | `85` |
| `ACTIVE_DEFENDER` | Enable adaptive IP banning (`true`/`false`) | `true` |
| `SIMULATION_MODE` | Bypass active defense for simulation IPs | `false` |
| `OAUTH_ADMIN_ENABLED` | Allow OAuth role elevation to ADMIN | `false` |
| `ADMIN_EMAILS` | Comma-separated emails that receive ADMIN on OAuth provision | — |
| `ADMIN_DOMAIN` | Email domain that receives ADMIN on OAuth provision | — |
| `ADMIN_DOMAIN_STRICT` | Require email verification for domain-based admin | `false` |
| `GRAFANA_URL` | Internal Grafana URL for embed proxy | `http://localhost:3001` |
| `SEED_ADMIN_PASSWORD` | Admin seed account password | — |
| `SEED_ANALYST_PASSWORD` | Analyst seed account password | — |
| `SEED_USER_PASSWORD` | User seed account password | — |
| `MFA_TARGET_EMAIL` | Email for the MFA attack test account | — |
| `MFA_TARGET_PASSWORD` | Password for the MFA attack test account | — |

---

## API Documentation

All endpoints are prefixed with `/api/v1`. Responses use the envelope format:
```json
{ "success": true, "message": "...", "data": { ... } }
```

### Authentication — `/api/v1/auth`

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/csrf` | None | Returns CSRF token (set as cookie + response body) |
| `POST` | `/register` | None | Create new user account |
| `POST` | `/login` | None | Authenticate with email/password |
| `POST` | `/mfa/validate-login` | temp token | Complete MFA challenge after login |
| `GET` | `/google` | None | Initiate Google OAuth flow (redirect) |
| `GET` | `/google/callback` | None | Google OAuth redirect handler |
| `POST` | `/refresh` | Cookie | Rotate access + refresh tokens |
| `POST` | `/logout` | JWT | Revoke current session |
| `GET` | `/profile` | JWT | Get authenticated user's profile |
| `PATCH` | `/profile` | JWT | Update authenticated user's profile |
| `GET` | `/sessions` | JWT | List all own active sessions |
| `GET` | `/sessions/current` | JWT | Get current session details |
| `DELETE` | `/sessions/:id` | JWT | Revoke a specific session |
| `DELETE` | `/sessions` | JWT | Revoke all own sessions |

**Register Request:**
```json
POST /api/v1/auth/register
{ "name": "Alice", "email": "alice@example.com", "password": "StrongPass123!" }
```

**Login Response (MFA required):**
```json
{ "success": true, "data": { "status": "MFA_REQUIRED", "tempToken": "<jwt>" } }
```

**Login Response (no MFA):**
```json
{
  "success": true,
  "data": {
    "user": { "id": "uuid", "email": "...", "role": "USER" },
    "accessToken": "<jwt>"
  }
}
```

### MFA — `/api/v1/mfa`

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/setup` | JWT | Generate TOTP secret and QR code |
| `POST` | `/verify` | JWT | Confirm TOTP code to enable MFA |
| `POST` | `/disable` | JWT | Disable MFA (requires TOTP code or password) |
| `GET` | `/status` | JWT | Check if MFA is enabled for current user |

### Users — `/api/v1/users`

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/` | `users:list` | List all users (ADMIN/ANALYST) |
| `GET` | `/:id` | `users:read` | Get user by ID |
| `PATCH` | `/:id/role` | `users:update_role` | Change user role (ADMIN only) |
| `DELETE` | `/:id` | `users:delete` | Delete user (ADMIN only) |

### Analytics — `/api/v1/analytics`

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/summary` | `analytics:view` | User counts and role breakdown |
| `GET` | `/internal-demo/:userId` | `analytics:internal_demo` | Internal demo data via service call |

### Audit — `/api/v1/audit`

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/events` | JWT + `audit:view` | Paginated, filterable security events |
| `GET` | `/events/defense` | `x-internal-token` | Defense events only (internal service use) |
| `GET` | `/debug/counts` | `x-internal-token` | Diagnostic event counts by type |

**Audit Query Parameters:**
- `action` — filter by action name (e.g., `LOGIN_FAILED`)
- `status` — `SUCCESS` or `FAILURE`
- `severity` — `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- `ip` — filter by source IP
- `from`, `to` — ISO 8601 date range
- `cursor` — pagination cursor
- `limit` — results per page (default 20, max 100)

### Security Simulation — `/api/v1/security`

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/attacks` | `security:view` | List all available attack types |
| `POST` | `/simulate` | `security:simulate` | Trigger an attack simulation |
| `GET` | `/status` | `security:view` | Active defense and ban status |

**Simulate Request:**
```json
POST /api/v1/security/simulate
{ "type": "BRUTE_FORCE" }
```

### Graph — `/api/v1/graph`

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/` | `security:view` | Query Neo4j graph (attack-defense, chain, user-attack, recent) |
| `GET` | `/attack-paths` | `security:view` | Alias for root graph endpoint |

**Graph Query Parameters:**
- `type` — `attack-defense` (default), `attack-chain`, `user-attack`, `recent`
- `severity` — filter by event severity
- `correlation_id` — filter by correlation chain
- `limit` — max results (default 50, max 100)

### RBAC — `/api/v1/rbac`

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/roles` | JWT | List all roles and their permissions |
| `GET` | `/my-permissions` | JWT | Get permissions for authenticated user's role |

### Admin — `/api/v1/admin`

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/users` | `users:list` | Admin user list with role details |
| `PATCH` | `/users/:id/role` | `users:update_role` | Promote/demote user role |

### Internal Routes — `/api/internal`

Protected by `x-internal-token` header. Not reachable from the public API prefix.

| Method | Path | Description |
|---|---|---|
| `GET` | `/users/:id` | Fetch user by ID (service-to-service) |

### Health and Metrics

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/health` | None | Service health check + uptime |
| `GET` | `/metrics` | `x-internal-token` | Prometheus metrics endpoint |
| `GET` | `/api/v1/dashboard/embed-url` | JWT + `metrics:view` | Grafana embed URL proxy |

---

## Key Components / Architecture

### Request Lifecycle

```
Client Request
    ↓
Nginx (reverse proxy)
    ↓
Express App
    ├── correlationId middleware (UUID injected)
    ├── helmet (security headers)
    ├── CORS validation
    ├── body parsing (10KB limit)
    ├── HPP (HTTP parameter pollution guard)
    ├── activeDefenseMiddleware (ban check — BEFORE rate limiter)
    ├── apiLimiter (Redis-backed rate limit)
    ├── Prometheus request tracking
    ├── Route handler:
    │     authenticate → requirePermission → authorizePolicy → handler
    └── errorHandler
```

### Security Event Pipeline

```
Any security event (login fail, ban, IDOR, etc.)
    ↓
logSecurityEvent() — audit.service.js
    ├── PostgreSQL AuditLog INSERT (with event deduplication)
    └── Redis XADD → security_events stream
              ↓
         eventWorker.js (XREADGROUP consumer)
              ├── Idempotency check (SET NX on processed:<event_id>)
              ├── RiskEngine.score() — Lua atomic update in Redis
              │     ├── Risk score ≥ HIGH threshold?
              │     │     └── XADD → defense_events stream
              │     └── Risk metrics to Prometheus
              └── mergeEventToGraph() → Neo4j
                        ↓
                   defenseWorker.js (XREADGROUP consumer)
                        ├── Dedup check (defense:dedup: SET NX)
                        └── recordStrike() → activeDefender.js
                              └── Ban IP if strikes ≥ 5
```

### JWT Flow

```
Login success
    ↓
generateAccessToken()  → RS256, 15min, KID in header, jti claim
generateRefreshToken() → RS256, 7d, KID in header, stored hash in DB

Token refresh:
    verifyRefreshToken() → extract KID from header → load public key → verify
    isUsed check → reuse detection (session compromise signal)
    Rotate: new access + refresh tokens, mark old as isUsed

Authentication middleware:
    Extract Bearer token → verify RS256 with correct KID's public key
    Load session from DB → check revoked, expiry, tokenVersion match
    Attach req.user + req.session
```

### Active Defense State Machine

```
Incoming request from IP X
    ↓
isAllowlisted(IP)? → skip all checks
    ↓ no
isBanned(IP)? → 403 BLOCKED_BANNED_IP
    ↓ no
pass through to routes
    ↓
Attack event detected in risk engine
    ↓
recordStrike(IP, correlationId) → INCR strike:ip:<IP>, EXPIRE 300s
    ↓
strikes ≥ STRIKE_THRESHOLD (5)?
    ↓ yes
banIp(IP) → read ban count → escalate duration (600s / 3600s / 86400s)
           → SET ban:ip:<IP> EX <duration>
           → SET ban:meta:<IP> (count, duration, timestamp)
           → emit IP_BANNED event to security stream
           → Prometheus counter increment
```

---

## Scripts / Commands

### API Backend

```bash
# Development server (hot reload)
npm run dev

# Production server
npm start

# Start event worker
npm run worker

# Start defense worker
npm run worker:defense

# Development event worker (hot reload)
npm run worker:dev

# Development defense worker (hot reload)
npm run worker:defense:dev

# Database migrations
npm run db:migrate

# Regenerate Prisma client after schema change
npm run db:generate

# Prisma Studio (database GUI)
npm run db:studio

# Seed database with default users
npm run db:seed

# Generate RSA key pairs (key1 and key2)
node scripts/generate-keys.js key1 key2

# Validate all secrets are present and correctly formatted
node scripts/validate-secrets.js

# Backfill attack events into Neo4j
npm run ingest:attack

# Direct Neo4j ingestion
node scripts/neo4j_ingest.js
```

### Frontend

```bash
# Development server (port 5173)
npm run dev

# Production build
npm run build

# Preview production build
npm run preview

# Lint
npm run lint
```

### Docker Compose

```bash
# Start all services
docker compose up -d

# Start with rebuild
docker compose up --build -d

# View logs
docker compose logs -f api
docker compose logs -f worker
docker compose logs -f defense_worker

# Stop all services
docker compose down

# Stop and remove volumes (full reset)
docker compose down -v
```

### Kubernetes

```bash
# Apply all resources (kustomize)
kubectl apply -k k8s/

# Delete all resources
kubectl delete -k k8s/

# Run attack simulator job
kubectl apply -f k8s/attack-sim/attack-sim-job.yaml

# Check worker pod status
kubectl get pods -n iam-system

# View API logs
kubectl logs -n iam-system -l app=backend -f

# Scale backend manually
kubectl scale deployment backend -n iam-system --replicas=3
```

### Rust Attack Simulator

```bash
# Build
cargo build --release

# Run all attacks
ATTACK_MODE=all API_BASE_URL=http://localhost:3000 ./target/release/cloudshield-attacker

# Run specific attack (by name or code)
ATTACK_MODE=jwt_tamper ./target/release/cloudshield-attacker
ATTACK_MODE=atk04 ./target/release/cloudshield-attacker

# Docker build and run
docker build -t cloudshield-attacker .
docker run -e API_BASE_URL=http://api:3000 -e SIMULATION_MODE=true cloudshield-attacker
```

---

## Dependencies

### Backend (`api/package.json`)

| Package | Purpose |
|---|---|
| `@prisma/client` / `prisma` | PostgreSQL ORM with type-safe queries and migrations |
| `argon2` | Argon2id password hashing (primary hasher) |
| `bcryptjs` | bcrypt hashing (legacy fallback) |
| `express` | HTTP framework |
| `helmet` | Security HTTP headers (CSP, HSTS, etc.) |
| `cors` | Cross-origin resource sharing configuration |
| `hpp` | HTTP parameter pollution prevention |
| `cookie-parser` | Cookie parsing for CSRF and session cookies |
| `compression` | Gzip response compression |
| `express-rate-limit` | Request rate limiting |
| `rate-limit-redis` | Redis backing store for distributed rate limits |
| `express-validator` | Input validation and sanitization |
| `jsonwebtoken` | JWT generation and verification (RS256) |
| `google-auth-library` | Google OAuth token verification |
| `speakeasy` | TOTP secret generation and verification |
| `qrcode` | QR code image generation for MFA setup |
| `ioredis` | Redis client (streams, rate limiting, caching) |
| `neo4j-driver` | Neo4j graph database client |
| `prom-client` | Prometheus metrics exposition |
| `winston` | Structured JSON logging |
| `morgan` | HTTP request access logging |
| `axios` | HTTP client for internal service calls |
| `dotenv` | `.env` file loading for local development |
| `xss` | XSS sanitization for user input |
| `nodemon` | Development hot-reload (devDependency) |

### Frontend (`frontend/package.json`)

| Package | Purpose |
|---|---|
| `react` / `react-dom` | UI framework (v19) |
| `react-router-dom` | Client-side routing (v7) |
| `axios` | HTTP client for API calls |
| `react-force-graph-2d` | 2D force-directed graph rendering for Neo4j data |
| `react-icons` | Icon library |
| `dayjs` | Lightweight date formatting |
| `tailwindcss` | Utility-first CSS framework (v4) |
| `vite` | Frontend build tool (v8) |
| `@vitejs/plugin-react` | Vite React plugin |

### Rust Simulator (`Cargo.toml`)

| Crate | Purpose |
|---|---|
| `tokio` | Async runtime |
| `reqwest` | Async HTTP client (rustls TLS) |
| `serde` / `serde_json` | JSON serialization |
| `chrono` | Date/time handling |
| `totp-rs` | TOTP code generation for MFA attack modules |
| `uuid` | UUID generation for attack identities |
| `data-encoding` | Base32/Base64 encoding for TOTP secrets |

---

## Known Issues / Limitations

- **No test suite** — both the API and frontend `package.json` scripts have `test` commands that echo placeholder messages. No unit or integration tests are implemented.

- **ESLint not configured** — the `lint` script in `api/package.json` echoes a placeholder. The frontend has ESLint configured but it may not be enforced in CI.

- **HashiCorp Vault provider is a stub** — `SecretProvider.js` documents a `VaultProvider` class but it is not implemented. Any production deployment requiring Vault must implement this provider.

- **`PENDING_ADMIN` role requires manual promotion** — OAuth-provisioned users that match admin criteria are placed in `PENDING_ADMIN` status. There is no automatic or frontend-driven promotion flow documented; promotion must be done via the admin role management API.

- **No email verification for local accounts** — the registration flow does not send a verification email. Email addresses are accepted as-is.

- **Neo4j ingestion is best-effort** — if Neo4j is unavailable, the event worker logs the failure and continues. Events that fail Neo4j ingestion are not retried and are not sent to a DLQ (unlike the defense events stream which has full retry/DLQ support).

- **Single Grafana organization** — the embed URL proxy hardcodes `orgId=1`. Multi-org Grafana deployments would require changes to the embed proxy logic.

- **TOTP window is ±1 (90-second total tolerance)** — this is intentionally lenient to handle clock skew, but may allow very brief replay in edge cases. Consider tightening to ±0 in high-security environments.

- **`ADMIN_DOMAIN` email verification is not enforced at login** — the domain-based admin check only runs at OAuth provisioning time. A user whose domain changes after provisioning keeps their role.

- **Worker metrics ports (9091, 9092) are not authenticated** — the event worker and defense worker expose their Prometheus `/metrics` endpoints on separate HTTP servers without `internalAuth`. These ports should not be exposed outside the internal network.

- **`test.txt` in project root** — a `test.txt` file exists at the root of the repository with no apparent purpose. It appears to be a development artifact.

---

## Future Improvements

- **Automated test suite** — add Jest unit tests for services (auth, risk engine, RBAC) and supertest integration tests for API routes. Add Rust `#[cfg(test)]` modules for attack modules.

- **HashiCorp Vault integration** — implement the `VaultProvider` stub to support enterprise secrets management.

- **Email verification and password reset** — add email delivery (SMTP or SES) for account verification and self-service password reset flows.

- **WebSocket-based real-time feed** — replace the polling-based activity feed with a WebSocket or Server-Sent Events stream pushed directly from the event worker.

- **PENDING_ADMIN approval workflow** — build an admin UI flow for reviewing and approving `PENDING_ADMIN` accounts with an audit trail.

- **Refresh token family tracking** — extend refresh token reuse detection to track entire token families (rotation chain), allowing compromise detection when any token in a chain is replayed.

- **IP geolocation enrichment** — enrich security events with country/ASN data for the Neo4j graph (useful for geographic attack pattern analysis).

- **OpenTelemetry traces** — add distributed tracing (correlation ID is already propagated, making this straightforward to layer in).

- **Role hierarchy** — introduce explicit role inheritance (e.g., `ADMIN` implies all `SECURITY_ANALYST` permissions) to reduce duplication in `rolePermissions.js`.

- **API versioning** — introduce `/api/v2` with backward-compatible breaking changes as the platform evolves.

- **Frontend E2E tests** — add Playwright or Cypress tests for the critical authentication and simulation flows.

---

## License

No `LICENSE` file was detected in the repository.

> **Assumption:** Based on the project's security-research and internal tooling nature, it is likely intended for internal or proprietary use. It is recommended to add an appropriate license — either a permissive license (MIT, Apache 2.0) if open-sourcing, or a proprietary license notice if this is internal software.
