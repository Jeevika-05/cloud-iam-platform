use crate::client::{ApiClient, HttpResult};
use serde::Serialize;
use serde_json::Value;

// ── Report structures ────────────────────────────

#[derive(Serialize)]
pub struct IdorReport {
    pub attack: String,
    pub timestamp: String,
    pub attacker_email: String,
    pub victim_email: String,
    pub attacker_id: String,
    pub victim_id: String,
    pub probes: Vec<IdorProbe>,
    pub verdict: String,
}

#[derive(Serialize)]
pub struct IdorProbe {
    pub name: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub response_code: String,
    pub exposed_data: bool,
    pub detail: String,
}

// ── Attack entry point ───────────────────────────

pub async fn run(
    client: &ApiClient,
    base_email: &str,
    password: &str,
) -> Result<IdorReport, String> {

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 1 — Setup: Register & login two users
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    let attacker_email = format!("idor-attacker-{}", base_email);
    let victim_email = format!("idor-victim-{}", base_email);

    println!("[IDOR] Phase 1: Setting up attacker + victim accounts");
    println!("[IDOR]   Attacker: {}", attacker_email);
    println!("[IDOR]   Victim  : {}", victim_email);

    // Register both (ignore 409 duplicate)
    match client.register(&attacker_email, password, "IDOR-Attacker").await {
        Ok(()) => println!("[IDOR]   Attacker registered"),
        Err(e) => println!("[IDOR]   Attacker registration: {}", e),
    }
    match client.register(&victim_email, password, "IDOR-Victim").await {
        Ok(()) => println!("[IDOR]   Victim registered"),
        Err(e) => println!("[IDOR]   Victim registration: {}", e),
    }

    // Login both to obtain access tokens + user IDs
    let attacker_login = client.login(&attacker_email, password).await
        .map_err(|e| format!("attacker login failed: {}", e))?;

    let victim_login = client.login(&victim_email, password).await
        .map_err(|e| format!("victim login failed: {}", e))?;

    // Extract user IDs from /auth/profile using each token
    let attacker_id = get_user_id(client, &attacker_login.access_token).await
        .map_err(|e| format!("cannot get attacker ID: {}", e))?;
    let victim_id = get_user_id(client, &victim_login.access_token).await
        .map_err(|e| format!("cannot get victim ID: {}", e))?;

    println!("[IDOR]   Attacker ID: {}", attacker_id);
    println!("[IDOR]   Victim   ID: {}", victim_id);

    let attacker_token = &attacker_login.access_token;

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 2 — IDOR Probes
    //
    //  All requests use attacker's access token
    //  targeting victim's resources.
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    println!();
    println!("[IDOR] Phase 2: Running IDOR probes");

    let mut probes: Vec<IdorProbe> = Vec::new();

    // ── Probe 1: GET /api/v1/users/:victim_id ───
    // Attacker tries to read victim's profile
    {
        let path = format!("/api/v1/users/{}", victim_id);
        println!("[IDOR]   Probe 1: GET {} (read victim profile)", path);

        let r = client.get_authenticated(&path, attacker_token).await;
        let exposed = r.status == 200 && has_user_data(&r.body);

        println!("[IDOR]     → status={} code={} exposed={}", r.status, r.code, exposed);

        probes.push(IdorProbe {
            name: "read_victim_profile".into(),
            method: "GET".into(),
            path,
            status: r.status,
            response_code: r.code,
            exposed_data: exposed,
            detail: summarize_body(&r.body),
        });
    }

    // ── Probe 2: GET /api/v1/users/:attacker_id ─
    // Control: attacker reads OWN profile (should succeed)
    {
        let path = format!("/api/v1/users/{}", attacker_id);
        println!("[IDOR]   Probe 2: GET {} (read own profile — control)", path);

        let r = client.get_authenticated(&path, attacker_token).await;
        let exposed = r.status == 200 && has_user_data(&r.body);

        println!("[IDOR]     → status={} code={} exposed={}", r.status, r.code, exposed);

        probes.push(IdorProbe {
            name: "read_own_profile_control".into(),
            method: "GET".into(),
            path,
            status: r.status,
            response_code: r.code,
            exposed_data: exposed,
            detail: summarize_body(&r.body),
        });
    }

    // ── Probe 3: GET /api/v1/users/ (list all) ──
    // Non-admin trying to enumerate all users
    {
        let path = "/api/v1/users".to_string();
        println!("[IDOR]   Probe 3: GET {} (list all users)", path);

        let r = client.get_authenticated(&path, attacker_token).await;
        let exposed = r.status == 200;

        println!("[IDOR]     → status={} code={} exposed={}", r.status, r.code, exposed);

        probes.push(IdorProbe {
            name: "list_all_users".into(),
            method: "GET".into(),
            path,
            status: r.status,
            response_code: r.code,
            exposed_data: exposed,
            detail: summarize_body(&r.body),
        });
    }

    // ── Probe 4: PATCH /api/v1/users/:victim_id/role ─
    // Attacker tries to escalate victim to ADMIN
    {
        let path = format!("/api/v1/users/{}/role", victim_id);
        println!("[IDOR]   Probe 4: PATCH {} (privilege escalation)", path);

        let body = serde_json::json!({ "role": "ADMIN" });
        let r = client.patch_authenticated(&path, attacker_token, &body).await;
        let escalated = r.status == 200;

        println!("[IDOR]     → status={} code={} escalated={}", r.status, r.code, escalated);

        probes.push(IdorProbe {
            name: "escalate_victim_role".into(),
            method: "PATCH".into(),
            path,
            status: r.status,
            response_code: r.code,
            exposed_data: escalated,
            detail: summarize_body(&r.body),
        });
    }

    // ── Probe 5: DELETE /api/v1/users/:victim_id ─
    // Attacker tries to delete victim account
    {
        let path = format!("/api/v1/users/{}", victim_id);
        println!("[IDOR]   Probe 5: DELETE {} (delete victim)", path);

        let r = client.delete_authenticated(&path, attacker_token).await;
        let deleted = r.status == 200;

        println!("[IDOR]     → status={} code={} deleted={}", r.status, r.code, deleted);

        probes.push(IdorProbe {
            name: "delete_victim_account".into(),
            method: "DELETE".into(),
            path,
            status: r.status,
            response_code: r.code,
            exposed_data: deleted,
            detail: summarize_body(&r.body),
        });
    }

    // ── Probe 6: GET /api/v1/auth/profile ────────
    // Control: attacker's own profile via /auth/profile
    {
        let path = "/api/v1/auth/profile".to_string();
        println!("[IDOR]   Probe 6: GET {} (own profile baseline)", path);

        let r = client.get_authenticated(&path, attacker_token).await;

        println!("[IDOR]     → status={} code={}", r.status, r.code);

        probes.push(IdorProbe {
            name: "own_profile_baseline".into(),
            method: "GET".into(),
            path,
            status: r.status,
            response_code: r.code,
            exposed_data: r.status == 200,
            detail: summarize_body(&r.body),
        });
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  VERDICT
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    // Critical IDOR probes (attacker → victim resources)
    let idor_probes = ["read_victim_profile", "list_all_users",
                       "escalate_victim_role", "delete_victim_account"];

    let vulnerabilities: Vec<&IdorProbe> = probes.iter()
        .filter(|p| idor_probes.contains(&p.name.as_str()) && p.exposed_data)
        .collect();

    let verdict = if vulnerabilities.is_empty() {
        "SECURE"
    } else if vulnerabilities.iter().any(|p| p.name == "escalate_victim_role" || p.name == "delete_victim_account") {
        "CRITICAL"
    } else if vulnerabilities.iter().any(|p| p.name == "read_victim_profile") {
        "CRITICAL"
    } else {
        "VULNERABLE"
    };

    println!();
    println!("[IDOR] Vulnerabilities found: {}", vulnerabilities.len());
    for v in &vulnerabilities {
        println!("[IDOR]   🚨 {} → {} {}", v.name, v.method, v.path);
    }
    println!("[IDOR] Verdict: {}", verdict);

    Ok(IdorReport {
        attack: "idor_authorization_bypass".into(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        attacker_email,
        victim_email,
        attacker_id,
        victim_id,
        probes,
        verdict: verdict.into(),
    })
}

// ── Helpers ──────────────────────────────────────

/// Fetch the authenticated user's ID from /auth/profile.
async fn get_user_id(client: &ApiClient, token: &str) -> Result<String, String> {
    let r = client.get_authenticated("/api/v1/auth/profile", token).await;
    if r.status != 200 {
        return Err(format!("profile request failed ({}): {}", r.status, r.code));
    }
    // Response shape: { data: { user: { id: "uuid" } } }
    r.body["data"]["user"]["id"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "no user.id in profile response".into())
}

/// Check if the response body contains user data (signs of data leakage).
fn has_user_data(body: &Value) -> bool {
    let data = &body["data"];
    // Check for user object with sensitive fields
    let user = if data["user"].is_object() {
        &data["user"]
    } else if data.is_object() {
        data
    } else {
        return false;
    };

    // If we can see at least email or name of another user, it's a leak
    user.get("email").is_some() || user.get("name").is_some() || user.get("id").is_some()
}

/// Summarize a response body for the report (truncated).
fn summarize_body(body: &Value) -> String {
    let s = serde_json::to_string(body).unwrap_or_default();
    if s.len() > 200 {
        format!("{}…", &s[..200])
    } else {
        s
    }
}
