use crate::client::ApiClient;
use serde::Serialize;

// ── Report structures ────────────────────────────

#[derive(Serialize)]
pub struct MassAssignmentReport {
    pub attack: String,
    pub attempted_fields: Vec<String>,
    pub endpoint_status: u16,
    pub endpoint_code: String,
    pub escalation_success: bool,
    pub verdict: String,
}

// ── Attack execution ─────────────────────────────

pub async fn run(
    client: &ApiClient,
    email: &str,
    password: &str,
) -> Result<MassAssignmentReport, String> {

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 1 — Login as a normal USER
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    println!("[MASS_ASSIGN] Phase 1: Logging in as a normal user");

    let login = client.login(email, password).await
        .map_err(|e| format!("login failed: {}", e))?;

    let access_token = login.access_token.clone();
    let account_info = client.get_authenticated("/api/v1/auth/profile", &access_token).await;
    
    if account_info.status != 200 {
        return Err(format!("Could not fetch initial profile: status={}", account_info.status));
    }

    let initial_role = account_info.body["data"]["user"]["role"].as_str().unwrap_or("USER").to_string();
    let user_id = account_info.body["data"]["user"]["id"].as_str().unwrap_or("").to_string();

    println!("[MASS_ASSIGN]   Logged in successfully");
    println!("[MASS_ASSIGN]   Current Role: {}", initial_role);
    println!("[MASS_ASSIGN]   User ID: {}", user_id);

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 2 — Attempt Mass Assignment
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    // We send extra attributes that shouldn't be accepted by a profile update endpoint.
    let malicious_payload = serde_json::json!({
        "name": "Attacker Updated",
        "role": "ADMIN",
        "isAdmin": true,
        "isVerified": true,
        "permissions": ["all"]
    });

    let attempted_fields = vec![
        "role".to_string(),
        "isAdmin".to_string(),
        "isVerified".to_string(),
        "permissions".to_string()
    ];

    println!();
    println!("[MASS_ASSIGN] Phase 2: Sending Malicious Update Payload");

    // Attack Target 1: The user-requested generic profile endpoint
    let target1 = "/api/v1/users/profile".to_string();
    // Attack Target 2: The specific user ID endpoint (in case the system uses that instead)
    let target2 = format!("/api/v1/users/{}", user_id);

    let mut attack_result = client.patch_authenticated(&target1, &access_token, &malicious_payload).await;
    let mut chosen_target = target1.clone();

    if attack_result.status == 404 {
        // If /profile endpoint does not exist, try the /:id endpoint
        println!("[MASS_ASSIGN]   {} returned 404, trying {}", target1, target2);
        attack_result = client.patch_authenticated(&target2, &access_token, &malicious_payload).await;
        chosen_target = target2;
    }

    println!("[MASS_ASSIGN]   Target : {}", chosen_target);
    println!("[MASS_ASSIGN]   Status : {}", attack_result.status);
    println!("[MASS_ASSIGN]   Code   : {}", attack_result.code);

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 3 — Verify Escalation
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    println!();
    println!("[MASS_ASSIGN] Phase 3: Verifying Account Status");

    let verify_info = client.get_authenticated("/api/v1/auth/profile", &access_token).await;
    let new_role = verify_info.body["data"]["user"]["role"].as_str().unwrap_or("USER").to_string();

    println!("[MASS_ASSIGN]   Updated Role: {}", new_role);

    let escalation_success = new_role == "ADMIN" || new_role != initial_role;

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  VERDICT
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    let verdict = if escalation_success {
        "CRITICAL" 
    } else {
        "SECURE"
    };

    println!();
    println!("[MASS_ASSIGN] Verdict: {}", verdict);

    Ok(MassAssignmentReport {
        attack: "mass_assignment".into(),
        attempted_fields,
        endpoint_status: attack_result.status,
        endpoint_code: attack_result.code,
        escalation_success,
        verdict: verdict.into(),
    })
}
