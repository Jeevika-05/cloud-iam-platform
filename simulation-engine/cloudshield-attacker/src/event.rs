use serde::Serialize;
use uuid::Uuid;
use chrono::Utc;

#[derive(Serialize)]
pub struct GraphEvent {
    pub event_id: String,
    pub correlation_id: String,
    pub user_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_email: Option<String>,
    pub event_type: String,
    pub action: String,
    pub source_ip: String,
    pub ip_type: String,
    pub user_agent: String,
    pub agent_type: String,
    pub target_type: String,
    pub target_endpoint: String,
    pub result: String,
    pub severity: String,
    pub timestamp: String,
}

impl GraphEvent {
    /// W-1 FIX: Per-action severity mapping replaces the naive VULNERABLE/LOW binary.
    /// Severity reflects actual attack danger independent of whether the platform blocked it.
    /// Mapping rationale (MITRE ATT&CK + OWASP):
    ///   CRITICAL — direct account compromise or mass-scale brute force
    ///   HIGH     — token/session forgery, IDOR, privilege escalation vectors
    ///   MEDIUM   — session hijack, rate flooding, CSRF, mass assignment
    ///   LOW      — single-IP brute (caught by rate limiter), access token post-logout
    fn severity_for_action(action: &str) -> &'static str {
        match action {
            "MFA_BRUTE_FORCE_DISTRIBUTED" => "CRITICAL",
            "JWT_TAMPER"                  => "HIGH",
            "IDOR"                        => "HIGH",
            "TOKEN_RACE"                  => "HIGH",
            "SESSION_REUSE"               => "HIGH",
            "ACCESS_TOKEN_ABUSE"          => "MEDIUM",
            "SESSION_INVALID"             => "MEDIUM",
            "RATE_FLOOD"                  => "MEDIUM",
            "CSRF"                        => "MEDIUM",
            "MASS_ASSIGNMENT"             => "MEDIUM",
            "PASSWORD_BRUTE"              => "MEDIUM",
            "MFA_BRUTE_FORCE_SINGLE_IP"   => "MEDIUM",
            _                             => "LOW",
        }
    }

    pub fn new_with_ip(
        correlation_id: &str,
        user_id: &str,
        user_email: Option<String>,
        action: &str,
        target_endpoint: &str,
        result: &str,
        source_ip: String,
    ) -> Self {
        // W-1: Use action-based severity. Fall back to result-based only for unknown actions.
        let severity = Self::severity_for_action(action).to_string();
        Self {
            event_id: Uuid::new_v4().to_string(),
            correlation_id: correlation_id.to_string(),
            user_id: user_id.to_string(),
            user_email,
            event_type: "ATTACK".to_string(),
            action: action.to_string(),
            source_ip,
            ip_type: "SIMULATED".to_string(),
            user_agent: "attack-engine".to_string(),
            agent_type: "SIMULATED".to_string(),
            target_type: "API".to_string(),
            target_endpoint: target_endpoint.to_string(),
            result: result.to_string(),
            severity,
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    pub fn new(
        correlation_id: &str,
        user_id: &str,
        user_email: Option<String>,
        action: &str,
        target_endpoint: &str,
        result: &str,
    ) -> Self {
        Self::new_with_ip(
            correlation_id,
            user_id,
            user_email,
            action,
            target_endpoint,
            result,
            "192.168.1.100".to_string(),
        )
    }
}
