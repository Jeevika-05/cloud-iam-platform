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
    pub fn new(
        correlation_id: &str,
        user_id: &str,
        user_email: Option<String>,
        action: &str,
        target_endpoint: &str,
        result: &str,
    ) -> Self {
        let severity = if result == "VULNERABLE" || result == "CRITICAL" { "HIGH" } else { "LOW" }.to_string();
        Self {
            event_id: Uuid::new_v4().to_string(),
            correlation_id: correlation_id.to_string(),
            user_id: user_id.to_string(),
            user_email,
            event_type: "ATTACK".to_string(),
            action: action.to_string(),
            source_ip: "192.168.1.100".to_string(),
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
}
