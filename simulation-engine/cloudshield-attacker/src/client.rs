use reqwest::Client;
use serde_json::Value;
use std::time::Duration;

#[derive(Clone)]
pub struct ApiClient {
    client: Client,
    base_url: String,
}

pub struct LoginResult {
    pub access_token: String,
    pub refresh_token: String,
}

/// Login that returned MFA_REQUIRED instead of tokens.
pub struct MfaLoginResult {
    pub temp_token: String,
}

pub struct RefreshResult {
    pub status: u16,
    pub code: String,
    pub latency_ms: u64,
    pub error: Option<String>,
}

/// Generic HTTP result used by MFA attack probes.
pub struct HttpResult {
    pub status: u16,
    pub code: String,
    pub body: Value,
    pub latency_ms: u64,
}

impl ApiClient {
    pub fn new(base_url: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .expect("Failed to build HTTP client");

        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    // ── Health ────────────────────────────────────

    pub async fn health_check(&self) -> Result<bool, String> {
        let url = format!("{}/health", self.base_url);
        self.client
            .get(&url)
            .send()
            .await
            .map(|r| r.status().is_success())
            .map_err(|e| e.to_string())
    }

    // ── Register ─────────────────────────────────

    pub async fn register(&self, email: &str, password: &str, name: &str) -> Result<(), String> {
        let url = format!("{}/api/v1/auth/register", self.base_url);
        let body = serde_json::json!({ "name": name, "email": email, "password": password });

        let resp = self.client.post(&url).json(&body).send().await
            .map_err(|e| format!("request error: {}", e))?;

        let status = resp.status().as_u16();
        if status == 201 || status == 409 {
            Ok(())
        } else {
            let text = resp.text().await.unwrap_or_default();
            Err(format!("status {}: {}", status, text))
        }
    }

    // ── Login (standard — expects tokens back) ───

    pub async fn login(&self, email: &str, password: &str) -> Result<LoginResult, String> {
        let url = format!("{}/api/v1/auth/login", self.base_url);
        let body = serde_json::json!({ "email": email, "password": password });

        let resp = self.client.post(&url).json(&body).send().await
            .map_err(|e| format!("login request error: {}", e))?;

        let status = resp.status().as_u16();
        let refresh_token = Self::extract_cookie(&resp, "refreshToken");

        let text = resp.text().await.unwrap_or_default();
        let json: Value = serde_json::from_str(&text).unwrap_or(Value::Null);

        if status != 200 {
            if json.get("data").and_then(|d| d.get("status"))
                .and_then(|s| s.as_str()) == Some("MFA_REQUIRED")
            {
                return Err("MFA_REQUIRED — use a non-MFA account".into());
            }
            return Err(format!("login failed ({}): {}", status, text));
        }

        let refresh_token = refresh_token
            .ok_or("No refreshToken cookie in login response")?;

        let access_token = json["data"]["accessToken"]
            .as_str().unwrap_or("").to_string();

        Ok(LoginResult { access_token, refresh_token })
    }

    // ── Login (MFA path — expects tempToken back) ─

    pub async fn login_expect_mfa(&self, email: &str, password: &str) -> Result<MfaLoginResult, String> {
        let url = format!("{}/api/v1/auth/login", self.base_url);
        let body = serde_json::json!({ "email": email, "password": password });

        let resp = self.client.post(&url).json(&body).send().await
            .map_err(|e| format!("login request error: {}", e))?;

        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        let json: Value = serde_json::from_str(&text).unwrap_or(Value::Null);

        if status != 200 {
            return Err(format!("login failed ({}): {}", status, text));
        }

        // The API returns { data: { status: "MFA_REQUIRED", tempToken: "..." } }
        let data = &json["data"];
        if data["status"].as_str() != Some("MFA_REQUIRED") {
            return Err("Expected MFA_REQUIRED but got normal login".into());
        }

        let temp_token = data["tempToken"]
            .as_str()
            .ok_or("No tempToken in MFA_REQUIRED response")?
            .to_string();

        Ok(MfaLoginResult { temp_token })
    }

    // ── MFA setup (requires access token) ────────

    pub async fn mfa_setup(&self, access_token: &str) -> Result<String, String> {
        let url = format!("{}/api/v1/mfa/setup", self.base_url);

        let resp = self.client.post(&url)
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| format!("mfa setup error: {}", e))?;

        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        let json: Value = serde_json::from_str(&text).unwrap_or(Value::Null);

        if status != 200 {
            return Err(format!("mfa setup failed ({}): {}", status, text));
        }

        // Returns { data: { manualKey: "BASE32SECRET", qr: "...", otpauth_url: "..." } }
        let manual_key = json["data"]["manualKey"]
            .as_str()
            .ok_or("No manualKey in MFA setup response")?
            .to_string();

        Ok(manual_key)
    }

    // ── MFA verify (finalize setup, requires access token) ──

    pub async fn mfa_verify(&self, access_token: &str, code: &str) -> Result<(), String> {
        let url = format!("{}/api/v1/mfa/verify", self.base_url);
        let body = serde_json::json!({ "code": code });

        let resp = self.client.post(&url)
            .header("Authorization", format!("Bearer {}", access_token))
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("mfa verify error: {}", e))?;

        let status = resp.status().as_u16();
        if status == 200 {
            Ok(())
        } else {
            let text = resp.text().await.unwrap_or_default();
            Err(format!("mfa verify failed ({}): {}", status, text))
        }
    }

    // ── MFA validate-login (public endpoint) ─────

    pub async fn mfa_validate_login(&self, temp_token: &str, code: &str) -> HttpResult {
        let url = format!("{}/api/v1/auth/mfa/validate-login", self.base_url);
        let body = serde_json::json!({ "tempToken": temp_token, "code": code });
        let start = std::time::Instant::now();

        let result = self.client.post(&url)
            .json(&body)
            .timeout(Duration::from_secs(5))
            .send()
            .await;

        let latency_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let json: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                let code = json["code"].as_str().unwrap_or("").to_string();
                HttpResult { status, code, body: json, latency_ms }
            }
            Err(e) => {
                let json = serde_json::json!({ "error": e.to_string() });
                HttpResult { status: 0, code: "NETWORK_ERROR".into(), body: json, latency_ms }
            }
        }
    }

    // ── Refresh (for token_race) ─────────────────

    pub async fn refresh_with_token(&self, refresh_token: &str) -> RefreshResult {
        let url = format!("{}/api/v1/auth/refresh", self.base_url);
        let start = std::time::Instant::now();

        let result = self.client.post(&url)
            .header("Cookie", format!("refreshToken={}", refresh_token))
            .timeout(Duration::from_secs(5))
            .send()
            .await;

        let latency_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let json: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                let code = json["code"].as_str().unwrap_or("").to_string();
                RefreshResult { status, code, latency_ms, error: None }
            }
            Err(e) => {
                RefreshResult { status: 0, code: String::new(), latency_ms, error: Some(e.to_string()) }
            }
        }
    }

    // ── Cookie extraction ────────────────────────

    fn extract_cookie(resp: &reqwest::Response, name: &str) -> Option<String> {
        let prefix = format!("{}=", name);
        for val in resp.headers().get_all("set-cookie") {
            if let Ok(s) = val.to_str() {
                if let Some(rest) = s.strip_prefix(&prefix) {
                    let end = rest.find(';').unwrap_or(rest.len());
                    return Some(rest[..end].to_string());
                }
            }
        }
        None
    }

    // ── Authenticated GET (generic) ─────────────

    pub async fn get_authenticated(&self, path: &str, access_token: &str) -> HttpResult {
        let url = format!("{}{}", self.base_url, path);
        let start = std::time::Instant::now();

        let result = self.client.get(&url)
            .header("Authorization", format!("Bearer {}", access_token))
            .timeout(Duration::from_secs(5))
            .send()
            .await;

        let latency_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let json: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                let code = json["code"].as_str().unwrap_or("").to_string();
                HttpResult { status, code, body: json, latency_ms }
            }
            Err(e) => {
                let json = serde_json::json!({ "error": e.to_string() });
                HttpResult { status: 0, code: "NETWORK_ERROR".into(), body: json, latency_ms }
            }
        }
    }

    // ── Authenticated PATCH (generic) ────────────

    pub async fn patch_authenticated(&self, path: &str, access_token: &str, body: &Value) -> HttpResult {
        let url = format!("{}{}", self.base_url, path);
        let start = std::time::Instant::now();

        let result = self.client.patch(&url)
            .header("Authorization", format!("Bearer {}", access_token))
            .json(body)
            .timeout(Duration::from_secs(5))
            .send()
            .await;

        let latency_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let json: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                let code = json["code"].as_str().unwrap_or("").to_string();
                HttpResult { status, code, body: json, latency_ms }
            }
            Err(e) => {
                let json = serde_json::json!({ "error": e.to_string() });
                HttpResult { status: 0, code: "NETWORK_ERROR".into(), body: json, latency_ms }
            }
        }
    }

    // ── Authenticated DELETE (generic) ───────────

    pub async fn delete_authenticated(&self, path: &str, access_token: &str) -> HttpResult {
        let url = format!("{}{}", self.base_url, path);
        let start = std::time::Instant::now();

        let result = self.client.delete(&url)
            .header("Authorization", format!("Bearer {}", access_token))
            .timeout(Duration::from_secs(5))
            .send()
            .await;

        let latency_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let json: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                let code = json["code"].as_str().unwrap_or("").to_string();
                HttpResult { status, code, body: json, latency_ms }
            }
            Err(e) => {
                let json = serde_json::json!({ "error": e.to_string() });
                HttpResult { status: 0, code: "NETWORK_ERROR".into(), body: json, latency_ms }
            }
        }
    }

    // ── Logout (revoke session via refresh token) ─

    pub async fn logout(&self, access_token: &str, refresh_token: &str) -> HttpResult {
        let url = format!("{}/api/v1/auth/logout", self.base_url);
        let start = std::time::Instant::now();

        let result = self.client.post(&url)
            .header("Authorization", format!("Bearer {}", access_token))
            .header("Cookie", format!("refreshToken={}", refresh_token))
            .timeout(Duration::from_secs(5))
            .send()
            .await;

        let latency_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let json: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                let code = json["code"].as_str().unwrap_or("").to_string();
                HttpResult { status, code, body: json, latency_ms }
            }
            Err(e) => {
                let json = serde_json::json!({ "error": e.to_string() });
                HttpResult { status: 0, code: "NETWORK_ERROR".into(), body: json, latency_ms }
            }
        }
    }

    // ── Login raw (returns status + code for brute-force tracking) ─

    pub async fn login_raw(&self, email: &str, password: &str) -> HttpResult {
        let url = format!("{}/api/v1/auth/login", self.base_url);
        let body = serde_json::json!({ "email": email, "password": password });
        let start = std::time::Instant::now();

        let result = self.client.post(&url)
            .json(&body)
            .timeout(Duration::from_secs(5))
            .send()
            .await;

        let latency_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let json: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                let code = json["code"].as_str().unwrap_or("").to_string();
                HttpResult { status, code, body: json, latency_ms }
            }
            Err(e) => {
                let json = serde_json::json!({ "error": e.to_string() });
                HttpResult { status: 0, code: "NETWORK_ERROR".into(), body: json, latency_ms }
            }
        }
    }

    // ── Authenticated POST (generic) ────────────

    pub async fn post_authenticated(&self, path: &str, access_token: &str, body: &Value) -> HttpResult {
        let url = format!("{}{}", self.base_url, path);
        let start = std::time::Instant::now();

        let result = self.client.post(&url)
            .header("Authorization", format!("Bearer {}", access_token))
            .json(body)
            .timeout(Duration::from_secs(5))
            .send()
            .await;

        let latency_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let json: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                let code = json["code"].as_str().unwrap_or("").to_string();
                HttpResult { status, code, body: json, latency_ms }
            }
            Err(e) => {
                let json = serde_json::json!({ "error": e.to_string() });
                HttpResult { status: 0, code: "NETWORK_ERROR".into(), body: json, latency_ms }
            }
        }
    }

    // ── POST with cookie only (for CSRF testing) ─

    pub async fn post_with_cookie(&self, path: &str, cookie_name: &str, cookie_val: &str) -> HttpResult {
        let url = format!("{}{}", self.base_url, path);
        let start = std::time::Instant::now();

        let result = self.client.post(&url)
            .header("Cookie", format!("{}={}", cookie_name, cookie_val))
            .timeout(Duration::from_secs(5))
            .send()
            .await;

        let latency_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let json: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                let code = json["code"].as_str().unwrap_or("").to_string();
                HttpResult { status, code, body: json, latency_ms }
            }
            Err(e) => {
                let json = serde_json::json!({ "error": e.to_string() });
                HttpResult { status: 0, code: "NETWORK_ERROR".into(), body: json, latency_ms }
            }
        }
    }
}

