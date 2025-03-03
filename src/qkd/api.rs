use reqwest::Client;
use std::error::Error;
use serde::{Deserialize, Serialize};

const QKD_API_URL: &str = "https://<QKD_MACHINE_IP>/api/v1/keys"; // Replace with actual QKD machine IP

#[derive(Debug, Serialize, Deserialize)]
struct KeyResponse {
    keys: Vec<KeyEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct KeyEntry {
    key_ID: String,
    key: String, // Base64-encoded key
}

pub struct QkdClient {
    client: Client,
    api_url: String,
    auth_token: String,
}

impl QkdClient {
    pub fn new(api_url: &str, auth_token: &str) -> Self {
        Self {
            client: Client::new(),
            api_url: api_url.to_string(),
            auth_token: auth_token.to_string(),
        }
    }

    /// **Fetch QKD encryption keys from KIRQ API**
    pub async fn fetch_qkd_keys(&self) -> Result<Vec<String>, Box<dyn Error>> {
        let response = self.client
            .get(&self.api_url)
            .header("Authorization", format!("Bearer {}", self.auth_token))
            .send()
            .await?
            .json::<KeyResponse>()
            .await?;

        let keys: Vec<String> = response.keys.into_iter().map(|k| k.key).collect();
        Ok(keys)
    }
}

