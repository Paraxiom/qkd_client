
// src/reporter/config.rs
use serde::Deserialize;

#[derive(Deserialize)]
pub struct ReporterConfig {
    pub qkd_endpoint: String,
    pub cert_path: String,
    pub key_path: String,
    pub batch_size: usize,
    pub retry_attempts: u32,
}
