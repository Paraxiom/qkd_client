// src/reporter/metrics.rs
use std::time::Duration;

#[derive(Debug)]
pub struct ReporterMetrics {
    pub key_retrieval_time: Duration,
    pub proof_generation_time: Duration,
    pub verification_time: Duration,
}
