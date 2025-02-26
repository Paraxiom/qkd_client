// src/reporter/mod.rs
mod key_proof;
mod metrics;
mod qkd_client;

pub use key_proof::ProofGenerator;
pub use metrics::ReporterMetrics;
pub use qkd_client::QKDClient;

use std::error::Error;
use std::time::Instant;
use tracing::{debug, error, info};

pub struct ReporterNode {
    qkd_client: QKDClient,
    proof_generator: ProofGenerator,
}

impl ReporterNode {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            qkd_client: QKDClient::new()?,
            proof_generator: ProofGenerator::new()?,
        })
    }

    pub async fn report(&self) -> Result<ReporterMetrics, Box<dyn Error>> {
        let mut metrics = ReporterMetrics {
            key_retrieval_time: std::time::Duration::default(),
            proof_generation_time: std::time::Duration::default(),
            verification_time: std::time::Duration::default(),
        };

        // Key retrieval with timing
        let start = Instant::now();
        let key = self.qkd_client.get_key().await?;
        metrics.key_retrieval_time = start.elapsed();
        debug!("Key retrieved in {:?}", metrics.key_retrieval_time);

        // Proof generation with timing
        let start = Instant::now();
        let proof = self.proof_generator.generate_proof(&key).await?;
        metrics.proof_generation_time = start.elapsed();
        debug!("Proof generated in {:?}", metrics.proof_generation_time);

        // Verification with timing
        let start = Instant::now();
        let verified = proof.verify()?;
        metrics.verification_time = start.elapsed();

        if verified {
            info!(
                "✅ Proof verified successfully in {:?}",
                metrics.verification_time
            );
        } else {
            error!("❌ Proof verification failed");
        }

        Ok(metrics)
    }
}
