// src/byzantine/manager.rs
use crate::reporter::ReporterNode;
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{error, info};

pub struct ReportResult {
    pub reporter_id: String,
    pub success: bool,
    pub key_id: Option<String>,
    pub timestamp: Instant,
    pub duration: Duration,
}

pub struct ConsensusResult {
    pub successful_reports: usize,
    pub total_reports: usize,
    pub consensus_reached: bool,
    pub seed_material: Option<Vec<u8>>,
}

pub struct ReporterManager {
    reporter_count: usize,
    threshold: usize,
    timeout: Duration,
    results: Arc<Mutex<Vec<ReportResult>>>,
}

impl ReporterManager {
    pub fn new(reporter_count: usize, threshold: usize, timeout_ms: u64) -> Self {
        Self {
            reporter_count,
            threshold,
            timeout: Duration::from_millis(timeout_ms),
            results: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub async fn run(&self) -> Result<ConsensusResult, Box<dyn Error>> {
        info!(
            "Starting Byzantine consensus with {} reporters, threshold {}",
            self.reporter_count, self.threshold
        );

        // Track timing
        let _start_time = Instant::now();

        // Run reporters sequentially (for simplicity in first version)
        for i in 0..self.reporter_count {
            let reporter_id = format!("reporter-{}", i);
            info!("Starting Reporter {}", reporter_id);

            // Create and run reporter
            match ReporterNode::new() {
                Ok(reporter) => {
                    let report_start = Instant::now();
                    match reporter.report().await {
                        Ok(_metrics) => {
                            let duration = report_start.elapsed();
                            info!("Reporter {} succeeded in {:?}", reporter_id, duration);

                            // Track successful result
                            let mut results = self.results.lock().unwrap();
                            results.push(ReportResult {
                                reporter_id,
                                success: true,
                                key_id: Some(format!("key-{}", i)), // Placeholder
                                timestamp: Instant::now(),
                                duration,
                            });
                        }
                        Err(e) => {
                            error!("Reporter {} failed: {}", reporter_id, e);
                            // Track failed result
                            let mut results = self.results.lock().unwrap();
                            results.push(ReportResult {
                                reporter_id,
                                success: false,
                                key_id: None,
                                timestamp: Instant::now(),
                                duration: report_start.elapsed(),
                            });
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to create Reporter {}: {}", reporter_id, e);
                    // Track creation failure
                    let mut results = self.results.lock().unwrap();
                    results.push(ReportResult {
                        reporter_id,
                        success: false,
                        key_id: None,
                        timestamp: Instant::now(),
                        duration: Duration::from_secs(0),
                    });
                }
            }

            // Check if we already have enough for consensus (early completion)
            if self.check_current_consensus() {
                info!("Early consensus reached after {} reporters", i + 1);
                break;
            }
        }

        // Calculate final consensus
        let results = self.results.lock().unwrap();
        let successful = results.iter().filter(|r| r.success).count();
        let consensus_reached = successful >= self.threshold;

        let seed_material = if consensus_reached {
            // Generate seed material from successful reports
            Some(self.generate_seed(&results))
        } else {
            None
        };

        let result = ConsensusResult {
            successful_reports: successful,
            total_reports: results.len(),
            consensus_reached,
            seed_material,
        };

        // Log results
        if consensus_reached {
            info!(
                "✅ Byzantine consensus reached! {}/{} reporters successful (needed {})",
                successful,
                results.len(),
                self.threshold
            );
            if let Some(seed) = &result.seed_material {
                info!("Generated seed material: {} bytes", seed.len());
            }
        } else {
            error!(
                "❌ Failed to reach Byzantine consensus. {}/{} reporters successful (needed {})",
                successful,
                results.len(),
                self.threshold
            );
        }

        Ok(result)
    }

    fn check_current_consensus(&self) -> bool {
        let results = self.results.lock().unwrap();
        let successful = results.iter().filter(|r| r.success).count();
        successful >= self.threshold
    }

    fn generate_seed(&self, results: &[ReportResult]) -> Vec<u8> {
        // Simple seed generation: XOR all successful keys
        // In a real implementation, this would use a more sophisticated approach
        let mut seed = vec![0u8; 32]; // 256-bit seed

        for result in results.iter().filter(|r| r.success) {
            // In a real implementation, we would use actual key material
            // For now, just use some bytes derived from the reporter ID
            let bytes = result.reporter_id.bytes().collect::<Vec<_>>();
            for (i, b) in bytes.iter().enumerate().take(32) {
                seed[i % 32] ^= b;
            }
        }

        seed
    }
    // Add this new method
    pub fn with_fault_probability(self, fault_probability: f64) -> Self {
        // This is a placeholder - in a real implementation we would
        // store this and use it to inject faults
        info!("Setting fault probability to {}", fault_probability);
        self
    }

    // Add this new method
    pub fn with_network_delay(self, min_ms: u64, max_ms: u64) -> Self {
        // This is a placeholder - in a real implementation we would
        // use this to simulate network delays
        info!("Setting network delay range to {}ms-{}ms", min_ms, max_ms);
        self
    }
}
