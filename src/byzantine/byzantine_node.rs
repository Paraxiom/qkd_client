// src/bin/byzantine_node.rs
use qkd_client::byzantine::ReporterManager;
use qkd_client::reporter::ReporterNode;  // Make sure this is exported
use tracing_subscriber::FmtSubscriber;
use tracing::{info, error};

#[tokio::main]
async fn main() {
    // Setup logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    info!("🌟 Starting Byzantine QKD Reporter Manager...");
    
    // Configuration
    let reporter_count = 5;
    let threshold = reporter_count / 2 + 1;
    let timeout_ms = 10000;
    
    // Create manager
    let manager = ReporterManager::new(reporter_count, threshold, timeout_ms);
    
    // Run consensus
    match manager.run().await {
        Ok(result) => {
            if result.consensus_reached {
                info!("Byzantine consensus reached!");
                info!("Successful reports: {}/{}", 
                     result.successful_reports, result.total_reports);
                
                if let Some(seed) = result.seed_material {
                    info!("Generated seed: {:?}", seed);
                }
            } else {
                error!("Failed to reach Byzantine consensus");
                error!("Successful reports: {}/{} (needed {})", 
                      result.successful_reports, result.total_reports, threshold);
            }
        }
        Err(e) => {
            error!("Error running Byzantine consensus: {}", e);
        }
    }
}
