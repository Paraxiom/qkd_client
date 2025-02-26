// src/bin/byzantine_demo.rs
use qkd_client::byzantine::ReporterManager;
use tracing::{error, info};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() {
    // Setup logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("failed to set subscriber");

    info!("🌟 Byzantine Consensus Demonstration");
    info!("====================================");

    // Configuration
    let reporter_count = 7; // Use 7 reporters
    let threshold = reporter_count / 2 + 1; // Need majority (4 of 7)
    let timeout_ms = 30000; // 30 second timeout

    info!("Configuration:");
    info!("  Reporter Count: {}", reporter_count);
    info!("  Consensus Threshold: {}", threshold);
    info!("  Timeout: {}ms", timeout_ms);
    info!("====================================");

    // Create Byzantine manager
    let manager = ReporterManager::new(reporter_count, threshold, timeout_ms);

    info!("Starting Byzantine consensus process...");
    // Run the Byzantine process
    match manager.run().await {
        Ok(result) => {
            if result.consensus_reached {
                info!("✅ CONSENSUS ACHIEVED!");
                info!(
                    "Successful reporters: {}/{}",
                    result.successful_reports, result.total_reports
                );

                if let Some(seed) = result.seed_material {
                    info!("📊 Generated seed material: {} bytes", seed.len());
                    info!("First 16 bytes: {:02x?}", &seed[..16.min(seed.len())]);

                    // Demonstrate how this could be used for VRF input
                    info!("This seed can now be used as input to a VRF for:");
                    info!("- Blockchain leader election");
                    info!("- Random committee selection");
                    info!("- Lottery/randomness applications");
                }
            } else {
                error!("❌ CONSENSUS FAILED!");
                error!(
                    "Successful reporters: {}/{}",
                    result.successful_reports, result.total_reports
                );
                error!("Needed {} successful reporters for consensus", threshold);
            }
        }
        Err(e) => {
            error!("❌ Error during Byzantine process: {}", e);
        }
    }
}
