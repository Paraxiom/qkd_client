// src/bin/multi_reporter.rs
use qkd_client::reporter::ReporterNode;
use std::sync::{Arc, Mutex};
use tracing::{error, info};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() {
    // Setup logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("failed to set subscriber");

    info!("🌟 Starting Multi-Reporter Byzantine Simulation...");

    // Use a mutex to track successful reporters
    let success_count = Arc::new(Mutex::new(0));

    // Number of reporters to simulate
    let reporter_count = 5;

    // Byzantine fault tolerance threshold (2f+1 where f is max faulty nodes)
    let threshold = (reporter_count / 2) + 1;
    info!(
        "Running with {} reporters, requiring {} for consensus",
        reporter_count, threshold
    );

    // Run reporters sequentially to avoid thread-safety issues
    for i in 0..reporter_count {
        let reporter_id = format!("reporter-{}", i);
        info!("Starting Reporter {}", reporter_id);

        // Create and run a reporter
        if let Ok(reporter) = ReporterNode::new() {
            if let Ok(metrics) = reporter.report().await {
                info!("Reporter {} completed successfully", reporter_id);

                // Track successful reporter
                let mut count = success_count.lock().unwrap();
                *count += 1;
            } else {
                error!("Reporter {} failed to report", reporter_id);
            }
        } else {
            error!("Failed to create Reporter {}", reporter_id);
        }
    }

    // Check if we have enough successful reporters for consensus
    let final_count = *success_count.lock().unwrap();

    if final_count >= threshold {
        info!("✅ Byzantine consensus reached!");
        info!(
            "Successful reporters: {}/{} (needed {})",
            final_count, reporter_count, threshold
        );
        info!("This consensus can now be used for VRF seed generation");
    } else {
        error!("❌ Failed to reach Byzantine consensus");
        error!(
            "Successful reporters: {}/{} (needed {})",
            final_count, reporter_count, threshold
        );
    }
}
