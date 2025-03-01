// src/bin/byzantine_scenarios.rs
use qkd_client::byzantine::ReporterManager;
use tracing::{error, info};
use tracing_subscriber::FmtSubscriber;

async fn run_scenario(
    name: &str,
    reporter_count: usize,
    threshold: usize,
    fault_probability: f64,
) -> bool {
    info!("Running Scenario: {}", name);
    info!("  Reporters: {}", reporter_count);
    info!("  Threshold: {}", threshold);
    info!("  Fault Probability: {}", fault_probability);

    let manager = ReporterManager::new(reporter_count, threshold, 30000)
        .with_fault_probability(fault_probability)
        .with_network_delay(100, 1000);

    match manager.run().await {
        Ok(result) => {
            if result.consensus_reached {
                info!("✅ Scenario {} SUCCEEDED", name);
                info!(
                    "  Successful reports: {}/{}",
                    result.successful_reports, result.total_reports
                );
                true
            } else {
                error!("❌ Scenario {} FAILED", name);
                error!(
                    "  Successful reports: {}/{}",
                    result.successful_reports, result.total_reports
                );
                false
            }
        }
        Err(e) => {
            error!("❌ Scenario {} ERROR: {}", name, e);
            false
        }
    }
}

#[tokio::main]
async fn main() {
    // Setup logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("failed to set subscriber");

    info!("🌟 Byzantine Consensus Scenarios");
    info!("===============================");

    // Run different scenarios
    let scenarios = vec![
        ("Best Case (No Failures)", 7, 4, 0.0),
        ("Tolerable Failures", 7, 4, 0.3),
        ("Borderline Case", 7, 4, 0.4),
        ("Consensus Failure", 7, 4, 0.6),
        ("Increased Redundancy", 9, 5, 0.4),
        ("Minimal Configuration", 3, 2, 0.2),
    ];

    let mut results = Vec::new();

    for (name, reporters, threshold, fault_prob) in scenarios {
        let success = run_scenario(name, reporters, threshold, fault_prob).await;
        results.push((name, success));
        info!("------------------------------");
    }

    // Summary
    info!("Scenario Results Summary:");
    for (name, success) in results {
        if success {
            info!("✅ {} - SUCCEEDED", name);
        } else {
            info!("❌ {} - FAILED", name);
        }
    }
}
