// src/main.rs
mod byzantine;
mod quantum_auth;
mod reporter;
mod vrf;
mod zk;
use reporter::ReporterNode;
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() {
    // Setup logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    println!("🌟 Starting Reporter Node...");

    // Create and run reporter node
    match ReporterNode::new() {
        Ok(reporter) => match reporter.report().await {
            Ok(metrics) => {
                println!("\n📊 Reporter Node Metrics:");
                println!("Key Retrieval Time: {:?}", metrics.key_retrieval_time);
                println!("Proof Generation Time: {:?}", metrics.proof_generation_time);
                println!("Verification Time: {:?}", metrics.verification_time);
            }
            Err(e) => println!("❌ Reporting failed: {}", e),
        },
        Err(e) => println!("❌ Failed to create Reporter Node: {}", e),
    }
}
