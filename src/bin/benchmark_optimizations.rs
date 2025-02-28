// src/bin/benchmark_optimizations.rs
use qkd_client::quantum_auth::pq::sphincs::SphincsAuth;
use std::error::Error;
use std::time::{Duration, Instant};

fn main() -> Result<(), Box<dyn Error>> {
    println!("🚀 SPHINCS+ Performance Benchmarks");
    println!("==================================");

    // Initialize standard SPHINCS+
    let sphincs = SphincsAuth::new()?;

    // Messages to sign (with some repetition to test caching)
    let messages = vec![
        b"Message 1".to_vec(),
        b"Message 2".to_vec(),
        b"Message 3".to_vec(),
        b"Message 1".to_vec(), // Repeated
        b"Message 2".to_vec(), // Repeated
    ];

    // Benchmark SPHINCS+ signing
    println!("SPHINCS+ signing performance:");
    let mut durations = Vec::new();
    for message in &messages {
        let start = Instant::now();
        let signature = sphincs.sign(message)?;
        let duration = start.elapsed();
        durations.push(duration);
        println!(
            "  Message: {:?}, Duration: {:?}",
            String::from_utf8_lossy(message),
            duration
        );
    }

    // Calculate average performance
    let avg_duration = durations.iter().sum::<Duration>() / durations.len() as u32;
    println!("\nAverage signing time: {:?}", avg_duration);

    // Benchmark verification
    println!("\nSPHINCS+ verification performance:");
    let mut verify_durations = Vec::new();
    for (i, message) in messages.iter().enumerate() {
        let signature = sphincs.sign(message)?;
        let start = Instant::now();
        let valid = sphincs.verify(message, &signature)?;
        let duration = start.elapsed();
        verify_durations.push(duration);
        println!(
            "  Message: {:?}, Valid: {}, Duration: {:?}",
            String::from_utf8_lossy(message),
            valid,
            duration
        );
    }

    // Calculate average verification performance
    let avg_verify = verify_durations.iter().sum::<Duration>() / verify_durations.len() as u32;
    println!("\nAverage verification time: {:?}", avg_verify);

    Ok(())
}
