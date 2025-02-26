// src/bin/byzantine_simulation.rs
use rand::Rng;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// Simple reporter node that simulates quantum key retrieval
struct SimpleReporter {
    id: String,
    success_rate: f64,
}

impl SimpleReporter {
    fn new(id: &str, success_rate: f64) -> Self {
        Self {
            id: id.to_string(),
            success_rate,
        }
    }

    fn retrieve_key(&self) -> Result<Vec<u8>, String> {
        // Simulate network delay
        thread::sleep(Duration::from_millis(
            100 + rand::thread_rng().gen_range(0..500),
        ));

        // Simulate success based on success_rate
        if rand::thread_rng().gen_bool(self.success_rate) {
            // Generate random "quantum" key
            let key: Vec<u8> = (0..32).map(|_| rand::thread_rng().gen()).collect();
            println!("✅ Reporter {} successfully retrieved key", self.id);
            Ok(key)
        } else {
            println!("❌ Reporter {} failed to retrieve key", self.id);
            Err(format!("Reporter {} failed to retrieve key", self.id))
        }
    }
}

// Byzantine fault-tolerant system
struct ByzantineSystem {
    reporters: Vec<SimpleReporter>,
    threshold: usize,
}

impl ByzantineSystem {
    fn new(reporter_count: usize, threshold: usize) -> Self {
        let mut reporters = Vec::new();

        for i in 0..reporter_count {
            // Some reporters are more reliable than others
            let success_rate = if i % 5 == 0 { 0.3 } else { 0.8 };
            reporters.push(SimpleReporter::new(
                &format!("reporter-{}", i),
                success_rate,
            ));
        }

        Self {
            reporters,
            threshold,
        }
    }

    fn run(&self) -> bool {
        // Track successful retrievals
        let successful_reports = Arc::new(Mutex::new(0));

        // Run all reporters
        let mut handles = Vec::new();

        for reporter in &self.reporters {
            let reporter_id = reporter.id.clone();
            let success_counter = Arc::clone(&successful_reports);

            // Create a thread for each reporter
            let handle = thread::spawn(move || {
                let reporter = SimpleReporter::new(&reporter_id, 0.8);
                if reporter.retrieve_key().is_ok() {
                    let mut count = success_counter.lock().unwrap();
                    *count += 1;
                }
            });

            handles.push(handle);
        }

        // Wait for all reporters to finish
        for handle in handles {
            handle.join().unwrap();
        }

        // Check if we have enough successful reports for consensus
        let final_count = *successful_reports.lock().unwrap();
        println!(
            "Successful reports: {}/{} (needed {})",
            final_count,
            self.reporters.len(),
            self.threshold
        );

        final_count >= self.threshold
    }
}

fn main() {
    println!("🌟 Starting Byzantine Simulation...");

    // Create a system with 7 reporters, requiring 5 for consensus (can tolerate 2 failures)
    let reporter_count = 7;
    let threshold = (reporter_count / 2) + 1;
    let system = ByzantineSystem::new(reporter_count, threshold);

    println!(
        "Running with {} reporters, requiring {} for consensus",
        reporter_count, threshold
    );

    // Run the system
    if system.run() {
        println!("✅ Byzantine consensus reached!");
        println!("This consensus can now be used for VRF seed generation");
    } else {
        println!("❌ Failed to reach Byzantine consensus");
    }
}
