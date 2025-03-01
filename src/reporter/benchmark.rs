use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ark_bn254::Bn254;
use ark_groth16::{create_random_proof, generate_random_parameters, Proof, ProvingKey, VerifyingKey};
use ark_std::rand::thread_rng;
use std::time::Instant;
use crate::zk::multi_source_proof::MultiSourceKeyProof;

pub fn benchmark_reporter(c: &mut Criterion) {
    let mut group = c.benchmark_group("Reporter Node Operations");

    // ✅ Baseline benchmark for PQE operations
    group.bench_function("pqe_baseline", |b| b.iter(|| {
        let mut rng = thread_rng();
        let num_operations: u64 = black_box(10_000);
        for _ in 0..num_operations {
            let _ = rng.next_u64(); // Simulating PQE randomness
        }
    }));

    // ✅ Benchmark our Zero-Knowledge Proof implementation
    group.bench_function("zk_enhanced", |b| b.iter(|| {
        let mut rng = thread_rng();
        let circuit = MultiSourceKeyProof::dummy_proof();
        
        let (proving_key, _) = generate_random_parameters::<Bn254, _, _>(circuit.clone(), &mut rng)
            .expect("Failed to generate parameters");

        let proof_start = Instant::now();
        let proof = create_random_proof(circuit, &proving_key, &mut rng)
            .expect("Failed to generate proof");
        let proof_time = proof_start.elapsed();

        black_box(proof);
        println!("ZK proof generation took {:?}", proof_time);
    }));

    group.finish();
}

criterion_group!(benches, benchmark_reporter);
criterion_main!(benches);
