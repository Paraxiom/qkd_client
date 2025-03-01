// src/bin/explore_crate.rs
// A simple program to explore the contents of pqcrypto-sphincsplus

use pqcrypto_traits as traits;
use pqcrypto_sphincsplus as sphincsplus;

fn main() {
    println!("Exploring pqcrypto-sphincsplus version: {}", env!("CARGO_PKG_VERSION"));
    println!("=========================================================");
    
    // Print crate-level documentation or modules if available
    println!("\nAvailable functionality:");
    
    // Try to access some generic functions that might be available
    println!("\nTrying to find available modules through functions:");
    
    // Check if the crate re-exports keypair functions
    println!("Looking for keypair functions:");
    
    // Print defined re-exports
    println!("\nRe-exports in the crate:");
    
    // List functions and types in scope
    println!("\nRecommended approach:");
    println!("Check the documentation at https://docs.rs/pqcrypto-sphincsplus/0.7.0/pqcrypto_sphincsplus/");
    println!("The crate might not expose modules directly; it may use re-exports instead");
    
    // Use known functions from pqcrypto_traits to see what's available
    println!("\nLooking at available trait implementations...");
    
    // Check if we can access types through traits
    match sphincsplus::haraka_128f_simple::keypair() {
        (pk, sk) => {
            println!("✓ Found haraka_128f_simple::keypair()");
            println!("  Public key size: {} bytes", pk.as_bytes().len());
            println!("  Secret key size: {} bytes", sk.as_bytes().len());
        },
    }
    
    // Try other potential module names based on documentation
    println!("\nAttempting to access other potential modules:");
    
    // Try with haraka
    try_module("haraka_128f_simple");
    try_module("haraka_128f_robust");
    try_module("haraka_128s_simple");
    try_module("haraka_128s_robust");
    
    // Try with sha256
    try_module("sha256_128f_simple");
    try_module("sha256_128f_robust");
    try_module("sha256_128s_simple");
    try_module("sha256_128s_robust");
    
    // Try with shake256
    try_module("shake256_128f_simple");
    try_module("shake256_128f_robust");
    try_module("shake256_128s_simple");
    try_module("shake256_128s_robust");
}

fn try_module(name: &str) {
    println!("Checking for module: {}", name);
    
    // We can't dynamically import modules, so we'll check each one manually
    match name {
        "haraka_128f_simple" => {
            match sphincsplus::haraka_128f_simple::keypair() {
                _ => println!("  ✓ Found sphincsplus::haraka_128f_simple"),
            }
        },
        "haraka_128f_robust" => {
            match sphincsplus::haraka_128f_robust::keypair() {
                _ => println!("  ✓ Found sphincsplus::haraka_128f_robust"),
            }
        },
        "haraka_128s_simple" => {
            match sphincsplus::haraka_128s_simple::keypair() {
                _ => println!("  ✓ Found sphincsplus::haraka_128s_simple"),
            }
        },
        "haraka_128s_robust" => {
            match sphincsplus::haraka_128s_robust::keypair() {
                _ => println!("  ✓ Found sphincsplus::haraka_128s_robust"),
            }
        },
        "sha256_128f_simple" => {
            match sphincsplus::sha256_128f_simple::keypair() {
                _ => println!("  ✓ Found sphincsplus::sha256_128f_simple"),
            }
        },
        "sha256_128f_robust" => {
            match sphincsplus::sha256_128f_robust::keypair() {
                _ => println!("  ✓ Found sphincsplus::sha256_128f_robust"),
            }
        },
        "sha256_128s_simple" => {
            match sphincsplus::sha256_128s_simple::keypair() {
                _ => println!("  ✓ Found sphincsplus::sha256_128s_simple"),
            }
        },
        "sha256_128s_robust" => {
            match sphincsplus::sha256_128s_robust::keypair() {
                _ => println!("  ✓ Found sphincsplus::sha256_128s_robust"),
            }
        },
        "shake256_128f_simple" => {
            match sphincsplus::shake256_128f_simple::keypair() {
                _ => println!("  ✓ Found sphincsplus::shake256_128f_simple"),
            }
        },
        "shake256_128f_robust" => {
            match sphincsplus::shake256_128f_robust::keypair() {
                _ => println!("  ✓ Found sphincsplus::shake256_128f_robust"),
            }
        },
        "shake256_128s_simple" => {
            match sphincsplus::shake256_128s_simple::keypair() {
                _ => println!("  ✓ Found sphincsplus::shake256_128s_simple"),
            }
        },
        "shake256_128s_robust" => {
            match sphincsplus::shake256_128s_robust::keypair() {
                _ => println!("  ✓ Found sphincsplus::shake256_128s_robust"),
            }
        },
        _ => println!("  ✗ Module not recognized"),
    }
}
