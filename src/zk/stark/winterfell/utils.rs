// src/zk/stark/winterfell/utils.rs
use winter_air::BatchingMethod;

// Define a trait to extend BatchingMethod functionality
pub trait BatchingMethodExt {
    fn safe_variant() -> Self;
}

impl BatchingMethodExt for BatchingMethod {
    fn safe_variant() -> Self {
        // Use Linear instead of unsafe mem::zeroed
        BatchingMethod::Linear
    }
}
