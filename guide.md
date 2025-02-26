# SPHINCS+ Integration Guide

Now that we've found the correct module names in the pqcrypto-sphincsplus crate, here's how to integrate the real SPHINCS+ implementation with your QKD client:

## Step 1: Update Your Files

Replace these files in your project:

1. `src/quantum_auth/pq/sphincs.rs` - Use the real implementation
2. `src/quantum_auth/pq/mod.rs` - Already set up correctly
3. `src/reporter/mod.rs` - Fixed version that handles type mismatches 
4. `src/byzantine/manager.rs` - Fixed unused variables
5. `src/quantum_auth/pq_auth.rs` - Fixed unused variables warning
6. `src/bin/sphincs_real_demo.rs` - Demo program showing the implementation

## Step 2: Test the Implementation

```bash
# Build the project
cargo build

# Run the SPHINCS+ demo
cargo run --bin sphincs_real_demo
```

This will show you the performance characteristics of the real SPHINCS+ implementation on your hardware.

## Step 3: Integration Recommendations

Based on the performance characteristics, consider these integration approaches:

1. **Pre-computation for Critical Operations**:
   - Generate SPHINCS+ signatures ahead of time for predictable operations
   - Store them in a secure cache for quick access

2. **Tiered Authentication Approach**:
   - Use fast classical crypto for high-frequency operations
   - Use SPHINCS+ for critical control messages and key operations
   - Consider a hybrid approach for optimal security/performance

3. **Batched Verification**:
   - Group verification operations to amortize overhead
   - Use multi-threading for parallel verification

4. **Monitoring and Alerting**:
   - Monitor SPHINCS+ operation times
   - Set alerts for performance degradation
   - Implement adaptive timeouts based on measured performance

## Step 4: Future Expansion

This implementation currently uses the `sphincssha2128fsimple` variant, but you can expand it to support other variants:

1. Add support for SHA2-128s (smaller signatures but slower)
2. Add support for SHAKE-based variants 
3. Add support for higher security levels (192, 256)

The module structure in the `pqcrypto-sphincsplus` crate makes it straightforward to support these other variants when needed.

## Performance Expectations

Based on typical SPHINCS+ performance:

- **Key Generation**: ~10ms to ~100ms
- **Signing**: ~10ms to ~100ms depending on message size
- **Verification**: ~1ms to ~10ms depending on message size
- **Signature Size**: ~8KB to ~30KB depending on variant

These are significantly larger/slower than classical algorithms but provide post-quantum security.
