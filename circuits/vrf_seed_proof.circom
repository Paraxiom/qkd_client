// vrf_seed_proof.circom
pragma circom 2.0.8;
include "circomlib/poseidon.circom";
include "circomlib/comparators.circom";

// This circuit proves that the provided VRF seed equals the hash of the quantum key and input data.
// Each input is a single field element.
template VRFSeedProof() {
    // Inputs (each one a single field element)
    signal input quantumKey;  // e.g. a 256-bit field element (hex string)
    signal input inputData;   // e.g. a 256-bit field element representing your input message
    signal input vrfSeed;     // the expected VRF seed as a field element

    // Output: isValid = 1 if the hash equals vrfSeed, else 0.
    signal output isValid;

    // Hash quantumKey and inputData together using Poseidon
    component hasher = Poseidon(2);
    hasher.inputs[0] <== quantumKey;
    hasher.inputs[1] <== inputData;

    // Compare the computed hash with the provided vrfSeed
    component comparator = IsEqual();
    comparator.in[0] <== hasher.out;
    comparator.in[1] <== vrfSeed;

    isValid <== comparator.out;
}

component main = VRFSeedProof();
