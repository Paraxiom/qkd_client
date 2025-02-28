pragma circom 2.0.8;
include "circomlib/poseidon.circom";
include "circomlib/comparators.circom";

// This circuit proves that a VRF seed incorporates a valid quantum key
template VRFSeedProof() {
    // Input: quantum key, input data, and VRF seed
    signal input quantumKey;
    signal input inputData;
    signal input vrfSeed;
    signal output isValid;
    
    // Hash the quantum key and input to get expected seed
    component hasher = Poseidon(2);
    hasher.inputs[0] <== quantumKey;
    hasher.inputs[1] <== inputData;
    
    // Compare hash output with provided VRF seed
    component comparator = IsEqual();
    comparator.in[0] <== hasher.out;
    comparator.in[1] <== vrfSeed;
    
    // Output 1 if valid, 0 if invalid
    isValid <== comparator.out;
}

component main = VRFSeedProof();
