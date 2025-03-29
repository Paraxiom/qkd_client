// vrf_proof.circom
include "circomlib/sha256.circom";

template VRFCircuit(nBytes) {
   // Private inputs (seed, inputData) as arrays of bytes:
   signal private input seed[nBytes];
   signal private input inputData[nBytes];
   
   // Public output: the computed hash (VRF result)
   signal output computedHash[8];  // 8 32-bit words for sha256

   // We'll wire up the sha256 of (seed ++ inputData).
   component hash = Sha256(nBytes*2);
   var i;
   for (i=0; i<nBytes; i++) {
      hash.in[i] = seed[i];
      hash.in[nBytes + i] = inputData[i];
   }

   // The computedHash is an 8-element array
   for (i=0; i<8; i++) {
      computedHash[i] <== hash.out[i];
   }
}

component main = VRFCircuit(32);
// This circuit expects 32 bytes for seed, 32 bytes for inputData
// and outputs an 8-word (256-bit) computedHash

