pragma circom 2.0.8;

include "circomlib/comparators.circom";  
include "circomlib/multiplexer.circom";  
include "circomlib/bitify.circom";  
include "circomlib/poseidon.circom";  

template MultiSourceKey(N) {
    signal input sourceCount;
    signal input validSources[N];

    signal output selectedKey;

    // Define key hashers
    component keyHashers[N];
    signal keyHashes[N];  // Store Poseidon outputs

    for (var i = 0; i < N; i++) {
        keyHashers[i] = Poseidon(1);
        keyHashers[i].inputs[0] <== validSources[i];  
        keyHashes[i] <== keyHashers[i].out;  // Store Poseidon hash outputs
    }

    // Multiplexer to select the correct key
    component keySelector = Multiplexer(1, N);  

    // Ensure signal arrays match expected dimensions
    signal keySelectorInp[N][1];
    signal sourceActive[N];
    signal selectionBits[N];  // ✅ Fixed multiple assignment issue
    component sourceActiveCmp[N];

    for (var i = 0; i < N; i++) {
        sourceActiveCmp[i] = LessThan(8);
        sourceActiveCmp[i].in[0] <== i;
        sourceActiveCmp[i].in[1] <== sourceCount;
        sourceActive[i] <== sourceActiveCmp[i].out;
        
        selectionBits[i] <== validSources[i] * sourceActive[i];  
        keySelectorInp[i][0] <== keyHashes[i];  
    }

    keySelector.inp <== keySelectorInp;  
    keySelector.sel <== selectionBits[0];  // ✅ Assign only ONE selector (fix T3001)
    selectedKey <== keySelector.out[0];  
}

// ✅ Ensure this is added at the end
component main = MultiSourceKey(8);

