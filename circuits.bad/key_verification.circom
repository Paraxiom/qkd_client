pragma circom 2.0.0;

template KeyHasher() {
    signal input key[32];
    signal output hash;    
    signal acc[33];
    
    acc[0] <== 0;
    for (var i = 0; i < 32; i++) {
        acc[i+1] <== acc[i] + key[i];
    }
    hash <== acc[32];
}

component main {public [key]} = KeyHasher();
