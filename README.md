# QKD Client (Rust + PKCS#12 + CA)

This repository demonstrates how to **securely** request keys from a QKD server (or other quantum-safe endpoint) using **PKCS#12-based client certificates** in Rust. We also parse JSON responses for key retrieval (e.g., `key_ID`, `key`). Below is an overview of **how** certificates were created, **why** we use them, and **the** high-level flow of our code.

## 1. Overview

- **Goal**: Connect to a `KMS` or QKD endpoint at `https://<ip>/api/v1/keys/...` with a **mutual TLS** setup, using a **client certificate**.  
- **TLS** is partially quantum-safe: 
  - We rely on post-quantum key exchange in the server library or a quantum channel.  
  - But classical certificates are still used for authentication, or a PKCS#12 containing a classical or PQ-based key.  
- **Result**: 
  - The server sees our client certificate (via `.p12`), ensuring only legitimate clients request QKD keys.  
  - We obtain a JSON response containing new keys (like `key_ID` and `key`).  

## 2. Certificates Explanation

We have the following files:

1. **`client_alice_crt.pem`** - Alice’s public certificate in PEM format.  
2. **`client_alice_key.pem`** - Alice’s private key (RSA or EC or possibly PQ).  
3. **`client_alice.p12`** - A PKCS#12 bundle containing both the above cert + key, protected by a password. 
   - Created via:
     ```bash
     openssl pkcs12 -export \
       -in client_alice_crt.pem \
       -inkey client_alice_key.pem \
       -out client_alice.p12 \
       -name alice \
       -passout pass:MySecret
     ```  
4. **`ca_crt.pem`** - The **CA certificate** that signs or trusts the server’s certificate. We also add it to our local trust store so we trust the server.  
5. **`server_crt.pem`, `server_key.pem`** - Possibly used on the server side (not strictly needed by the client, except we do want `ca_crt.pem` that signed it).

### How We Obtained Them

- The private key + certificate can be generated with typical OpenSSL commands, e.g.:  
  ```bash
  # Generate a private key (eg. RSA 3072 bits)
  openssl genrsa -out client_alice_key.pem 3072

  # Create a CSR (certificate signing request)
  openssl req -new -key client_alice_key.pem -out client_alice.csr \
    -subj "/C=GB/ST=England/L=Cambridge/O=Toshiba/OU=Test/CN=alice"

  # Self-sign or use a CA to sign:
  openssl x509 -req -in client_alice.csr -CA ca_crt.pem -CAkey ca_key.pem \
    -CAcreateserial -days 365 -out client_alice_crt.pem
echnological Advantage

    Mutual TLS with a client certificate ensures the server knows exactly which client is requesting keys, preventing unauthorized requests.
    PKCS#12 bundling means all you do in Rust code is Identity::from_pkcs12_der(...) with one file and a password—no messing with separate key/cert PEM merges.
    Quantum aspect: If the server side uses a quantum-safe KEM (like Kyber) or a QKD link, the ephemeral keys we get are not breakable by a future quantum adversary. The classical cert is still partially vulnerable, but overall we have forward secrecy for the session and quantum-safe key transport.

3. Code Flow Diagram

We have a single main.rs that does:

flowchart LR
    A[Start Program] --> B[Load PKCS#12 file<br>(client_alice.p12)]
    B --> C[Load CA cert<br>(ca_crt.pem)]
    C --> D[Create reqwest::Client<br>with identity+CA]
    D --> E[POST /api/v1/keys/bobsae/enc_keys<br>with JSON body]
    E --> F[Receive JSON response<br>like {\"keys\":[{\"key_ID\":\"...\",\"key\":\"...\"}]}]
    F --> G[Parse JSON,<br>store keys]
    G --> H[Done]

Explanation:

    We open the .p12 file (private key + cert) with a known password.
    We open ca_crt.pem so we trust the server.
    We build a reqwest client that does mutual TLS.
    We do a JSON POST request.
    The server responds with a keys array. We parse the key_ID and key.
    Done.

4. Usage

    Ensure you have cargo build or cargo run from the root.
    Place client_alice.p12 and ca_crt.pem in certificate/Toshiba/certs/.
    Confirm the correct password is in main.rs when calling from_pkcs12_der(..., \"MySecret\").
    Run:

    cargo run

    If successful, you’ll see Success! Got keys: logs, printing the key_ID and key.

5. Limitations & Future Work

    We still rely on classical certificates for authentication. A large quantum computer could break classical RSA/ECDSA. For full post-quantum, we’d need a PQ signature scheme or zero-knowledge–based approach.
    If you want total quantum safety, consider a QKD or post-quantum KEM handshake on the server side, plus post-quantum authentication (e.g., Dilithium certificates).
    Right now, we danger_accept_invalid_certs(true) to skip verifying the server’s certificate chain. In a real environment, we’d rely on the real CA path or remove that line.

6. References

    OpenSSL docs on PKCS#12
    Reqwest identity docs
    Quantum-Safe Key Exchange (Kyber) info from NIST PQC
