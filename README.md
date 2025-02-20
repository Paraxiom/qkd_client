QKD Client (Rust + PKCS#12 + CA)
This repository demonstrates how to securely request keys from a QKD server (or other quantum-safe endpoint) using PKCS#12-based client certificates in Rust. The implementation includes JSON response parsing for key retrieval (e.g., key_ID, key).
Overview
The client connects to a KMS or QKD endpoint at https://<ip>/api/v1/keys/... using mutual TLS authentication with client certificates.
Security Considerations

TLS Implementation:

Post-quantum key exchange via server library or quantum channel
Authentication currently uses classical certificates or PKCS#12 containing classical/PQ-based keys


Authentication Flow:

Server validates client certificate from .p12 file
Only authorized clients can request QKD keys
Returns JSON response containing new keys (key_ID and key)



Certificate Setup
Required Files

client_alice_crt.pem - Alice's public certificate (PEM format)
client_alice_key.pem - Alice's private key (RSA/EC/PQ)
client_alice.p12 - PKCS#12 bundle containing certificate and key (password-protected)
ca_crt.pem - CA certificate for server certificate validation
server_crt.pem, server_key.pem - Server-side certificates (client needs only ca_crt.pem)

Certificate Generation
Creating PKCS#12 Bundle
bash
