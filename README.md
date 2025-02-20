# QKD Client (Rust + PKCS#12 + CA)

## Overview

### Purpose

##### Authentication System
The client connects to a KMS or QKD endpoint at `https://<ip>/api/v1/keys/...` using mutual TLS authentication with client certificates.

##### Security Implementation

###### TLS Architecture
- Post-quantum key exchange via server library or quantum channel
- Authentication uses classical certificates or PKCS#12 containing classical/PQ-based keys

###### Authentication Flow
- Server validates client certificate from `.p12` file
- Only authorized clients can request QKD keys
- Returns JSON response containing new keys (`key_ID` and `key`)

### Certificate Configuration

##### Required Files
1. `client_alice_crt.pem` - Alice's public certificate (PEM format)
2. `client_alice_key.pem` - Alice's private key (RSA/EC/PQ)
3. `client_alice.p12` - PKCS#12 bundle containing certificate and key (password-protected)
4. `ca_crt.pem` - CA certificate for server certificate validation

##### Certificate Generation

###### Create PKCS#12 bundle
```bash
openssl pkcs12 -export \
  -in client_alice_crt.pem \
  -inkey client_alice_key.pem \
  -out client_alice.p12 \
  -name alice \
  -passout pass:MySecret
```

###### Generate client certificates
```bash
# Generate private key (RSA 3072 bits)
openssl genrsa -out client_alice_key.pem 3072

# Create CSR
openssl req -new -key client_alice_key.pem -out client_alice.csr \
  -subj "/C=GB/ST=England/L=Cambridge/O=Toshiba/OU=Test/CN=alice"

# Sign with CA
openssl x509 -req -in client_alice.csr -CA ca_crt.pem -CAkey ca_key.pem \
  -CAcreateserial -days 365 -out client_alice_crt.pem
```

### Quick Start

##### Build
```bash
cargo build
```

##### Setup
- Place `client_alice.p12` and `ca_crt.pem` in `certificate/Toshiba/certs/`
- Verify PKCS#12 password in `main.rs` matches your configuration

##### Run
```bash
cargo run
```

### Security Considerations

##### Current Implementation
- Client authentication uses mutual TLS with PKCS#12 certificates
- Quantum-safe key exchange when server implements:
  - QKD link
  - Post-quantum KEM (e.g., Kyber)

##### Limitations
- Classical certificates remain quantum-vulnerable
- Development mode accepts invalid certificates (remove for production)

### Development Notes

##### Implementation Details
- Uses `reqwest` for HTTPS client implementation
- Implements proper error handling for certificate operations
- Supports JSON parsing for key management responses
- Configurable for different QKD/KMS endpoints

##### Future Work
- [ ] Implement post-quantum certificate support
- [ ] Add proper certificate chain validation
- [ ] Enhance error handling and logging
- [ ] Add support for multiple key formats
- [ ] Implement key storage security

### References

##### Documentation
- [OpenSSL PKCS#12 Documentation](https://www.openssl.org/docs/manmaster/man1/openssl-pkcs12.html)
- [Reqwest Identity Documentation](https://docs.rs/reqwest/latest/reqwest/struct.Identity.html)
- [NIST PQC Standards](https://csrc.nist.gov/Projects/post-quantum-cryptography)
