# Cryptographic Artifact Discovery & Correlation
## ECDAT / QuantumShield Container & Filesystem Inspection Engine

### 1. Discovered Cryptographic Asset Types
1. **X.509 Certificates**:
   - Formats: PEM (`-----BEGIN CERTIFICATE-----`), DER.
   - Metadata: Subject, Issuer, Serial Number, NotBefore, NotAfter, Expiry Days, SANs, CA Basic Constraints, Key Usage.
   - Algorithms: RSA, EC, Ed25519, Ed448, DSA.
   - Signatures: SHA-2, SHA-3, PQC signatures (ML-DSA, Dilithium).
   - Chains: Statically correlates parent-child relationships (leaf, intermediate, root).
2. **Private Keys**:
   - Formats: PKCS#1 (`BEGIN RSA PRIVATE KEY`), PKCS#8 (`BEGIN PRIVATE KEY`), SEC1 (`BEGIN EC PRIVATE KEY`), OpenSSH.
   - Algorithms, Key Size, Curve name.
   - Zero Secret Leakage: Never stores, logs, or exports private key material.
   - Safe Public Key Fingerprint: Derives public key and computes SHA-256 fingerprint for correlation with certificates.
   - Encryption: Encrypted keys recorded as `ENCRYPTED_UNINSPECTED` with safe header fingerprint. Never brute-forces passwords!
3. **Public Keys**:
   - Formats: PEM (`BEGIN PUBLIC KEY`), OpenSSH (`ssh-rsa`, `ssh-ed25519`, `ecdsa-sha2-*`).
4. **Key-Certificate Correlation**:
   - Pairs private keys with certificates if and only if their derived public key SHA-256 fingerprints are identical.
   - Filename matching is never used as proof of correlation.
5. **Keystores & Trust Stores**:
   - PKCS#12 (`.p12`, `.pfx`): Inspected safely with empty password. If encrypted: `status = ENCRYPTED_UNINSPECTED`.
   - JKS (`.jks`): Detected via magic bytes `\xfe\xed\xfe\xed` -> `status = ENCRYPTED_UNINSPECTED`.
   - Trust Bundles: Counts certificates, lists root CAs, checks expiry.
6. **Daemon & Framework Configurations**:
   - SSH (`sshd_config`): Ciphers, KexAlgorithms, MACs, HostKeyAlgorithms.
   - Nginx (`nginx.conf`): `ssl_protocols`, `ssl_ciphers`, certificate/key paths.
   - Apache (`httpd.conf`, `ssl.conf`): `SSLProtocol`, `SSLCipherSuite`, `SSLCertificateFile`.
   - OpenSSL (`openssl.cnf`): `CipherString`, `MinProtocol`, `MaxProtocol`.
   - Java (`java.security`): `jdk.tls.disabledAlgorithms`.
7. **Environment Variables**:
   - Crypto env vars (`SSL_CERT_FILE`, `PRIVATE_KEY_PATH`, `TLS_KEY`, `KMS_KEY_ID`, etc.) detected with values strictly redacted.
8. **Post-Quantum Cryptography (PQC)**:
   - Algorithms: ML-KEM, ML-DSA, SLH-DSA, Kyber, Dilithium, Falcon, SPHINCS+.
   - Libraries: liboqs, BouncyCastle PQC, Cloudflare CIRCL, wolfSSL PQC.
   - Status: `PQC_CAPABLE_LIBRARY`, `PQC_CONFIGURED`, `PQC_USAGE_OBSERVED`.
