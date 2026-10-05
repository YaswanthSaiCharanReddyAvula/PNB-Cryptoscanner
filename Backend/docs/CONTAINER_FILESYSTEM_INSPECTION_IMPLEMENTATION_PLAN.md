# ECDAT / QuantumShield — Container & File System Inspection Engine
## Implementation Plan

### 1. Executive Summary & Audit Baseline
Following a comprehensive audit of the ECDAT / QuantumShield codebase, this document defines the complete engineering blueprint for repairing, upgrading, and delivering the enterprise **Container & File System Inspection Engine**.

The current codebase contains:
- Track A (Runtime / External): Stages 1–12 (Recon, Network, TLS, etc.)
- Track B (Build / Internal): SAST (`sast_crypto.py`), SCA (`sca_engine.py`), and a rudimentary `host_scanner.py` (Stage 15).
- Track C (Unification): `cbom_unification.py` which aggregates findings from all tracks into a CERT-IN / PNB Annexure-A compliant Cryptographic Bill of Materials (CBOM).

#### Identified Gaps in Current Stage 15 (`host_scanner.py`):
1. **No Container Image Support**: Zero support for OCI or Docker image archives (`.tar`, `.tar.gz`), manifests (`manifest.json`, `index.json`, `oci-layout`), layer diffs, or image configurations.
2. **Missing Whiteout Handling**: No support for OCI/Docker deletion markers (`.wh.<filename>` and `.wh..wh..opq`), meaning deleted cryptographic keys or files would incorrectly bleed through or remain unhandled.
3. **No Archive Security Bounds**: Standard `os.walk` without protection against zip/tar bombs, symlink escapes, path traversal (`../`), special device files (FIFOs, char/block devices), or resource exhaustion.
4. **Key Parsing Disabled**: Private keys (`.key`) were skipped as placeholders with zero cryptographic metadata (algorithm, key size, curve, fingerprint).
5. **Keystore Parsing Disabled**: Binary keystores (`.jks`, `.p12`, `.pfx`) were skipped without structured evidence or safe uninspected status.
6. **No Package Discovery**: No static extraction of OS packages (Debian/Ubuntu `dpkg`, Alpine `apk`, RedHat `rpm`) or language packages from filesystems or container layers.
7. **No PQC Detection**: No detection of Post-Quantum Cryptography algorithms (ML-KEM, ML-DSA, Kyber, Dilithium) or PQC-capable libraries (liboqs, BouncyCastle PQC).
8. **No Normalized Evidence Model**: Lack of an explicit `CryptoObservation` model preserving layer provenance, file path, parser confidence, and hash fingerprints.

---

### 2. Target Architecture Overview

```text
                                  INSPECTION TARGET
              ┌───────────────────────────┼───────────────────────────┐
              ▼                           ▼                           ▼
       Container Archive/Image       Local Filesystem            Repository Root
              │                           │                           │
              └───────────────────────────┼───────────────────────────┘
                                          ▼
                         Image Acquisition & Scope Validation
                                          ▼
                               Inspection Coordinator
                                          │
        ┌─────────────────────────────────┼─────────────────────────────────┐
        ▼                                 ▼                                 ▼
Container Image Parser           Filesystem Traversal               Package Discovery
  • Manifest & Digest               • Scope Enforcement               • OS (dpkg/apk/rpm)
  • Layer Extraction                • Resource Limits                 • Language Manifests
  • Whiteout & Merged View          • Symlink Bounds                  • Crypto Libs & Sonames
        │                                 │                                 │
        └─────────────────────────────────┼─────────────────────────────────┘
                                          ▼
                               Artifact Classification
                                          │
        ┌─────────────────────────────────┼─────────────────────────────────┐
        ▼                                 ▼                                 ▼
  Certificates & Chains            Private/Public Keys             Crypto Configs & Secrets
   • X.509 Deep Parsing             • RSA, EC, Ed25519              • SSH, Nginx, Apache
   • Key/Cert Correlation           • Safe Fingerprinting           • Env Vars (Redacted)
   • Trust Stores & Keystores       • Non-destructive Extraction    • PQC Readiness
        │                                 │                                 │
        └─────────────────────────────────┼─────────────────────────────────┘
                                          ▼
                                Evidence Normalization
                            (CryptoObservation Model)
                                          │
        ┌─────────────────────────────────┴─────────────────────────────────┐
        ▼                                                                   ▼
Downstream SCA & SAST Engines                                     CBOM Unification Engine
 (Package Vulns / Source AST)                                    (Certificates, Keys, Algos)
                                                                            │
                                                                            ▼
                                                                Quantum Risk & Dashboard
```

---

### 3. Phased Implementation Roadmap

#### Phase 1: Architecture Recovery & Baselining (COMPLETED)
- Audit entire codebase, runtime pipeline (`DualTrackPipelineManager`, `ScanContext`, `common.py`), and test infrastructure.
- Document exact execution flows, gaps, and legacy shims.

#### Phase 2: Common Inspection Models (`app.scanner.container.models`)
- `InspectionTarget`: Encapsulates target type (`container_archive`, `container_image`, `filesystem`, `repository`, `extracted_image`), source URI, scope, and authorization.
- `ContainerImageMetadata`: Statically captured manifest, image digest (immutable `sha256:...`), labels, architecture, OS, creation time, config.
- `ContainerLayer`: Layer digest, index, diff size, introduced files, whiteouts, layer tar reference.
- `FileArtifact`: File path, classification (`certificate`, `private_key`, `public_key`, `crypto_config`, `keystore`, `package_metadata`, `binary`, etc.), size, permissions, hashes.
- `CryptoObservation`: Normalized evidence record with target, image digest, layer, path, artifact type, algorithm, key size, signature algorithm, confidence, and parser metadata.
- `ResourceLimits`: Comprehensive bounds for archive size, layer count, file size, max files, depth, and traversal timeout.

#### Phase 3: Safe Filesystem Traversal Subsystem (`app.scanner.container.filesystem`)
- Strict scope enforcement: prevents escaping authorized roots (`SYMLINK_SKIPPED_OUT_OF_SCOPE`).
- Bounded traversal: max depth, max files, max bytes, file size limits.
- Content-based file classification: safe magic numbers + structural markers, avoiding reliance on file extensions alone.

#### Phase 4 & 5: Container Image Parsing, Layer Reconstruction & Archive Security (`app.scanner.container.container`)
- OCI & Docker image archive parsing (`manifest.json`, `index.json`, `oci-layout`, layer tarballs).
- Archive Security: strict path sanitization (`../` traversal rejection, absolute path stripping, symlink containment, zip/tar bomb detection, decompression ratio limits, no FIFO/device extraction).
- Layer Delta & Whiteout Engine:
  - Standard whiteout: `.wh.<filename>` marks deletion in previous layers.
  - Opaque whiteout: `.wh..wh..opq` hides all entries in the directory from previous layers.
  - Preserves layer provenance (`layer_digest`, `layer_index`, `historical_layer_presence`).

#### Phase 6: Deep Cryptographic Artifact Inspection (`app.scanner.container.crypto`)
- **Certificates**: Safely parses X.509 PEM and DER with `cryptography.x509`. Extracts Subject, Issuer, Serial, Validity dates, SANs, Key type/size, Signature Algorithm OID, Fingerprint, Basic Constraints, Key Usage. Identifies certificate chains.
- **Private Keys**: Detects and parses PEM private keys (PKCS#1, PKCS#8, EC, Encrypted). Extracts algorithm, curve, key size, safe SHA-256 public key fingerprint. NEVER persists raw private key material!
- **Public Keys**: Parses RSA, EC, Ed25519, Ed448 public keys.
- **Key-Certificate Correlation**: Correlates private keys with certificates by comparing public key fingerprints (not filenames).
- **Keystores & Trust Stores**: Safely inspects PKCS#12, JKS magic detection, PEM trust bundles (`/etc/ssl/certs/ca-certificates.crt`). Encrypted stores without password recorded as `ENCRYPTED_UNINSPECTED`.
- **Crypto Configurations**: Nginx, Apache, OpenSSL (`openssl.cnf`), SSH (`sshd_config`), Java security (`java.security`), KMS/HSM configs.
- **Environment Variables**: Redacted detection of crypto-related env vars (`SSL_CERT_FILE`, `PRIVATE_KEY_PATH`, etc.).
- **PQC Detection**: Recognizes PQC algorithms (ML-KEM, ML-DSA, SLH-DSA, Kyber, Dilithium, Falcon, SPHINCS+) and PQC libraries.

#### Phase 7: Static Package & Library Discovery (`app.scanner.container.packages`)
- OS Packages: Debian/Ubuntu (`/var/lib/dpkg/status`), Alpine (`/lib/apk/db/installed`), RPM metadata.
- Language Manifests: Python (`dist-info`, `egg-info`), Node.js (`package.json`, `package-lock.json`), Java (JAR manifests, POMs), Go/Rust metadata.
- Crypto Libraries & ELF Metadata: Detects presence of `libssl.so`, `libcrypto.so`, `liboqs.so`, `libsodium.so`, BouncyCastle, OpenSSL binaries without executing them.

#### Phase 8: Coordinator & Pipeline Integration
- `InspectionCoordinator`: High-level orchestrator connecting targets to filesystem traversal, container reconstruction, crypto analysis, and package discovery.
- Integration into `HostScannerEngine` (Stage 15 in Track B): seamlessly executes during scan runs, populating `ctx.internal_certificates`, `ctx.host_config_findings`, `ctx.crypto_observations`, and feeding packages into SCA and source code into SAST.
- Full integration with `CBOMUnificationEngine` (Track C) and `ScanRequest`.

#### Phase 9: Testing & Verification
- Unit and integration tests covering:
  - Filesystem safety (scope bounds, symlink traps, bomb limits).
  - Certificate & private key parsing, encryption detection, fingerprinting.
  - Keystore handling (PKCS#12, JKS).
  - Container layers, whiteout resolution, layer provenance.
  - Archive security (traversal rejection, safe decompression).
  - Package and PQC discovery.
  - End-to-end pipeline execution with CBOM integration.
