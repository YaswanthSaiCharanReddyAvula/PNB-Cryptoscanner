# ECDAT / QuantumShield — Container & File System Inspection Engine
## Technical Architecture Specification

### 1. Architectural Invariants & Security Boundary
The Container & File System Inspection Engine is strictly **static, defensive, and observation-based**.

#### Non-Negotiable Invariants:
1. **Zero Execution**: The engine MUST NEVER execute untrusted container entrypoints, shell scripts, binaries, ELF executables, package hooks, Dockerfiles, or dynamic runtimes.
2. **Read-Only / Isolated**: Filesystem inspection is read-only. Container archives are extracted into strictly isolated temporary scratch sandboxes with bounded lifetime and size.
3. **No Credential / Secret Material Retention**: Full private keys, secrets, API tokens, passwords, and registry credentials MUST NEVER be persisted in plaintext, emitted into logs, or stored in CBOMs. Only safe SHA-256 fingerprints, algorithm classifications, and redacted evidence are preserved.
4. **Observation vs. Risk Separation**: The engine records factual cryptographic evidence (`CryptoObservation`). It does NOT assign final business risk scores (e.g. "CRITICAL"). Risk calculation is delegated to the downstream Quantum Risk Engine.
5. **Deduplication with Provenance**: Assets are deduplicated by cryptographic fingerprints, while preserving full provenance (file path, image digest, layer index).

---

### 2. Subsystem Architecture

```text
app/scanner/container/
├── __init__.py
├── models.py                     # Common Inspection Models & Limits
├── coordinator.py                # InspectionCoordinator
├── filesystem/
│   ├── __init__.py
│   ├── traversal.py              # Scope-bounded, symlink-safe directory walker
│   └── classifier.py             # Heuristic and content-based file classification
├── container/
│   ├── __init__.py
│   ├── archive.py                # Anti-bomb, path-sanitized tar/archive handler
│   ├── image_parser.py           # OCI & Docker manifest / config / layer extractor
│   └── layer_reconstructor.py    # Whiteout (.wh.*) handling & layer diff merger
├── crypto/
│   ├── __init__.py
│   ├── cert_parser.py            # Deep X.509 certificate & chain analyzer
│   ├── key_parser.py             # PEM/DER/PKCS#8 private & public key analyzer
│   ├── keystore_parser.py        # PKCS#12, JKS, and trust store analyzer
│   ├── config_parser.py          # Daemon, TLS, OpenSSL, SSH, & env configuration
│   └── pqc_detector.py           # PQC algorithms and PQC-capable library detector
├── packages/
│   ├── __init__.py
│   ├── os_packages.py            # dpkg, apk, rpm static database readers
│   ├── language_packages.py      # Python, npm, Maven/Gradle, Go static metadata
│   └── crypto_libraries.py       # Static crypto shared library / binary detector
└── binary/
    ├── __init__.py
    └── binary_inspector.py       # Static ELF/PE header and DT_NEEDED inspector
```

---

### 3. Layer Provenance & Whiteout Handling Specification

OCI Image Specification (and Docker image format) uses whiteout files to mark file deletion in Union filesystems:
1. **Explicit File Whiteout**:
   - Filename format: `.wh.<target_filename>`
   - Meaning: In the merged filesystem view, any file matching `<target_filename>` from lower layers must be omitted.
2. **Opaque Whiteout**:
   - Filename format: `.wh..wh..opq`
   - Meaning: All files in this directory from lower layers are masked/hidden.
3. **Layer Provenance Tracking**:
   - When a cryptographic artifact (e.g., an RSA private key) is found in Layer $i$, but deleted by a whiteout in Layer $j$ ($j > i$):
     - `final_image_presence = False`
     - `historical_layer_presence = True`
     - `layer_introduced = i`
     - `layer_deleted = j`
   - This provides critical auditability for answering: *"Which build layer inadvertently baked this credential into the image history?"*

---

### 4. Archive Security & Decompression Bomb Defense

Every container archive and layer tar is treated as untrusted input. The archive handler enforces:
- **Path Sanitization**: Every path within the tar member is resolved against the sandbox root. Any member containing `../`, root prefixes `/` or `C:\`, or attempting to resolve outside the sandbox root is rejected.
- **Symlink / Hardlink Bounding**: Symlinks and hardlinks pointing outside the extraction directory are refused (`SYMLINK_SKIPPED_OUT_OF_SCOPE`).
- **Device Node Rejection**: Block devices, character devices, FIFOs, and socket nodes are skipped.
- **Decompression Ratio & Size Quotas**:
  - Maximum archive size: 500 MB (configurable)
  - Maximum extracted size: 1.5 GB
  - Maximum file count: 50,000 files
  - Maximum decompression ratio: 20x
  - Decompression halts immediately if quotas are exceeded, raising `RESOURCE_LIMIT_EXCEEDED`.

---

### 5. Cryptographic Evidence Normalization

Every discovery emits a normalized `CryptoObservation` schema:

```json
{
  "observation_id": "obs-7c9e-4b21-8f5a",
  "target_id": "app-container:v1.2.0",
  "target_type": "container_image",
  "image_digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "layer_index": 2,
  "layer_digest": "sha256:d8e8fca2dc0f896fd7cb4cb0031ba249",
  "file_path": "/etc/ssl/certs/internal.crt",
  "artifact_type": "certificate",
  "algorithm": "RSA",
  "key_size": 2048,
  "signature_algorithm": "sha256WithRSAEncryption",
  "fingerprint": "a3b2c1...",
  "pqc_classification": "CLASSICAL",
  "confidence": "HIGH",
  "metadata": {
    "subject": "CN=internal-service.local",
    "issuer": "CN=Enterprise Root CA",
    "not_valid_after": "2027-01-01T00:00:00Z",
    "days_until_expiry": 365,
    "is_self_signed": false
  },
  "observed_at": "2026-10-05T10:00:00Z"
}
```

This model directly transforms into `CBOMCertificate`, `CBOMKey`, and `CBOMAlgorithm` entries inside Track C (`CBOMUnificationEngine`), guaranteeing zero data loss.
