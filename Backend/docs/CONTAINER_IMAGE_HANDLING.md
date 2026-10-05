# Container Image Handling Specification
## ECDAT / QuantumShield Container & Filesystem Inspection Engine

### 1. Overview
The container image handling subsystem provides secure, read-only, static inspection of container images without invoking Docker daemon or running any container runtime processes.

### 2. Supported Container Formats
- **Docker Image Archives**: Standard `docker save` tarballs containing `manifest.json`, config JSON, and layer tarballs (`<layer-id>/layer.tar`).
- **OCI Image Layouts**: Open Container Initiative compliant image archives containing `oci-layout`, `index.json`, and blob storage (`blobs/sha256/<hash>`).
- **Extracted Images**: Pre-extracted image directory hierarchies containing manifest and config files.

### 3. Image Identity & Immutable Digests
1. **Immutable Digests Preferred**:
   - The engine computes and verifies the canonical `sha256:...` digest over image configuration and layer manifests.
   - If only a mutable repository tag (e.g., `latest`, `v1.0.0`) is supplied, `identity_confidence` is marked as `MEDIUM` or `LOW`.
   - Never invent or fabricate image digests.
2. **Static Manifest Inspection**:
   - Extracts `architecture` (e.g. `amd64`, `arm64`)
   - `os` (e.g. `linux`, `windows`)
   - `created` timestamp
   - Environment variables (statically parsed, sensitive values redacted)
   - `Entrypoint` and `Cmd` (extracted for telemetry only; NEVER executed)
   - Configured `User` (tracks non-root vs root execution security signals)
   - Labels and build metadata

### 4. Image Acquisition vs. Inspection Decoupling
Image acquisition is strictly isolated from cryptographic inspection:
```text
Image Reference / Archive Path
               ↓
Scope & Authorization Validation
               ↓
Safe Unpack into Scratch Sandbox
               ↓
Static Manifest & Config Parsing
               ↓
Layer Reconstruction & Whiteout Processing
```

### 5. Registry Credentials Isolation
When registry integration is active:
- Credentials remain strictly in-memory within acquisition modules.
- Credentials NEVER appear in logs, error traces, or WebSocket events.
- Credentials NEVER enter `CryptoObservation` evidence dictionaries.
- Credentials NEVER persist in MongoDB or CBOM outputs.
