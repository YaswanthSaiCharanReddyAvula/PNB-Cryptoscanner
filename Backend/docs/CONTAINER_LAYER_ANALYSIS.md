# Container Layer Analysis & Whiteout Resolution
## ECDAT / QuantumShield Container & Filesystem Inspection Engine

### 1. Layer Reconstruction Architecture
Container images are constructed as a stack of immutable filesystem layers. Each layer represents a delta against the previous layer.

```text
Layer 0 (Base OS)    → Introduced /etc/ssl/certs/old.key
       ↓
Layer 1 (App Setup)  → Introduced /app/package.json
       ↓
Layer 2 (Security)   → Whiteout (.wh.old.key) + Introduced /app/server.key
       ↓
Merged View          → /app/package.json, /app/server.key (/etc/ssl/certs/old.key is absent)
```

### 2. Whiteout Specification & Implementation
The engine fully implements OCI / Docker whiteout specifications:

1. **Standard Whiteout**:
   - Marker format: `.wh.<filename>` in directory `dir/`
   - Effect: Deletes `dir/<filename>` from all lower layers in the merged view.
   - Example: If `etc/.wh.old.key` is present in Layer $N$, `/etc/old.key` is deleted from the merged filesystem sandbox.
2. **Opaque Directory Whiteout**:
   - Marker format: `.wh..wh..opq` in directory `dir/`
   - Effect: Hides all files in `dir/` from lower layers, starting fresh in the current layer.
   - Example: Used in multi-stage builds to mask entire staging directories.

### 3. Layer Provenance & Deleted Artifacts Tracking
Even when an artifact is deleted from the final image view, historical evidence may be critical for supply-chain vulnerability and secret exposure audits:
- If a private key or certificate was introduced in Layer 1 and deleted in Layer 2:
  - `final_image_presence = False`
  - `historical_layer_presence = True`
  - `layer_introduced = 1`
  - `layer_deleted = 2`
- The artifact is NOT reported as active in the current filesystem, but remains auditable in `container_findings` and historical provenance logs.
