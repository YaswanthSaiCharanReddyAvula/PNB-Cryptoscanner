# Phase 3: Canonical Data Model Specification

## Abstract
The Canonical Data Model normalizes arbitrary and overlapping inputs from varying scan engines into a strict entity framework capable of being deterministically ordered and serialized.

## Core Models

### 1. CanonicalAsset
Represents an identifiable node within the estate graph.
- **asset_id**: UUIDv4 primary identifier.
- **scan_id**: Scan execution context.
- **asset_type**: Enum (`application`, `service`, `library`, `package`, `framework`, `container`, `host`, `certificate`, `key`, `algorithm`, `protocol`, `cloud_resource`).
- **identifiers**: Array of typed identities (e.g., `hostname`, `ip`, `purl`).
- **locations**: Deployment or file locations.
- **relationships**: Directed edges to other CanonicalAssets.
- **evidence_refs**: Pointers to CanonicalEvidence objects.

### 2. CanonicalFinding
Represents a vulnerability, misconfiguration, or noteworthy observation.
- **finding_id**: UUIDv4 primary identifier.
- **finding_type**: Categorization string.
- **severity**: `RiskLevel` Enum (SAFE, LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN).
- **confidence**: Float 0.0 - 1.0.
- **asset_refs**: Foreign keys to affected assets.
- **references**: External linkages (e.g. CVE records).

### 3. CanonicalEvidence
Represents immutable, auditable proof of a finding or asset observation.
- **observation_type**: Class of observation.
- **value_hash**: Redacted hash for secret tracking (SAST hardcoded keys).
- **redaction_status**: Enum signaling if `value` was removed for safety.
