# Phase 3: CycloneDX 1.6 Architecture

## Component Mapping Strategy
The export strictly targets CycloneDX 1.6 to leverage official support for `CryptoProperties`.

### Asset mapping
- **Hosts**: `ComponentType.OPERATING_SYSTEM` or `DEVICE`.
- **Services**: `ComponentType.APPLICATION` or Service abstractions.
- **Packages**: `ComponentType.LIBRARY` utilizing PURL for identifiers.
- **Algorithms / Keys / Certificates / Protocols**: `ComponentType.CRYPTOGRAPHIC_ASSET` or `LIBRARY` enriched with `cryptoProperties`.

### Crypto Properties Support
The exporter uses the `cyclonedx-python-lib` version 11+ (supporting spec 1.6) to accurately build:
- `AlgorithmProperties` (primitive, mode, padding).
- `CertificateProperties` (subject, issuer, valid_from, valid_to, pub_key_ref).
- `ProtocolProperties` (TLS versions).
- `RelatedCryptoMaterialProperties` (Key type, size).

### Vulnerability Mapping
`CanonicalFinding` objects are mapped to `Vulnerability` entities:
- `details.vulnerability_id` routes to ID.
- `RiskLevel` Enum maps precisely to `VulnerabilitySeverity` (e.g. CRITICAL -> CRITICAL).
- CWEs are parsed and linked as integer references.
- External references (like CVE URLs) are embedded.

### Validation
Output JSON is run through a JSonschema and structural validation pass to guarantee compliant output format.
