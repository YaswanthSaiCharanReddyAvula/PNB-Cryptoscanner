# PHASE 3 IMPLEMENTATION STATUS

## 1. OBSERVATION LAYER
* **Status**: `PARTIAL`
* **File/Class**: `app/scanner/convergence/canonical_models.py` -> `CanonicalEvidence`
* **Reason**: `CanonicalEvidence` exists and correctly tracks `source_engine`, `source_stage`, `target`, `value`, etc. However, an explicit `CanonicalObservation` model that cleanly separates an immutable observation from the canonical graph property is missing; properties are mapped directly into `Asset.properties` during the adapter phase.

## 2. ASSET IDENTITY RESOLUTION
* **Status**: `IMPLEMENTED` (with limitations)
* **File/Class**: `app/scanner/convergence/deduplication.py` -> `_generate_asset_identity`
* **Reason**: Identity is resolved deterministically by combining `AssetType` and sorted `Identifiers` (e.g., `hostname`, `ip`, `fingerprint`). It successfully groups assets. Limitation: relies on simple string keys rather than a dedicated `AssetIdentityResolver` service handling complex fallback logic.

## 3. GRANULAR PROPERTY MAPPING
* **Status**: `IMPLEMENTED`
* **File/Class**: `app/scanner/convergence/adapters/*`
* **Reason**: Engine-specific adapters (e.g., `NetworkAdapter`, `TLSAdapter`) correctly instantiate `CanonicalAsset` and map fields into the `properties: Dict[str, Any]` field. Properties are assigned to correct asset owners. 

## 4. NORMALIZATION
* **Status**: `PARTIAL`
* **File/Class**: `app/scanner/convergence/normalizers.py`
* **Reason**: Centralized functions exist for `normalize_hostname`, `normalize_ip`, `normalize_port`, `normalize_version`. However, the overall `Asset.properties` dictionary lacks strong typing, and no centralized property mapping registry exists.

## 5. PROPERTY RESOLUTION & CONFLICTS
* **Status**: `BROKEN` / `MISSING`
* **File/Class**: `app/scanner/convergence/deduplication.py` & `conflict_resolution.py`
* **Reason**: `conflict_resolution.py` contains a stubbed `resolve_asset_conflicts` function. In `deduplication.py`, properties are merged using a shallow `existing.properties.update(asset.properties)`, which silently overwrites conflicting values without preserving source precedence or conflict metadata.

## 6. ASSET GRAPH / RELATIONSHIPS
* **Status**: `IMPLEMENTED`
* **File/Class**: `app/scanner/convergence/canonical_models.py` -> `Relationship`
* **Reason**: One-to-many and many-to-one relationships are correctly represented via `Relationship(type, target_id)`. These are populated by adapters and deduplication merges them via set unions.

## 7. FINDING CORRELATION
* **Status**: `IMPLEMENTED`
* **File/Class**: `app/scanner/convergence/deduplication.py` -> `deduplicate_findings`
* **Reason**: Finds deterministic identity for vulnerabilities and associates them with `asset_refs` and `evidence_refs`. Correctly separates finding from the asset.

## 8. CANONICAL INVENTORY & CONVERGENCE
* **Status**: `IMPLEMENTED`
* **File/Class**: `app/scanner/convergence/aggregation.py` -> `aggregate_estate`, `convergence_stage.py`
* **Reason**: `ConvergenceStage` acts as a barrier, collecting from all adapters, deduplicating, correlating, and aggregating into `CanonicalEstate`.

## 9. CYCLONEDX EXPORTER
* **Status**: `PARTIAL`
* **File/Class**: `app/scanner/convergence/cyclonedx/*`
* **Reason**: Valid CycloneDX 1.6 logic exists and maps canonical data into components, services, and crypto properties. However, it is lossy; properties in the weakly typed dict that aren't explicitly extracted are dropped.

## 10. DATABASE & API INTEGRATION
* **Status**: `PARTIAL`
* **File/Class**: `app/api/routers/crypto_cbom.py`, `app/api/routers/assets.py`
* **Reason**: APIs expose CycloneDX export (`/cbom/cyclonedx`). However, older structures exist in the DB models (`cbom: dict`) instead of purely relying on `CanonicalEstate`.

## 11. LEGACY COMPONENTS
* **Status**: `LEGACY` / `DEPRECATED`
* **File/Class**: `app/scanner/engines/cbom_unification.py`, `app/scanner/engines/reporting.py`, `app/scanner/models.py` (CBOMReport, etc.)
* **Reason**: The legacy "Track C - CBOM Unification" stage and Annexure-A reporting engines build their own unified structures directly from contexts instead of consuming the new `CanonicalEstate`.
