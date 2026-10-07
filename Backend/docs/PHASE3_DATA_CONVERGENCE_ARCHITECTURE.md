# Phase 3: Data Convergence & Standardization Architecture

## Overview
The Data Convergence layer acts as the absolute barrier between discovering raw intelligence (Track A, Track B, Cloud) and aggregating it into the final `CanonicalEstate`. It resolves fragmentation, standardizes data through normalizers, and creates a unified single source of truth capable of exporting to any downstream format like CycloneDX 1.6 and CERT-IN Annexure-A.

## Architecture Pattern
The convergence pipeline follows a rigid pipeline execution defined in `ConvergenceStage`:

1. **Engine Adapters**: Sub-modules read raw outputs from `ScanContext` and emit `CanonicalAsset`, `CanonicalFinding`, and `CanonicalEvidence`.
2. **Normalization**: Identifiers, IPs, Ports, URLs, Hostnames, Versions, and Crypto algorithms are routed through `normalizers.py`.
3. **Deduplication**: Assets and Findings are deduplicated deterministically by generated identities. Evidence and sources are merged without loss.
4. **Correlation**: Disparate assets (e.g. IPs to Hostnames, Keys to Certificates) are linked via `Relationship` objects.
5. **Aggregation**: `CanonicalEstate` is formed, categorizing assets deterministically.

## The Convergence Barrier
The `ConvergenceStage` runs explicitly at order `10`, guaranteeing that Track A, Track B, and Cloud modules have executed first. It reads their output and injects `canonical_inventory` into the pipeline. Downstream processes (Reporting, CycloneDX Generation) only consume `canonical_inventory`.
