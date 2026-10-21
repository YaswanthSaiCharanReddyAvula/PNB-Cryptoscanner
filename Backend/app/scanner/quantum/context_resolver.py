"""
Phase 4 — Quantum Context Resolver

Adapts Phase 3 Canonical Assets into Quantum Assessment subjects,
resolving temporal constraints (Tm, Tc, Tq) from policies or properties.
"""

from typing import List, Dict, Any, Optional, Tuple, Set

from app.scanner.convergence.canonical_models import CanonicalAsset, CanonicalProperty
from app.scanner.engines.crypto_normalization import CryptoNormalization
from app.scanner.quantum.models import (
    QuantumTimeline,
    TimeValue,
    QuantumRiskAssessment,
)
from app.scanner.quantum.quantum_risk_engine import assess_quantum_risk


def _resolve_timeline(asset: CanonicalAsset, scenario: str = "baseline") -> QuantumTimeline:
    """
    Extracts or defaults Tm, Tc, Tq for an asset based on properties or policies.
    """
    # 1. Tq (Quantum Threat Timeline)
    # Typically comes from a global scenario, but we allow property overrides.
    tq_val = 15.0
    if scenario == "optimistic":
        tq_val = 20.0
    elif scenario == "aggressive":
        tq_val = 10.0

    tq = TimeValue(
        value=tq_val,
        unit="years",
        source=f"scenario_{scenario}",
        confidence=0.5,
        assumption="Global scenario assumption"
    )

    # 2. Tc (Confidentiality Lifetime)
    # Default policy: assume 5 years unless tagged.
    tc_val = 5.0
    tc_source = "default_policy"
    
    # Try to extract data classification from properties
    if "data_classification" in asset.properties:
        prop = asset.properties["data_classification"]
        if isinstance(prop, CanonicalProperty):
            val = str(prop.canonical_value).upper()
        else:
            val = str(prop).upper()
            
        mapping = {
            "PUBLIC": 0.0,
            "INTERNAL": 1.0,
            "CONFIDENTIAL": 5.0,
            "HIGHLY_SENSITIVE": 10.0,
            "LONG_TERM_SECRET": 20.0
        }
        if val in mapping:
            tc_val = mapping[val]
            tc_source = "asset_property:data_classification"

    tc = TimeValue(
        value=tc_val,
        unit="years",
        source=tc_source,
        confidence=0.8,
        assumption="Policy mapping from data classification"
    )

    # 3. Tm (Migration Time)
    # Default policy: assume 2 years.
    tm_val = 2.0
    tm_source = "default_policy"
    
    tm = TimeValue(
        value=tm_val,
        unit="years",
        source=tm_source,
        confidence=0.7,
        assumption="Standard system migration timeline"
    )

    return QuantumTimeline(Tm=tm, Tc=tc, Tq=tq)


def _get_property_val(prop: Any) -> str:
    if isinstance(prop, CanonicalProperty):
        return str(prop.canonical_value)
    return str(prop)


def resolve_asset_quantum_risk(
    asset: CanonicalAsset, scenario: str = "baseline"
) -> List[QuantumRiskAssessment]:
    """
    Reads a canonical asset, identifies cryptographic properties, and generates
    a list of QuantumRiskAssessments for each cryptographic subject.
    Supports canonical properties (keyType, signatureAlgorithm, cipherSuite, algorithm)
    as well as existing 'crypto:' prefixed properties and AssetType.ALGORITHM assets.
    Decomposes compound TLS cipher suites into constituent primitives and normalizes
    algorithm names while preserving original evidence.
    """
    assessments: List[QuantumRiskAssessment] = []
    
    # Resolve the shared temporal context for this asset
    timeline = _resolve_timeline(asset, scenario)
    
    # Data sensitivity for HNDL weight
    sensitivity = "UNKNOWN"
    if "data_classification" in asset.properties:
        sensitivity = _get_property_val(asset.properties["data_classification"]).upper()
        
    business_criticality = "UNKNOWN"
    if "business_criticality" in asset.properties:
        business_criticality = _get_property_val(asset.properties["business_criticality"]).upper()

    # Capture optional protocol context (e.g. tlsVersion) to attach as evidence
    protocol_context: Optional[str] = None
    for p_name in ("tlsVersion", "tls_version", "protocol", "protocol_version"):
        if p_name in asset.properties:
            p_val = _get_property_val(asset.properties[p_name]).strip()
            if p_val:
                protocol_context = f"{p_name}={p_val}"
                break

    # Extract global key size hint if present on asset (e.g., from keySize / key_size)
    global_key_size: Optional[int] = None
    for ks_name in ("keySize", "key_size"):
        if ks_name in asset.properties:
            ks_raw = _get_property_val(asset.properties[ks_name])
            try:
                global_key_size = int(ks_raw)
                break
            except (ValueError, TypeError):
                pass

    # Collect candidate cryptographic algorithm specifications from the asset
    # Each candidate is a tuple:
    # (algorithm_name: str, is_kex: bool, key_size: Optional[int], prop_source: str, prop_val_obj: Any, note: Optional[str])
    candidates: List[Tuple[str, bool, Optional[int], str, Any, Optional[str]]] = []

    def _add_candidate(val_str: str, default_kex: bool, explicit_key_size: Optional[int], prop_source: str, prop_val_obj: Any):
        if not val_str:
            return

        # Check if compound cipher suite (e.g. ECDHE-RSA-AES128-GCM-SHA256, TLS_AES_256_GCM_SHA384)
        if CryptoNormalization.is_compound_cipher_suite(val_str):
            decomposed = CryptoNormalization.decompose_cipher_suite(val_str)
            if decomposed:
                for comp in decomposed:
                    candidates.append((
                        comp["primitive"],
                        comp["is_kex"],
                        comp.get("key_size") or explicit_key_size,
                        prop_source,
                        prop_val_obj,
                        f"Decomposed from cipher suite '{val_str}' (role: {comp['role']})"
                    ))
                return

        # Single primitive normalization
        norm_alg, norm_bits, norm_kex, curve = CryptoNormalization.resolve_primitive(
            val_str, default_kex=default_kex
        )
        if norm_alg:
            candidates.append((
                norm_alg,
                norm_kex,
                norm_bits or explicit_key_size,
                prop_source,
                prop_val_obj,
                f"Normalized from '{val_str}'"
            ))
        else:
            # Fallback: maintain raw unrecognized string explicitly
            candidates.append((
                val_str,
                default_kex,
                explicit_key_size,
                prop_source,
                prop_val_obj,
                None
            ))

    # 1. Inspect properties for explicit cryptographic definitions
    for prop_name, prop_val in asset.properties.items():
        val_str = _get_property_val(prop_val).strip()
        if not val_str:
            continue

        prop_lower = prop_name.lower()

        # A. Prefixed crypto properties (contract preservation)
        if prop_name.startswith("crypto:"):
            is_kex = "kex" in prop_lower or "key_exchange" in prop_lower
            parsed_ks = None
            for token in val_str.replace("-", " ").split():
                if token.isdigit():
                    try:
                        parsed_ks = int(token)
                        break
                    except ValueError:
                        pass
            _add_candidate(val_str, is_kex, parsed_ks or global_key_size, prop_name, prop_val)

        # B. Key specifications: keyType / key_type
        elif prop_lower in ("keytype", "key_type"):
            is_kex = "kex" in val_str.lower() or "dh" in val_str.lower()
            _add_candidate(val_str, is_kex, global_key_size, prop_name, prop_val)

        # C. Signature algorithm specifications: signatureAlgorithm / signature_algorithm
        elif prop_lower in ("signaturealgorithm", "signature_algorithm"):
            _add_candidate(val_str, False, global_key_size, prop_name, prop_val)

        # D. Cipher suites: cipherSuite / cipher_suite
        elif prop_lower in ("ciphersuite", "cipher_suite"):
            val_upper = val_str.upper()
            is_kex = any(k in val_upper for k in ("ECDHE", "DHE", "ECDH", "DH"))
            _add_candidate(val_str, is_kex, global_key_size, prop_name, prop_val)

        # E. Direct algorithm properties: algorithm / algorithm_name
        elif prop_lower in ("algorithm", "algorithm_name"):
            is_kex = "kex" in val_str.lower() or "kex" in prop_lower
            _add_candidate(val_str, is_kex, global_key_size, prop_name, prop_val)

        # All other properties (subjectName, issuerName, notValidBefore, notValidAfter,
        # hostname, port, vendor, data_classification, business_criticality, tlsVersion, etc.)
        # are non-cryptographic or contextual and are explicitly ignored as algorithm candidates.

    # 2. If the asset itself is of type ALGORITHM, inspect asset.name (matches TLSAdapter for accepted_ciphers)
    is_algo_asset = False
    if hasattr(asset, "asset_type"):
        if isinstance(asset.asset_type, str):
            is_algo_asset = asset.asset_type.lower() == "algorithm"
        elif hasattr(asset.asset_type, "value"):
            is_algo_asset = str(asset.asset_type.value).lower() == "algorithm"

    if is_algo_asset and asset.name and asset.name.strip():
        algo_name = asset.name.strip()
        name_upper = algo_name.upper()
        is_kex = any(k in name_upper for k in ("ECDHE", "DHE", "ECDH", "DH")) or "kex" in str(asset.properties.get("primitive", "")).lower()
        _add_candidate(algo_name, is_kex, global_key_size, "asset_name", asset.name)

    # Deduplicate candidates on this asset: avoid duplicate assessments for the same asset & primitive
    seen_primitives: Set[Tuple[str, bool]] = set()

    for algorithm, is_kex, key_size, prop_source, prop_val, note in candidates:
        norm_key = (algorithm.upper().strip(), is_kex)
        if norm_key in seen_primitives:
            continue
        seen_primitives.add(norm_key)

        evidence = [f"Derived from canonical property '{prop_source}'"]
        if note:
            evidence.append(note)
        if getattr(asset, "evidence_refs", None):
            evidence.append(f"Evidence refs: {', '.join(asset.evidence_refs)}")
        if getattr(asset, "sources", None):
            evidence.append(f"Source engines: {', '.join(asset.sources)}")
        if isinstance(prop_val, CanonicalProperty):
            evidence.append(f"Property confidence: {prop_val.confidence}")
        if protocol_context:
            evidence.append(f"Protocol context: {protocol_context}")

        assessment = assess_quantum_risk(
            asset_id=asset.asset_id,
            algorithm_name=algorithm,
            key_size=key_size,
            key_exchange_role=is_kex,
            timeline=timeline,
            data_sensitivity=sensitivity,
            business_criticality=business_criticality,
            migration_complexity="MEDIUM",
            evidence=evidence,
            scan_id=getattr(asset, "scan_id", None)
        )
        assessments.append(assessment)

    return assessments
