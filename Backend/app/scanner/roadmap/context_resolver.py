from typing import List, Optional, Dict
from pydantic import BaseModel, Field
from app.scanner.roadmap.adapters.phase3_adapter import NormalizedFindingContext, NormalizedAssetContext
from app.scanner.engines.crypto_normalization import CryptoNormalization

class CryptographicContext(BaseModel):
    finding_id: str
    asset_ids: List[str]
    cryptographic_role: str
    observed_algorithm: str
    observed_parameter_set: Optional[str] = None
    protocol_version: Optional[str] = None
    libraries: List[str] = Field(default_factory=list)
    memory_constraint_bytes: Optional[int] = None
    payload_limit_bytes: Optional[int] = None
    latency_constraint_ms: Optional[int] = None
    confidence: float = 1.0

class ContextResolver:
    @classmethod
    def resolve(cls, finding: NormalizedFindingContext, asset_contexts: List[NormalizedAssetContext]) -> CryptographicContext:
        """Resolves canonical Phase 3 findings into structured cryptographic constraints."""
        
        # 1. Structured extraction from canonical finding details
        observed_algorithm = finding.details.get("algorithm", "UNKNOWN")
        
        role = finding.details.get("cryptographic_role", "UNKNOWN")
        if role == "UNKNOWN":
            primitive = finding.details.get("primitive", "unknown")
            if primitive != "unknown":
                role = primitive.upper()
                
        parameter_set = finding.details.get("parameter_set")
        protocol_version = finding.details.get("protocol_version")
        
        # Fallback to normalized names using existing normalization layer if missing in details
        if role == "UNKNOWN" and observed_algorithm != "UNKNOWN":
            primitive = CryptoNormalization.classify_primitive(observed_algorithm)
            if primitive != "unknown":
                role = primitive.upper()
                
        if observed_algorithm != "UNKNOWN":
            observed_algorithm = CryptoNormalization.normalize_algorithm(observed_algorithm)
            
        role = role.replace("KEY_AGREEMENT", "KEY_ESTABLISHMENT").replace("SIGNATURE", "DIGITAL_SIGNATURE")
            
        if role == "UNKNOWN" or observed_algorithm == "UNKNOWN":
            return CryptographicContext(
                finding_id=finding.finding_id,
                asset_ids=[a.asset_id for a in asset_contexts],
                cryptographic_role="INSUFFICIENT_CONTEXT",
                observed_algorithm=observed_algorithm,
                confidence=finding.confidence,
                libraries=[]
            )

        # 2. Extract Constraints & Libraries from Asset Contexts and Details
        memory_limit = finding.details.get("memory_constraint_bytes")
        payload_limit = finding.details.get("payload_limit_bytes")
        latency_limit = finding.details.get("latency_constraint_ms")
        
        libraries = set()
        if "libraries" in finding.details and isinstance(finding.details["libraries"], list):
            libraries.update(finding.details["libraries"])
            
        for ctx in asset_contexts:
            # Domain-specific limits
            if ctx.asset_type.lower() in ("embedded_device", "iot"):
                memory_limit = memory_limit or (64 * 1024)
                payload_limit = payload_limit or 4096
            
            # Evidence-backed library support extraction
            if ctx.technology and ctx.technology != "UNKNOWN":
                libraries.add(ctx.technology)
                
            for dep in ctx.dependencies:
                libraries.add(dep)

        return CryptographicContext(
            finding_id=finding.finding_id,
            asset_ids=[a.asset_id for a in asset_contexts],
            cryptographic_role=role,
            observed_algorithm=observed_algorithm,
            observed_parameter_set=parameter_set,
            protocol_version=protocol_version,
            libraries=list(libraries),
            memory_constraint_bytes=memory_limit,
            payload_limit_bytes=payload_limit,
            latency_constraint_ms=latency_limit,
            confidence=finding.confidence
        )
