"""
Phase 5 — Remediation Knowledge Base

Converts static recommendations into structured, versioned knowledge.
Maps findings and algorithms to specific Roadmap tracks and actions.
"""

from typing import Dict, List, Optional
from app.scanner.roadmap.models import RecommendationKBEntry, RoadmapTrack, ActionType, EffortLevel

KNOWLEDGE_BASE: List[RecommendationKBEntry] = [
    # ── Classical Security ──────────────────────────────────────────
    RecommendationKBEntry(
        recommendation_id="kb-tls-10-11-disable",
        finding_type="deprecated_protocol",
        technology="TLS",
        track=RoadmapTrack.CLASSICAL_SECURITY,
        action_type=ActionType.DISABLE,
        title="Disable TLS 1.0 and TLS 1.1",
        description="TLS 1.0 and 1.1 are vulnerable to protocol downgrade and known plaintext attacks (POODLE, BEAST).",
        solution="Configure the server or load balancer to strictly require TLS 1.2 or TLS 1.3.",
        prerequisites=["Ensure all legitimate clients support TLS 1.2+"],
        default_effort=EffortLevel.LOW,
        risk_reduction="Eliminates protocol downgrade risks",
        pqc_relevance=False,
        classical_relevance=True,
        validation_steps=["Scan endpoint with testssl.sh or nmap to verify TLS 1.0/1.1 are rejected."],
        rollback_steps=["Re-enable TLS 1.0/1.1 in configuration if critical clients fail."]
    ),
    RecommendationKBEntry(
        recommendation_id="kb-tls-weak-cipher",
        finding_type="weak_cipher",
        technology="TLS",
        track=RoadmapTrack.CLASSICAL_SECURITY,
        action_type=ActionType.DISABLE,
        title="Disable Weak Cipher Suites",
        description="RC4, 3DES, and export ciphers do not provide adequate classical security.",
        solution="Update cipher suite configuration to use modern AEAD ciphers (e.g., AES-GCM, ChaCha20).",
        prerequisites=[],
        default_effort=EffortLevel.LOW,
        pqc_relevance=False,
        classical_relevance=True,
    ),
    RecommendationKBEntry(
        recommendation_id="kb-cert-expiry",
        finding_type="expiring_certificate",
        technology="PKI",
        track=RoadmapTrack.CLASSICAL_SECURITY,
        action_type=ActionType.REISSUE,
        title="Renew Expiring Certificate",
        description="Certificate is expiring soon or has already expired.",
        solution="Request and install a new certificate before the current one expires.",
        default_effort=EffortLevel.LOW,
        pqc_relevance=False,
        classical_relevance=True,
    ),
    
    # ── Quantum Migration (PQC) ─────────────────────────────────────
    RecommendationKBEntry(
        recommendation_id="kb-pqc-kex-hybrid",
        finding_type="vulnerable_key_exchange",
        algorithm="ECDHE",  # This matches the canonical algorithm name
        track=RoadmapTrack.QUANTUM_MIGRATION,
        action_type=ActionType.INTRODUCE_HYBRID,
        title="Migrate ECDH to Hybrid ML-KEM",
        description="Classical ECDHE is vulnerable to Harvest Now, Decrypt Later (HNDL) attacks via Shor's algorithm.",
        solution="Enable hybrid key exchange (e.g., X25519-MLKEM768) in the TLS library or load balancer.",
        prerequisites=["Library/load balancer must support hybrid KEMs (e.g. OpenSSL 3.2+ with OQS provider or AWS ALBs)."],
        default_effort=EffortLevel.MEDIUM,
        risk_reduction="Protects against future quantum decryption of recorded traffic.",
        pqc_relevance=True,
        classical_relevance=False,
        validation_steps=["Verify server selects hybrid KEM when client advertises support (e.g., using a PQC-enabled curl)."]
    ),
    RecommendationKBEntry(
        recommendation_id="kb-pqc-kex-hybrid-rsa",
        finding_type="vulnerable_key_exchange",
        algorithm="RSA",
        track=RoadmapTrack.QUANTUM_MIGRATION,
        action_type=ActionType.REPLACE,
        title="Migrate RSA Key Exchange to Hybrid ML-KEM",
        description="RSA key exchange lacks forward secrecy and is vulnerable to HNDL.",
        solution="First transition to ECDHE for forward secrecy, then enable hybrid KEM.",
        prerequisites=["Update server to support ECDHE"],
        default_effort=EffortLevel.HIGH,
        pqc_relevance=True,
        classical_relevance=True,
    ),
    RecommendationKBEntry(
        recommendation_id="kb-pqc-sig-migrate",
        finding_type="vulnerable_signature",
        algorithm="RSA", # For signatures
        track=RoadmapTrack.QUANTUM_MIGRATION,
        action_type=ActionType.MIGRATE,
        title="Migrate RSA Signatures to ML-DSA",
        description="RSA signatures will become forgeable by a CRQC.",
        solution="Plan migration to ML-DSA (Dilithium) or SLH-DSA (SPHINCS+) for long-lived certificates.",
        prerequisites=["Ensure PKI infrastructure can issue and validate PQC certificates.", "Verify client compatibility."],
        default_effort=EffortLevel.HIGH,
        pqc_relevance=True,
        classical_relevance=False,
    )
]

def get_recommendations_for_finding(finding_type: str, algorithm: Optional[str] = None) -> List[RecommendationKBEntry]:
    """Retrieves relevant KB entries for a finding type, optionally filtered by algorithm."""
    results = []
    for kb in KNOWLEDGE_BASE:
        if kb.finding_type == finding_type:
            if algorithm and kb.algorithm and kb.algorithm.upper() != algorithm.upper():
                continue
            results.append(kb)
            
    # Fallback/default logic if no exact KB entry matches
    if not results:
        # Generate a generic fallback
        track = RoadmapTrack.CLASSICAL_SECURITY
        action = ActionType.CONFIGURE
        pqc = False
        
        if algorithm and "vulnerable" in finding_type:
            track = RoadmapTrack.QUANTUM_MIGRATION
            action = ActionType.MIGRATE
            pqc = True
            
        results.append(RecommendationKBEntry(
            recommendation_id=f"kb-generic-{finding_type}",
            finding_type=finding_type,
            title=f"Remediate {finding_type.replace('_', ' ').title()}",
            description="A generic remediation is required based on scan findings.",
            solution="Investigate the finding details and apply vendor-recommended patches or configuration changes.",
            track=track,
            action_type=action,
            pqc_relevance=pqc,
            classical_relevance=not pqc
        ))
        
    return results
