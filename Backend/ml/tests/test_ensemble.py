"""Tests for EnsemblePolicy — one test per decision branch."""

from __future__ import annotations

import pytest

from app.db.models import AlgorithmCategory, CryptoComponent
from ml.ensemble import EnsemblePolicy, EnsemblePolicyConfig, RuleAssessment
from ml.inference_engine import MLAssessment


def _comp(name: str = "X") -> CryptoComponent:
    return CryptoComponent(name=name, category=AlgorithmCategory.KEY_EXCHANGE)


def _rule(status: str = "VULNERABLE", conf: float = 0.8, tier: str = "none") -> RuleAssessment:
    return RuleAssessment(quantum_status_rule=status, rule_confidence=conf, override_tier=tier)


def _ml(p_safe: float = 0.1, p_partial: float = 0.1, p_vuln: float = 0.8,
        ood: float = 0.3, pred: int = 2) -> MLAssessment:
    return MLAssessment(
        p_safe=p_safe, p_partial=p_partial, p_vulnerable=p_vuln,
        ood_score=ood, predicted_class=pred,
    )


# Branch 1: hard-deny string → always VULNERABLE
def test_hard_deny_string():
    ep = EnsemblePolicy()
    ea = ep.decide(
        _rule("QUANTUM_SAFE", 1.0),
        _ml(p_safe=0.9, p_vuln=0.05, pred=0),
        _comp("RC4-SHA"),
    )
    assert ea.final_quantum_status == "VULNERABLE"
    assert ea.decision_path == "rule_hard"
    assert ea.ensemble_confidence == 1.0
    assert ea.disagreement is True  # ML said safe


# Branch 2: override_tier == hard_deny
def test_override_tier_hard_deny():
    ep = EnsemblePolicy()
    ea = ep.decide(
        _rule("VULNERABLE", 0.95, tier="hard_deny"),
        _ml(p_safe=0.9, p_vuln=0.05),
        _comp("SomeAlgo"),
    )
    assert ea.final_quantum_status == "VULNERABLE"
    assert ea.decision_path == "rule_hard"
    assert ea.ensemble_confidence == 0.95


# Branch 3: shadow mode (ml_override_enabled=False) → rule wins
def test_shadow_mode_rule_wins():
    cfg = EnsemblePolicyConfig(ml_override_enabled=False)
    ep = EnsemblePolicy(cfg)
    ea = ep.decide(
        _rule("QUANTUM_SAFE", 0.8),
        _ml(p_safe=0.1, p_vuln=0.8, pred=2),
        _comp("AES-256"),
    )
    assert ea.final_quantum_status == "QUANTUM_SAFE"
    assert ea.decision_path == "disagreement_review"
    assert ea.notes.startswith("Shadow mode")


# Branch 4: ML override high p_vulnerable
def test_ml_escalate_vulnerable():
    cfg = EnsemblePolicyConfig(ml_override_enabled=True, t_high_vulnerable=0.75)
    ep = EnsemblePolicy(cfg)
    ea = ep.decide(
        _rule("PARTIALLY_SAFE", 0.6),
        _ml(p_safe=0.05, p_vuln=0.85, ood=0.2, pred=2),
        _comp("ECDHE"),
    )
    assert ea.final_quantum_status == "VULNERABLE"
    assert ea.decision_path == "ml_escalate"
    assert ea.ensemble_confidence == pytest.approx(0.85, abs=0.01)


# Branch 5: ML override high p_safe + low OOD
def test_ml_escalate_safe():
    cfg = EnsemblePolicyConfig(ml_override_enabled=True, t_high_safe=0.75, ood_threshold=0.9)
    ep = EnsemblePolicy(cfg)
    ea = ep.decide(
        _rule("PARTIALLY_SAFE", 0.6),
        _ml(p_safe=0.85, p_vuln=0.05, ood=0.2, pred=0),
        _comp("ML-KEM-768"),
    )
    assert ea.final_quantum_status == "QUANTUM_SAFE"
    assert ea.decision_path == "ml_escalate"


# Branch 6: high OOD → disagreement_review, confidence capped
def test_high_ood_disagreement():
    cfg = EnsemblePolicyConfig(ml_override_enabled=True, ood_threshold=0.9)
    ep = EnsemblePolicy(cfg)
    ea = ep.decide(
        _rule("PARTIALLY_SAFE", 0.9),
        _ml(p_safe=0.4, p_vuln=0.35, p_partial=0.25, ood=0.95, pred=0),
        _comp("UnknownAlgo"),
    )
    assert ea.decision_path == "disagreement_review"
    assert ea.ensemble_confidence <= 0.55


# Branch 7: default → rule label, confidence adjusted
def test_default_rule_adjusted():
    cfg = EnsemblePolicyConfig(ml_override_enabled=True, t_high_vulnerable=0.75,
                                t_high_safe=0.75, ood_threshold=0.9)
    ep = EnsemblePolicy(cfg)
    ea = ep.decide(
        _rule("PARTIALLY_SAFE", 0.8),
        _ml(p_safe=0.6, p_vuln=0.1, p_partial=0.3, ood=0.3, pred=0),
        _comp("ECDSA-P256"),
    )
    assert ea.final_quantum_status == "PARTIALLY_SAFE"
    assert ea.decision_path == "rule_ml_agree"
    assert 0 < ea.ensemble_confidence <= 0.8


# Disagreement flag correctness
def test_disagreement_flag_true():
    cfg = EnsemblePolicyConfig(ml_override_enabled=True)
    ep = EnsemblePolicy(cfg)
    ea = ep.decide(
        _rule("PARTIALLY_SAFE", 0.6),
        _ml(p_safe=0.05, p_vuln=0.85, ood=0.2, pred=2),
        _comp("RSA-1024"),
    )
    assert ea.disagreement is True  # rule=PARTIAL, final=VULNERABLE
