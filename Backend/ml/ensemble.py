"""
Ensemble policy: merge rule-based and ML assessments into a final verdict.

Decision priority (7 steps):
  1. Hard-deny string match on component name
  2. Rule override_tier == hard_deny
  3. Shadow mode (ml_override_enabled=False) — always use rule label
  4. ML p_vulnerable >= threshold AND rule is not QUANTUM_SAFE
  5. ML p_safe >= threshold AND low OOD AND rule is not VULNERABLE
  6. High OOD or tight margin — disagreement_review
  7. Default — use rule label, adjust confidence by ML entropy
"""

from __future__ import annotations

import math
from typing import List

from pydantic import BaseModel, Field

from app.db.models import CryptoComponent
from ml.inference_engine import MLAssessment


class EnsemblePolicyConfig(BaseModel):
    ml_override_enabled: bool = False
    t_high_vulnerable: float = 0.75
    t_high_safe: float = 0.75
    ood_threshold: float = 0.9
    hard_deny_statuses: List[str] = Field(
        default_factory=lambda: ["SSLv2", "SSLv3", "MD5", "RC4", "NULL", "EXPORT"]
    )
    rule_confidence_threshold_for_ml: float = 0.7


class RuleAssessment(BaseModel):
    quantum_status_rule: str = "UNKNOWN"
    rule_confidence: float = 0.5
    matched_rules: List[str] = Field(default_factory=list)
    override_tier: str = "none"


class EnsembleAssessment(BaseModel):
    final_quantum_status: str = "UNKNOWN"
    ensemble_confidence: float = 0.0
    decision_path: str = "rule_hard"
    rule_assessment: RuleAssessment = Field(default_factory=RuleAssessment)
    ml_assessment: MLAssessment = Field(default_factory=MLAssessment)
    disagreement: bool = False
    notes: str = ""


def _ml_entropy(ml: MLAssessment) -> float:
    eps = 1e-9
    probs = [ml.p_safe + eps, ml.p_partial + eps, ml.p_vulnerable + eps]
    return -sum(p * math.log(p) for p in probs)


class EnsemblePolicy:
    def __init__(self, config: EnsemblePolicyConfig | None = None) -> None:
        self.cfg = config or EnsemblePolicyConfig()

    def decide(
        self,
        rule_assessment: RuleAssessment,
        ml_assessment: MLAssessment,
        component: CryptoComponent,
    ) -> EnsembleAssessment:
        name_lower = (component.name or "").lower()

        def _finish(status: str, conf: float, path: str, notes: str = "") -> EnsembleAssessment:
            return EnsembleAssessment(
                final_quantum_status=status,
                ensemble_confidence=round(min(max(conf, 0.0), 1.0), 4),
                decision_path=path,
                rule_assessment=rule_assessment,
                ml_assessment=ml_assessment,
                disagreement=(status != rule_assessment.quantum_status_rule),
                notes=notes,
            )

        # 1. Hard-deny string match
        for tok in self.cfg.hard_deny_statuses:
            if tok.lower() in name_lower:
                disag = ml_assessment.p_vulnerable < 0.5
                ea = _finish("VULNERABLE", 1.0, "rule_hard",
                             f"Hard-deny: '{tok}' matched in component name")
                ea.disagreement = disag
                return ea

        # 2. Rule override_tier == hard_deny
        if rule_assessment.override_tier == "hard_deny":
            return _finish(
                "VULNERABLE",
                rule_assessment.rule_confidence,
                "rule_hard",
                "Rule override_tier=hard_deny",
            )

        # 3. Shadow mode
        if not self.cfg.ml_override_enabled:
            ood = ml_assessment.ood_score
            adj = rule_assessment.rule_confidence * (1 - 0.3 * ood)
            ml_agrees = self._ml_agrees(rule_assessment.quantum_status_rule, ml_assessment)
            path = "rule_ml_agree" if ml_agrees else "disagreement_review"
            return _finish(
                rule_assessment.quantum_status_rule,
                adj,
                path,
                "Shadow mode: ML stored but rule verdict used",
            )

        # 4. High p_vulnerable AND rule is not QUANTUM_SAFE
        if (
            ml_assessment.p_vulnerable >= self.cfg.t_high_vulnerable
            and rule_assessment.quantum_status_rule != "QUANTUM_SAFE"
        ):
            return _finish(
                "VULNERABLE",
                ml_assessment.p_vulnerable,
                "ml_escalate",
                "ML high p_vulnerable override",
            )

        # 5. High p_safe AND low OOD AND rule is not VULNERABLE
        if (
            ml_assessment.p_safe >= self.cfg.t_high_safe
            and ml_assessment.ood_score < self.cfg.ood_threshold
            and rule_assessment.quantum_status_rule != "VULNERABLE"
        ):
            return _finish(
                "QUANTUM_SAFE",
                ml_assessment.p_safe,
                "ml_escalate",
                "ML high p_safe override",
            )

        # 6. High OOD or tight margin
        margin = abs(ml_assessment.p_safe - ml_assessment.p_vulnerable)
        if ml_assessment.ood_score >= self.cfg.ood_threshold or margin < 0.25:
            return _finish(
                rule_assessment.quantum_status_rule,
                min(rule_assessment.rule_confidence, 0.55),
                "disagreement_review",
                "High OOD or tight margin",
            )

        # 7. Default: rule label, confidence adjusted by ML entropy
        entropy = _ml_entropy(ml_assessment)
        max_entropy = math.log(3)
        adj = rule_assessment.rule_confidence * (1 - 0.2 * (entropy / max_entropy))
        return _finish(
            rule_assessment.quantum_status_rule,
            adj,
            "rule_ml_agree",
            "Default: rule label, confidence tuned by ML",
        )

    @staticmethod
    def _ml_agrees(rule_status: str, ml: MLAssessment) -> bool:
        ml_pred_map = {0: "QUANTUM_SAFE", 1: "PARTIALLY_SAFE", 2: "VULNERABLE"}
        return ml_pred_map.get(ml.predicted_class, "") == rule_status
