"""
Label pipeline for the hybrid ML quantum-safety layer.

Generates silver labels (from rule engine), synthetic mutations, and gold
manual labels — then exports a de-duplicated JSONL training dataset.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import random
import string
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from app.db.models import AlgorithmCategory, CryptoComponent, QuantumStatus
from ml.feature_builder import ComponentFeatureVector, FeatureBuilder

_QSTATUS_TO_LABEL: Dict[str, int] = {
    QuantumStatus.QUANTUM_SAFE.value: 0,
    QuantumStatus.PARTIALLY_SAFE.value: 1,
    QuantumStatus.VULNERABLE.value: 2,
}

_QSTATUS_WEIGHTS: Dict[str, float] = {
    QuantumStatus.QUANTUM_SAFE.value: 0.7,
    QuantumStatus.PARTIALLY_SAFE.value: 0.7,
    QuantumStatus.VULNERABLE.value: 0.9,
}


class LabeledExample(BaseModel):
    feature_vector: ComponentFeatureVector
    label: int
    label_source: str
    confidence_weight: float = 1.0
    raw_component_name: str = ""


_VULNERABLE_BASES = [
    "MD5", "RC4", "DES", "SSLv2", "SSLv3",
    "EXPORT-RSA", "NULL-SHA", "anon-DH", "RC2", "IDEA",
]
_PARTIAL_BASES = [
    "AES-128-GCM", "AES-128-CBC", "AES-192-GCM", "3DES-EDE-CBC",
    "CAMELLIA-128-CBC", "CHACHA20-POLY1305", "AES-128-CCM",
    "ARIA-128-GCM", "SEED-CBC", "AES-128-CFB",
]
_SAFE_BASES = [
    "ML-KEM-768", "ML-KEM-1024", "ML-DSA-65",
    "SLH-DSA-SHA2-128s", "CRYSTALS-Kyber", "NTRU-HPS-2048-509",
    "BIKE-L1", "FrodoKEM-640", "Classic-McEliece", "SPHINCS+",
]

_VENDOR_PREFIXES = ["vendor1-", "vendor2-", "draft-", "exp-", ""]
_VERSION_SUFFIXES = ["-v2", "-2024", "-ietf", "-final", ""]


def _mutate(base: str, rng: random.Random) -> str:
    name = base
    name = rng.choice(_VENDOR_PREFIXES) + name
    name = name + rng.choice(_VERSION_SUFFIXES)
    if rng.random() < 0.3:
        name = name.swapcase()
    if rng.random() < 0.2:
        idx = rng.randint(0, max(0, len(name) - 1))
        name = name[:idx] + " " + name[idx:]
    if rng.random() < 0.2:
        idx = rng.randint(1, max(1, len(name) - 1))
        name = name[:idx] + str(rng.randint(0, 9)) + name[idx:]
    return name


class LabelPipeline:
    def __init__(self, seed: int = 42):
        self._fb = FeatureBuilder()
        self._rng = random.Random(seed)

    def generate_silver_labels(
        self,
        components: Optional[List[CryptoComponent]] = None,
        limit: int = 10000,
    ) -> List[LabeledExample]:
        if components is None:
            components = self._default_silver_components()
        examples: List[LabeledExample] = []
        for comp in components[:limit]:
            qs = comp.quantum_status
            qs_val = qs.value if isinstance(qs, QuantumStatus) else str(qs)
            if qs_val not in _QSTATUS_TO_LABEL:
                continue
            fv = self._fb.build(comp)
            examples.append(
                LabeledExample(
                    feature_vector=fv,
                    label=_QSTATUS_TO_LABEL[qs_val],
                    label_source="silver_rule",
                    confidence_weight=_QSTATUS_WEIGHTS.get(qs_val, 0.7),
                    raw_component_name=comp.name or "",
                )
            )
        return examples

    def generate_synthetic_labels(self, n: int = 2000) -> List[LabeledExample]:
        examples: List[LabeledExample] = []
        total_bases = len(_VULNERABLE_BASES) + len(_PARTIAL_BASES) + len(_SAFE_BASES)
        per_base = max(1, n // total_bases)

        for base in _VULNERABLE_BASES:
            for _ in range(per_base):
                mutated = _mutate(base, self._rng)
                comp = CryptoComponent(
                    name=mutated,
                    category=AlgorithmCategory.CIPHER,
                    quantum_status=QuantumStatus.VULNERABLE,
                )
                fv = self._fb.build(comp)
                examples.append(
                    LabeledExample(
                        feature_vector=fv,
                        label=2,
                        label_source="synthetic",
                        confidence_weight=0.85,
                        raw_component_name=mutated,
                    )
                )

        for base in _PARTIAL_BASES:
            key_size = self._rng.choice([128, 192, 128, 128, 256])
            for _ in range(per_base):
                mutated = _mutate(base, self._rng)
                comp = CryptoComponent(
                    name=mutated,
                    category=AlgorithmCategory.CIPHER,
                    key_size=key_size,
                    quantum_status=QuantumStatus.PARTIALLY_SAFE,
                )
                fv = self._fb.build(comp)
                examples.append(
                    LabeledExample(
                        feature_vector=fv,
                        label=1,
                        label_source="synthetic",
                        confidence_weight=0.85,
                        raw_component_name=mutated,
                    )
                )

        for base in _SAFE_BASES:
            for _ in range(per_base):
                mutated = _mutate(base, self._rng)
                comp = CryptoComponent(
                    name=mutated,
                    category=AlgorithmCategory.KEY_EXCHANGE,
                    quantum_status=QuantumStatus.QUANTUM_SAFE,
                )
                fv = self._fb.build(comp)
                examples.append(
                    LabeledExample(
                        feature_vector=fv,
                        label=0,
                        label_source="synthetic",
                        confidence_weight=0.85,
                        raw_component_name=mutated,
                    )
                )

        self._rng.shuffle(examples)
        return examples[:n]

    def load_gold_labels(self, csv_path: str) -> List[LabeledExample]:
        examples: List[LabeledExample] = []
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                name = row.get("name", "")
                cat_str = row.get("category", "key_exchange")
                try:
                    cat = AlgorithmCategory(cat_str)
                except ValueError:
                    cat = AlgorithmCategory.KEY_EXCHANGE
                comp = CryptoComponent(
                    name=name,
                    category=cat,
                    key_size=int(row["key_size"]) if row.get("key_size") else None,
                    usage_context=row.get("usage_context", ""),
                )
                fv = self._fb.build(comp)
                examples.append(
                    LabeledExample(
                        feature_vector=fv,
                        label=int(row.get("label", 3)),
                        label_source="gold_manual",
                        confidence_weight=1.0,
                        raw_component_name=name,
                    )
                )
        return examples

    def export_dataset(
        self,
        output_path: str,
        silver: Optional[List[LabeledExample]] = None,
        synthetic: Optional[List[LabeledExample]] = None,
        gold: Optional[List[LabeledExample]] = None,
    ) -> None:
        merged: Dict[str, LabeledExample] = {}
        for ex in silver or []:
            merged[ex.raw_component_name] = ex
        for ex in synthetic or []:
            if ex.raw_component_name not in merged:
                merged[ex.raw_component_name] = ex
        for ex in gold or []:
            merged[ex.raw_component_name] = ex

        examples = list(merged.values())
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            for ex in examples:
                f.write(ex.model_dump_json() + "\n")

        counts_label = {0: 0, 1: 0, 2: 0}
        counts_source: Dict[str, int] = {}
        for ex in examples:
            counts_label[ex.label] = counts_label.get(ex.label, 0) + 1
            counts_source[ex.label_source] = counts_source.get(ex.label_source, 0) + 1
        print(f"Exported {len(examples)} examples to {output_path}")
        print(f"  Per-class: SAFE={counts_label[0]}, PARTIAL={counts_label[1]}, VULN={counts_label[2]}")
        print(f"  Per-source: {counts_source}")

    def _default_silver_components(self) -> List[CryptoComponent]:
        rows: List[CryptoComponent] = []
        for name, cat, qs, ks in [
            # QUANTUM_SAFE
            ("ML-KEM-768", AlgorithmCategory.KEY_EXCHANGE, QuantumStatus.QUANTUM_SAFE, 768),
            ("SHA-256", AlgorithmCategory.HASH, QuantumStatus.QUANTUM_SAFE, None),
            ("TLSv1.3", AlgorithmCategory.PROTOCOL, QuantumStatus.QUANTUM_SAFE, None),
            ("Dilithium", AlgorithmCategory.SIGNATURE, QuantumStatus.QUANTUM_SAFE, None),
            ("SPHINCS+", AlgorithmCategory.SIGNATURE, QuantumStatus.QUANTUM_SAFE, None),
            ("ML-DSA-65", AlgorithmCategory.SIGNATURE, QuantumStatus.QUANTUM_SAFE, None),
            # PARTIALLY_SAFE — symmetric ciphers that survive Grover's with margin
            ("AES-256-GCM", AlgorithmCategory.CIPHER, QuantumStatus.PARTIALLY_SAFE, 256),
            ("AES-128-GCM", AlgorithmCategory.CIPHER, QuantumStatus.PARTIALLY_SAFE, 128),
            ("CHACHA20-POLY1305", AlgorithmCategory.CIPHER, QuantumStatus.PARTIALLY_SAFE, 256),
            ("AES-192-CBC", AlgorithmCategory.CIPHER, QuantumStatus.PARTIALLY_SAFE, 192),
            ("CAMELLIA-256-CBC", AlgorithmCategory.CIPHER, QuantumStatus.PARTIALLY_SAFE, 256),
            ("AES-128-CCM", AlgorithmCategory.CIPHER, QuantumStatus.PARTIALLY_SAFE, 128),
            # VULNERABLE
            ("ECDHE", AlgorithmCategory.KEY_EXCHANGE, QuantumStatus.VULNERABLE, None),
            ("RSA", AlgorithmCategory.SIGNATURE, QuantumStatus.VULNERABLE, 2048),
            ("MD5", AlgorithmCategory.HASH, QuantumStatus.VULNERABLE, None),
            ("DES", AlgorithmCategory.CIPHER, QuantumStatus.VULNERABLE, 56),
            ("ECDSA", AlgorithmCategory.SIGNATURE, QuantumStatus.VULNERABLE, 256),
            ("RC4", AlgorithmCategory.CIPHER, QuantumStatus.VULNERABLE, 128),
        ]:
            rows.append(
                CryptoComponent(name=name, category=cat, quantum_status=qs, key_size=ks)
            )
        return rows
