# Hybrid rule-based + ML quantum-safety assessment

Operational reference for the ML layer that runs alongside QuantumShield's
rule-based quantum risk engine.

---

## 1. Architecture overview

```
TLS scan rows
    |
    v
crypto_analyzer.analyze()  -->  List[CryptoComponent]
    |                                   |
    v                                   |
quantum_risk_engine.calculate_score()   |
    |                                   |
    v                                   v
QuantumScore (stored in Mongo)     FeatureBuilder.build()
                                        |
                                        v
                                   MLInferenceEngine.predict()
                                        |
                                        v
                                   EnsemblePolicy.decide()
                                        |
                                        v
                                   ShadowStore.save() --> ml_assessments collection
```

The rule engine path is **unchanged**. The ML layer runs in **shadow mode** by
default — it stores assessments but never alters the `quantum_status` returned
to the user.

## 2. Feature schema reference

### Numeric features

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| key_size | int | 0 | Raw key size in bits |
| log_key_size | float | 0.0 | log2(key_size), 0 if key_size <= 0 |
| cert_chain_depth | int | 1 | Number of certs in chain from TLSInfo |
| port | int | 443 | TLS port |

### Boolean features

| Field | Type | Description |
|-------|------|-------------|
| tls_modern | bool | TLS version == 1.3 |
| pqc_kem_observed | bool | From TLSInfo.pqc_kem_observed |
| hybrid_key_exchange | bool | From TLSInfo.hybrid_key_exchange |
| is_symmetric | bool | category in {cipher, hash} |
| is_asymmetric | bool | category in {key_exchange, signature} |
| has_forward_secrecy | bool | "DHE" or "ECDHE" in component name |
| is_known_weak | bool | MD5, RC4, DES, NULL, EXPORT, anon in name |

### Categorical features (label-encoded)

| Field | Mapping |
|-------|---------|
| category_encoded | key_exchange=0, signature=1, cipher=2, hash=3, protocol=4, other=5 |
| tls_version_encoded | 1.0=0, 1.1=1, 1.2=2, 1.3=3, unknown=2 |
| threat_encoded | shor=0, grover=1, hndl=2, none/unknown=3 |

### Rule passthrough

| Field | Description |
|-------|-------------|
| rule_quantum_status_encoded | QUANTUM_SAFE=0, PARTIALLY_SAFE=1, VULNERABLE=2, UNKNOWN=3 |
| rule_confidence | 0.0-1.0, default 0.5 |

### Text hash vector

256-dimensional character n-gram (2+3) term-frequency vector, clipped to max
10 per bucket. Built from `f"{name} {category} {usage_context}".lower()`.

### Metadata (not used as ML features)

| Field | Description |
|-------|-------------|
| feature_schema_version | Semver; bump on any schema change |
| component_id | Optional tracking ID |
| raw_text | Concatenated string before hashing |

## 3. Ensemble decision logic

Priority order (first match wins):

1. **Hard-deny string**: component name contains any token from the hard-deny
   list (default: SSLv2, SSLv3, MD5, RC4, NULL, EXPORT) -> always VULNERABLE,
   confidence=1.0, path=rule_hard.

2. **Rule override_tier == hard_deny**: -> VULNERABLE, path=rule_hard.

3. **Shadow mode** (ML_OVERRIDE_ENABLED=false): use rule label, adjust
   confidence downward by OOD score. If ML and rule disagree,
   path=disagreement_review; otherwise path=rule_ml_agree.

4. **ML override enabled, high P(vulnerable)**: if P(vulnerable) >= threshold
   AND rule is not QUANTUM_SAFE -> VULNERABLE, path=ml_escalate.

5. **ML override enabled, high P(safe)**: if P(safe) >= threshold AND OOD < threshold
   AND rule is not VULNERABLE -> QUANTUM_SAFE, path=ml_escalate.

6. **High uncertainty**: if OOD >= threshold OR |P(safe) - P(vulnerable)| < 0.25
   -> use rule label, cap confidence at 0.55, path=disagreement_review.

7. **Default**: use rule label, reduce confidence by scaled ML entropy.

## 4. How to train a new model

```bash
cd Backend

# 1. Generate training data (silver + synthetic + optional gold)
python -c "
from ml.label_pipeline import LabelPipeline
lp = LabelPipeline()
silver = lp.generate_silver_labels()
synth = lp.generate_synthetic_labels(n=2000)
lp.export_dataset('ml/data/training_data.jsonl', silver=silver, synthetic=synth)
"

# 2. (Optional) Add gold labels
#    Create ml/data/gold_labels.csv with columns: name, category, key_size, usage_context, label, notes
#    Re-export including gold:
# python -c "
# from ml.label_pipeline import LabelPipeline
# lp = LabelPipeline()
# silver = lp.generate_silver_labels()
# synth = lp.generate_synthetic_labels(n=2000)
# gold = lp.load_gold_labels('ml/data/gold_labels.csv')
# lp.export_dataset('ml/data/training_data.jsonl', silver=silver, synthetic=synth, gold=gold)
# "

# 3. Train + evaluate + export ONNX
python -m ml.train_model

# Fails if critical_miss_rate > 0.05
# Output: ml/models/quantum_classifier_v1.onnx + .meta.json + .calibrator.joblib + registry.json
```

## 5. Shadow mode vs override mode

### Shadow mode (default)

- `ML_ENABLED=true`, `ML_OVERRIDE_ENABLED=false`
- ML predictions are computed and stored in `ml_assessments` MongoDB collection
- The user-facing `quantum_status` on CryptoComponent is **never changed**
- Monitor via `/api/ml/metrics` and `/api/ml/disagreements`

### Override mode

- `ML_ENABLED=true`, `ML_OVERRIDE_ENABLED=true`
- ML can change the final verdict according to the ensemble decision logic
- Hard-deny rules still always win (Step 1 of ensemble)
- ML never downgrades a rule's VULNERABLE verdict to SAFE

## 6. Monitoring endpoints

All require authentication (existing `get_current_user` dependency).

| Endpoint | Returns |
|----------|---------|
| `GET /api/ml/health` | model_loaded, model_version, feature_schema_version, inference_healthy |
| `GET /api/ml/metrics` | disagreement_rate_24h, total/disagreement counts, override flag |
| `GET /api/ml/disagreements?limit=20` | Recent disagreements with rule/ML verdicts |
| `GET /api/ml/model-info` | Full registry.json for the loaded model |

Returns **503** if ML engine is not loaded.

## 7. How to add a new feature

1. Add the field to `ComponentFeatureVector` in `ml/feature_builder.py`
2. Populate it in `FeatureBuilder.build()`
3. Add it to `_TABULAR_FIELDS` in `ml/model_trainer.py` and `ml/inference_engine.py`
4. Bump `FEATURE_SCHEMA_VERSION` (e.g. "1.0.0" -> "1.1.0")
5. Retrain the model (old ONNX will fail schema validation)
6. Update this documentation

## 8. Rollback procedure

To disable the ML layer entirely:

```bash
# In .env
ML_ENABLED=false
```

Or delete/rename the ONNX model file. The scan pipeline continues with
rules only. No user-facing behavior changes.

To rollback to a previous model version:

1. Replace `ml/models/quantum_classifier_v1.onnx` + sidecar files with the
   previous version
2. Restart the FastAPI server
3. Verify via `GET /api/ml/model-info`

## 9. Configuration reference

| Variable | Default | Description |
|----------|---------|-------------|
| ML_ENABLED | false | Master switch for the ML layer |
| ML_MODEL_PATH | ml/models/quantum_classifier_v1.onnx | Path to ONNX model |
| ML_OVERRIDE_ENABLED | false | Allow ML to change final verdicts |
| ML_T_HIGH_VULNERABLE | 0.75 | P(vulnerable) threshold for ML escalation |
| ML_T_HIGH_SAFE | 0.75 | P(safe) threshold for ML escalation |
| ML_OOD_THRESHOLD | 0.9 | Entropy threshold for "uncertain" flag |
| ML_HARD_DENY_LIST | SSLv2,SSLv3,MD5,RC4,NULL,EXPORT | Comma-separated hard-deny tokens |

## 10. File map

```
Backend/ml/
  __init__.py          Singleton loading (ml_engine, ensemble_policy, feature_builder)
  config.py            MLConfig (pydantic-settings, env vars)
  feature_builder.py   ComponentFeatureVector + FeatureBuilder
  label_pipeline.py    LabeledExample + silver/synthetic/gold generation
  model_trainer.py     QuantumClassifier (LightGBM + calibration + ONNX export)
  train_model.py       Runnable training script
  inference_engine.py  MLInferenceEngine (ONNX runtime) + MLAssessment
  ensemble.py          EnsemblePolicy + RuleAssessment + EnsembleAssessment
  shadow_store.py      ShadowStore (Mongo ml_assessments collection)
  monitoring.py        FastAPI router (/api/ml/*)
  data/                Training data (JSONL) + gold CSV
  models/              Trained ONNX + registry JSON
  tests/               Unit + integration tests
```
