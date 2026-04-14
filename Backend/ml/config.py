"""
ML layer configuration.

All settings are loaded from environment variables with an ``ML_`` prefix.
Defaults keep ML disabled so the existing pipeline is unaffected.
"""

from __future__ import annotations

from typing import List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class MLConfig(BaseSettings):
    ML_ENABLED: bool = False
    ML_MODEL_PATH: str = "ml/models/quantum_classifier_v1.onnx"
    ML_OVERRIDE_ENABLED: bool = False
    ML_T_HIGH_VULNERABLE: float = 0.75
    ML_T_HIGH_SAFE: float = 0.75
    ML_OOD_THRESHOLD: float = 0.9
    ML_HARD_DENY_LIST: str = "SSLv2,SSLv3,MD5,RC4,NULL,EXPORT"

    @property
    def hard_deny_list(self) -> List[str]:
        return [s.strip() for s in self.ML_HARD_DENY_LIST.split(",") if s.strip()]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


ml_config = MLConfig()
