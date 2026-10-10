import json
import os
from typing import List, Optional, Dict
from pydantic import BaseModel, Field

class PerformanceProfile(BaseModel):
    operation: Optional[str] = None
    metric: str = Field(alias="metric_name")
    value: float = Field(alias="metric_value")
    unit: str
    implementation: Optional[str] = None
    library_version: Optional[str] = None
    hardware: str
    operating_system: Optional[str] = None
    runtime_or_compiler: Optional[str] = None
    measurement_method: Optional[str] = None
    source: str
    source_version: Optional[str] = None
    measured_at: Optional[str] = None
    confidence: float = 1.0

    class Config:
        populate_by_name = True

class CatalogueEntry(BaseModel):
    catalogue_id: str
    name: str
    family: str
    primitive: str
    cryptographic_role: str
    standardization_status: str
    standard_reference: str
    parameter_set: str
    security_category: Optional[int] = None
    public_key_bytes: Optional[int] = None
    private_key_bytes: Optional[int] = None
    ciphertext_bytes: Optional[int] = None
    signature_bytes: Optional[int] = None
    shared_secret_bytes: Optional[int] = None
    performance_profiles: List[PerformanceProfile] = Field(default_factory=list)
    implementation_support: List[str] = Field(default_factory=list)
    protocol_support: List[str] = Field(default_factory=list)
    deployment_constraints: List[str] = Field(default_factory=list)
    data_provenance: List[str] = Field(default_factory=list)

class AlgorithmCatalogue(BaseModel):
    version: str
    algorithms: List[CatalogueEntry]

class CatalogueManager:
    _instance = None
    _catalogue: Optional[AlgorithmCatalogue] = None
    _by_id: Dict[str, CatalogueEntry] = {}
    _by_role: Dict[str, List[CatalogueEntry]] = {}

    @classmethod
    def load(cls, path: str = None):
        if path is None:
            path = os.path.join(os.path.dirname(__file__), "catalogue.json")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            cls._catalogue = AlgorithmCatalogue(**data)
        
        cls._by_id = {}
        cls._by_role = {}
        for algo in cls._catalogue.algorithms:
            cls._by_id[algo.catalogue_id] = algo
            role = algo.cryptographic_role.upper()
            if role not in cls._by_role:
                cls._by_role[role] = []
            cls._by_role[role].append(algo)

    @classmethod
    def get_by_id(cls, catalogue_id: str) -> Optional[CatalogueEntry]:
        if cls._catalogue is None:
            cls.load()
        return cls._by_id.get(catalogue_id)

    @classmethod
    def get_by_role(cls, role: str) -> List[CatalogueEntry]:
        if cls._catalogue is None:
            cls.load()
        return cls._by_role.get(role.upper(), [])

    @classmethod
    def get_all(cls) -> List[CatalogueEntry]:
        if cls._catalogue is None:
            cls.load()
        return cls._catalogue.algorithms
