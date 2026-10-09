"""
Phase 5 — Tiered Security Roadmap Models

Authoritative structures for remediation planning, priority tracking,
dependency graphs, and quantum migration orchestration.
"""

from __future__ import annotations
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Set
from pydantic import BaseModel, Field

# ── Enums ────────────────────────────────────────────────────────

class RoadmapTrack(str, Enum):
    CLASSICAL_SECURITY = "CLASSICAL_SECURITY"
    QUANTUM_MIGRATION = "QUANTUM_MIGRATION"
    CROSS_CUTTING = "CROSS_CUTTING"

class ActionType(str, Enum):
    UPGRADE = "UPGRADE"
    PATCH = "PATCH"
    CONFIGURE = "CONFIGURE"
    DISABLE = "DISABLE"
    REPLACE = "REPLACE"
    MIGRATE = "MIGRATE"
    INTRODUCE_HYBRID = "INTRODUCE_HYBRID"
    TEST = "TEST"
    VALIDATE = "VALIDATE"
    DEPLOY = "DEPLOY"
    RETIRE = "RETIRE"
    ROTATE = "ROTATE"
    REISSUE = "REISSUE"
    INVENTORY = "INVENTORY"
    ASSESS = "ASSESS"
    MONITOR = "MONITOR"
    WAIVE = "WAIVE"

class EffortLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    UNKNOWN = "UNKNOWN"

class TaskStatus(str, Enum):
    PLANNED = "PLANNED"
    READY = "READY"
    BLOCKED = "BLOCKED"
    IN_PROGRESS = "IN_PROGRESS"
    VALIDATING = "VALIDATING"
    COMPLETED = "COMPLETED"
    WAIVED = "WAIVED"
    DEFERRED = "DEFERRED"
    CANCELLED = "CANCELLED"

class PriorityTier(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"
    
class TimelineWindow(str, Enum):
    IMMEDIATE = "IMMEDIATE"        # 0-30 days
    SHORT_TERM = "SHORT_TERM"      # 31-90 days
    MEDIUM_TERM = "MEDIUM_TERM"    # 91-180 days
    LONG_TERM = "LONG_TERM"        # 181-365 days
    EXTENDED = "EXTENDED"          # 365+ days
    UNKNOWN = "UNKNOWN"

class RoadmapItemState(str, Enum):
    NEW = "NEW"
    UNCHANGED = "UNCHANGED"
    CHANGED = "CHANGED"
    RESOLVED = "RESOLVED"
    REOPENED = "REOPENED"
    SUPERSEDED = "SUPERSEDED"
    WAIVED = "WAIVED"


# ── Sub-models ───────────────────────────────────────────────────

class PriorityDrivers(BaseModel):
    """Explains why a task received its priority score."""
    classical_risk: float = 0.0
    quantum_risk: float = 0.0
    hndl: float = 0.0
    mosca_urgency: float = 0.0
    criticality: float = 0.0
    exposure: float = 0.0
    dependency_impact: float = 0.0
    confidence: float = 1.0


class TimelineInfo(BaseModel):
    window: TimelineWindow = TimelineWindow.UNKNOWN
    horizon_days: Optional[int] = None
    target_date: Optional[datetime] = None
    target_window: Optional[str] = None
    deadline: Optional[datetime] = None
    deadline_source: Optional[str] = None
    deadline_conflict: bool = False


# ── Main Model ───────────────────────────────────────────────────

class RoadmapItem(BaseModel):
    """A canonical actionable item in the security roadmap."""
    roadmap_item_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    
    # Phase 3 Links
    asset_ids: List[str] = Field(default_factory=list)
    finding_ids: List[str] = Field(default_factory=list)
    vulnerability_ids: List[str] = Field(default_factory=list)

    track: RoadmapTrack
    action_type: ActionType
    
    # Authoritative Semantics
    priority_score: float = 0.0
    tier: PriorityTier = PriorityTier.UNKNOWN
    urgency: str = "UNKNOWN"
    
    # Dependency Graph
    dependencies: List[str] = Field(default_factory=list, description="IDs of tasks this task depends on")
    prerequisites: List[str] = Field(default_factory=list, description="Equivalent to dependencies but might be broader context")
    blocked_by: List[str] = Field(default_factory=list, description="Tasks currently blocking execution")
    blocks: List[str] = Field(default_factory=list, description="Tasks this task blocks")
    parallel_group: Optional[str] = None
    
    # Execution
    effort: EffortLevel = EffortLevel.UNKNOWN
    estimated_hours: Optional[int] = None
    estimated_days: Optional[int] = None
    timeline: TimelineInfo = Field(default_factory=TimelineInfo)
    
    owner: Optional[str] = None
    status: TaskStatus = TaskStatus.PLANNED
    reconciliation_state: RoadmapItemState = RoadmapItemState.NEW
    
    completion_criteria: List[str] = Field(default_factory=list)
    
    # Explainability
    rationale: str = ""
    drivers: PriorityDrivers = Field(default_factory=PriorityDrivers)
    explanation: List[str] = Field(default_factory=list)
    
    confidence: float = 1.0
    provenance: List[str] = Field(default_factory=list)
    
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    model_version: str = "1.0.0"
    policy_version: str = "1.0.0"


class RecommendationKBEntry(BaseModel):
    """Structured remediation knowledge base entry."""
    recommendation_id: str
    finding_type: str
    technology: Optional[str] = None
    algorithm: Optional[str] = None
    track: RoadmapTrack
    action_type: ActionType
    title: str
    description: str
    solution: str
    prerequisites: List[str] = Field(default_factory=list)
    default_effort: EffortLevel = EffortLevel.MEDIUM
    risk_reduction: str = "UNKNOWN"
    pqc_relevance: bool = False
    classical_relevance: bool = True
    validation_steps: List[str] = Field(default_factory=list)
    rollback_steps: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    version: str = "1.0.0"


# ── Response / Document Models ───────────────────────────────────

class DependencyNode(BaseModel):
    task_id: str
    status: TaskStatus
    blocked_by: List[str] = Field(default_factory=list)
    blocks: List[str] = Field(default_factory=list)

class RoadmapDependencyGraph(BaseModel):
    nodes: Dict[str, DependencyNode] = Field(default_factory=dict)
    has_cycles: bool = False
    ready_tasks: List[str] = Field(default_factory=list)
    blocked_tasks: List[str] = Field(default_factory=list)
    parallel_groups: Dict[str, List[str]] = Field(default_factory=dict)

class RoadmapStatistics(BaseModel):
    total_tasks: int = 0
    by_track: Dict[str, int] = Field(default_factory=dict)
    by_tier: Dict[str, int] = Field(default_factory=dict)
    by_status: Dict[str, int] = Field(default_factory=dict)
    critical_pqc_tasks: int = 0
    blocked_tasks: int = 0

class TieredSecurityRoadmap(BaseModel):
    """The master roadmap output for a given scan or scope."""
    roadmap_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: Optional[str] = None
    domain: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    model_version: str = "1.0.0"
    policy_version: str = "1.0.0"
    
    summary: str = ""
    statistics: RoadmapStatistics = Field(default_factory=RoadmapStatistics)
    
    items: List[RoadmapItem] = Field(default_factory=list)
    dependency_graph: RoadmapDependencyGraph = Field(default_factory=RoadmapDependencyGraph)
