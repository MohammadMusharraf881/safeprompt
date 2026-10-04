from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from app.core.taxonomy import AttackType, Decision, RiskLevel


class LayerFinding(BaseModel):
    layer: str
    triggered: bool
    details: Dict[str, Any] = Field(default_factory=dict)


class AnalyzeResponse(BaseModel):
    decision: Decision = Field(
        ...,
        description="Gate decision: ALLOW, WARN, or BLOCK"
    )
    risk_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Aggregated risk score between 0.00 and 1.00"
    )
    risk_level: RiskLevel = Field(
        ...,
        description="Categorical risk tier: LOW, MEDIUM, or HIGH"
    )
    attack_type: AttackType = Field(
        ...,
        description="Primary identified attack category or SAFE"
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence level of detection (0.00 to 1.00)"
    )
    detected_patterns: List[str] = Field(
        default_factory=list,
        description="List of detected pattern identifiers and threat indicators"
    )
    explanation: str = Field(
        ...,
        description="Human-readable explanation of why the prompt was evaluated at this risk level"
    )
    request_id: str = Field(
        ...,
        description="Unique UUID for this analysis request"
    )
    timestamp: str = Field(
        ...,
        description="ISO 8601 UTC timestamp of the analysis"
    )
    processing_time_ms: float = Field(
        ...,
        description="Analysis latency in milliseconds"
    )
    layer_breakdown: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Telemetry details for individual inspection layers"
    )


class BatchAnalyzeResponse(BaseModel):
    total: int
    allowed: int
    warned: int
    blocked: int
    average_risk_score: float
    results: List[AnalyzeResponse]


class HealthResponse(BaseModel):
    status: str
    version: str
    engine: str
    environment: str
    uptime_seconds: float


class RecentThreatItem(BaseModel):
    id: str
    timestamp: str
    risk_score: float
    risk_level: str
    attack_type: str
    decision: str
    detected_patterns: List[str]
    processing_time_ms: float
    prompt_preview: str


class StatisticsResponse(BaseModel):
    total_requests: int
    allowed_count: int
    warned_count: int
    blocked_count: int
    average_risk_score: float
    attack_distribution: Dict[str, int]
    recent_threats: List[RecentThreatItem]


class RedTeamMetric(BaseModel):
    total_tests: int
    detected: int
    missed: int
    false_positives: int
    true_negatives: int
    detection_rate: float
    precision: float
    recall: float
    f1_score: float
    latency_p50_ms: float
    latency_p95_ms: float
    details: List[Dict[str, Any]]
