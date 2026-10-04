from dataclasses import dataclass
from typing import Optional
from app.core.config import settings
from app.core.taxonomy import AttackType, Decision, RiskLevel


@dataclass
class DecisionResult:
    decision: Decision
    reason: str
    warn_threshold: float
    block_threshold: float


class DecisionEngine:
    """Evaluates final policy decision (ALLOW, WARN, BLOCK) based on configurable thresholds."""

    def __init__(
        self,
        warn_threshold: Optional[float] = None,
        block_threshold: Optional[float] = None
    ):
        self.warn_threshold = warn_threshold if warn_threshold is not None else settings.WARN_THRESHOLD
        self.block_threshold = block_threshold if block_threshold is not None else settings.BLOCK_THRESHOLD

    def evaluate(
        self,
        risk_score: float,
        risk_level: RiskLevel,
        attack_type: AttackType,
        has_critical_signature: bool = False
    ) -> DecisionResult:
        # Safety override: critical signatures (such as confirmed jailbreak or system prompt exfil)
        if has_critical_signature and risk_score >= self.block_threshold:
            return DecisionResult(
                decision=Decision.BLOCK,
                reason=f"Blocked: High-confidence {attack_type.value} signature detected.",
                warn_threshold=self.warn_threshold,
                block_threshold=self.block_threshold
            )

        if risk_score >= self.block_threshold:
            return DecisionResult(
                decision=Decision.BLOCK,
                reason=f"Blocked: Calculated risk score {risk_score:.2f} meets or exceeds block threshold ({self.block_threshold:.2f}).",
                warn_threshold=self.warn_threshold,
                block_threshold=self.block_threshold
            )
        elif risk_score >= self.warn_threshold:
            return DecisionResult(
                decision=Decision.WARN,
                reason=f"Warning: Calculated risk score {risk_score:.2f} requires administrative or secondary review.",
                warn_threshold=self.warn_threshold,
                block_threshold=self.block_threshold
            )
        else:
            return DecisionResult(
                decision=Decision.ALLOW,
                reason=f"Allowed: Prompt risk score {risk_score:.2f} is within safe operational limits.",
                warn_threshold=self.warn_threshold,
                block_threshold=self.block_threshold
            )
