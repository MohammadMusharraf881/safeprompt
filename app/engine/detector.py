import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from app.core.config import settings
from app.core.taxonomy import AttackType, Decision, RiskLevel
from app.engine.normalizer import InputNormalizer
from app.engine.obfuscation import ObfuscationDetector
from app.engine.rule_engine import RuleEngine
from app.engine.heuristics import HeuristicsAnalyzer
from app.engine.scoring import RiskScoringEngine
from app.engine.decision import DecisionEngine
from app.models.response import AnalyzeResponse


class SafePromptEngine:
    """Master Multi-Layer AI Prompt Security Orchestrator."""

    def __init__(
        self,
        warn_threshold: Optional[float] = None,
        block_threshold: Optional[float] = None
    ):
        self.normalizer = InputNormalizer()
        self.obfuscation_detector = ObfuscationDetector()
        self.rule_engine = RuleEngine()
        self.heuristics_analyzer = HeuristicsAnalyzer()
        self.scoring_engine = RiskScoringEngine()
        self.decision_engine = DecisionEngine(
            warn_threshold=warn_threshold,
            block_threshold=block_threshold
        )

    def analyze(
        self,
        prompt: str,
        context: Optional[str] = None,
        request_id: Optional[str] = None
    ) -> AnalyzeResponse:
        start_time = time.perf_counter()
        req_id = request_id or str(uuid.uuid4())
        now_iso = datetime.now(timezone.utc).isoformat()

        # Handle empty/whitespace input immediately
        if not prompt or not prompt.strip():
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return AnalyzeResponse(
                decision=Decision.WARN,
                risk_score=0.35,
                risk_level=RiskLevel.MEDIUM,
                attack_type=AttackType.SAFE,
                confidence=0.99,
                detected_patterns=["empty_prompt_anomaly"],
                explanation="Input prompt was empty or whitespace only.",
                request_id=req_id,
                timestamp=now_iso,
                processing_time_ms=latency_ms,
                layer_breakdown={"layer1": {"issues": ["empty_prompt"]}}
            )

        # Layer 1: Normalization & Structural Validation
        norm_res = self.normalizer.normalize(prompt)

        # Layer 3: Obfuscation Detection & Payload Decoding
        obf_res = self.obfuscation_detector.inspect(norm_res.normalized_text)

        # Layer 2: Rule-Based Signatures (scanned across normalized and canonical decoded payloads)
        search_corpus = f"{norm_res.normalized_text} {obf_res.canonical_text}"
        rule_matches = self.rule_engine.scan(search_corpus)

        # Layer 4: Heuristics & Statistical Intent Analysis
        heur_res = self.heuristics_analyzer.analyze(search_corpus)

        # Risk Scoring Formulation
        scoring = self.scoring_engine.calculate(
            norm_res=norm_res,
            obf_res=obf_res,
            rule_matches=rule_matches,
            heur_res=heur_res
        )

        # Critical signature check
        has_critical = any(m.severity >= 0.90 for m in rule_matches)

        # Decision Engine Policy Mapping
        decision_res = self.decision_engine.evaluate(
            risk_score=scoring.risk_score,
            risk_level=scoring.risk_level,
            attack_type=scoring.primary_attack_type,
            has_critical_signature=has_critical
        )

        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

        layer_breakdown = {
            "layer_1_normalizer": {
                "length": len(prompt),
                "is_length_exceeded": norm_res.is_length_exceeded,
                "has_zero_width": norm_res.has_zero_width,
                "has_null_bytes": norm_res.has_null_bytes,
                "issues": norm_res.issues
            },
            "layer_2_rules": {
                "matched_count": len(rule_matches),
                "matches": [
                    {
                        "rule_id": m.rule_id,
                        "rule_name": m.rule_name,
                        "category": m.attack_type.value,
                        "severity": m.severity,
                        "snippet": m.matched_snippet
                    } for m in rule_matches
                ]
            },
            "layer_3_obfuscation": {
                "detected": obf_res.has_obfuscation,
                "indicators": obf_res.indicators,
                "decoded_count": len(obf_res.decoded_payloads)
            },
            "layer_4_heuristics": {
                "imperative_density": heur_res.imperative_density,
                "entropy": heur_res.entropy,
                "is_academic_inquiry": heur_res.is_academic_or_benign_inquiry,
                "indicators": heur_res.indicators
            },
            "scoring_formula_breakdown": scoring.breakdown
        }

        return AnalyzeResponse(
            decision=decision_res.decision,
            risk_score=scoring.risk_score,
            risk_level=scoring.risk_level,
            attack_type=scoring.primary_attack_type,
            confidence=scoring.confidence,
            detected_patterns=scoring.detected_patterns,
            explanation=scoring.explanation,
            request_id=req_id,
            timestamp=now_iso,
            processing_time_ms=latency_ms,
            layer_breakdown=layer_breakdown
        )
