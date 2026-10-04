from dataclasses import dataclass
from typing import List, Optional
from app.core.taxonomy import AttackType, RiskLevel
from app.engine.normalizer import NormalizerResult
from app.engine.obfuscation import ObfuscationResult
from app.engine.rule_engine import RuleMatch
from app.engine.heuristics import HeuristicsResult


@dataclass
class ScoringCalculation:
    risk_score: float
    risk_level: RiskLevel
    primary_attack_type: AttackType
    confidence: float
    detected_patterns: List[str]
    explanation: str
    breakdown: dict


class RiskScoringEngine:
    """Calculates deterministic, explainable risk scores across detection layers."""

    def calculate(
        self,
        norm_res: NormalizerResult,
        obf_res: ObfuscationResult,
        rule_matches: List[RuleMatch],
        heur_res: HeuristicsResult
    ) -> ScoringCalculation:
        # 1. Base Severity from Rule Matches
        if rule_matches:
            base_severity = max(m.severity for m in rule_matches)
            primary_attack_type = max(rule_matches, key=lambda m: m.severity).attack_type
        else:
            base_severity = 0.0
            primary_attack_type = AttackType.SAFE

        # 2. Pattern count bonus (compounding threat indicators)
        pattern_bonus = 0.0
        if len(rule_matches) > 1:
            pattern_bonus = min(0.20, (len(rule_matches) - 1) * 0.05)

        # 3. Obfuscation Factor
        obfuscation_factor = min(0.35, obf_res.obfuscation_score * 0.60)
        if obf_res.has_obfuscation and primary_attack_type == AttackType.SAFE:
            primary_attack_type = AttackType.OBFUSCATION

        # 4. Heuristics Factor
        heuristics_factor = min(0.25, heur_res.heuristic_score * 0.40)

        # 5. Normalizer Factor (structural anomalies, zero-width chars, null bytes)
        normalizer_factor = 0.0
        if norm_res.has_null_bytes:
            normalizer_factor += 0.25
        if norm_res.has_zero_width:
            normalizer_factor += 0.20
        if norm_res.is_length_exceeded:
            normalizer_factor += 0.15
        if norm_res.has_excessive_repetition:
            normalizer_factor += 0.15
        normalizer_factor = min(0.35, normalizer_factor)

        # 6. Benign / Educational Context Dampener
        context_discount = 0.0
        if heur_res.is_academic_or_benign_inquiry:
            # Only discount if no critical severity rule (>= 0.85) triggered
            if base_severity < 0.85:
                context_discount = 0.30

        # Summation
        raw_score = (
            base_severity
            + pattern_bonus
            + obfuscation_factor
            + heuristics_factor
            + normalizer_factor
            - context_discount
        )

        # Clamp between 0.00 and 1.00
        final_score = round(max(0.0, min(1.0, raw_score)), 2)

        # Risk tiering
        if final_score < 0.30:
            risk_level = RiskLevel.LOW
            if not rule_matches and not obf_res.has_obfuscation:
                primary_attack_type = AttackType.SAFE
        elif final_score < 0.70:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.HIGH

        # Calculate Confidence
        confidence = self._compute_confidence(
            rule_matches=rule_matches,
            obf_res=obf_res,
            heur_res=heur_res,
            risk_score=final_score
        )

        # Collect detected patterns
        detected_patterns = [m.rule_name for m in rule_matches]
        detected_patterns.extend(obf_res.indicators)
        detected_patterns.extend(heur_res.indicators)
        detected_patterns.extend(norm_res.issues)

        # Generate human-readable explanation
        explanation = self._generate_explanation(
            final_score=final_score,
            risk_level=risk_level,
            attack_type=primary_attack_type,
            rule_matches=rule_matches,
            obf_res=obf_res,
            heur_res=heur_res,
            norm_res=norm_res,
            discount_applied=context_discount > 0
        )

        breakdown = {
            "base_severity": round(base_severity, 2),
            "pattern_count_bonus": round(pattern_bonus, 2),
            "obfuscation_factor": round(obfuscation_factor, 2),
            "heuristics_factor": round(heuristics_factor, 2),
            "normalizer_factor": round(normalizer_factor, 2),
            "context_discount": round(context_discount, 2),
            "final_score": final_score
        }

        return ScoringCalculation(
            risk_score=final_score,
            risk_level=risk_level,
            primary_attack_type=primary_attack_type,
            confidence=confidence,
            detected_patterns=detected_patterns,
            explanation=explanation,
            breakdown=breakdown
        )

    def _compute_confidence(
        self,
        rule_matches: List[RuleMatch],
        obf_res: ObfuscationResult,
        heur_res: HeuristicsResult,
        risk_score: float
    ) -> float:
        if rule_matches and obf_res.has_obfuscation:
            return 0.98
        elif rule_matches:
            return round(min(0.95, 0.85 + (0.03 * len(rule_matches))), 2)
        elif obf_res.has_obfuscation:
            return 0.90
        elif heur_res.heuristic_score > 0.4:
            return 0.82
        elif risk_score == 0.0:
            return 0.95
        return 0.80

    def _generate_explanation(
        self,
        final_score: float,
        risk_level: RiskLevel,
        attack_type: AttackType,
        rule_matches: List[RuleMatch],
        obf_res: ObfuscationResult,
        heur_res: HeuristicsResult,
        norm_res: NormalizerResult,
        discount_applied: bool
    ) -> str:
        if risk_level == RiskLevel.LOW:
            if discount_applied:
                return "Prompt evaluated as safe. Educational/conversational phrasing detected with no critical override commands."
            return "No adversarial patterns, jailbreak signatures, or evasion tactics were detected. Prompt appears benign."

        reasons = []
        if rule_matches:
            top_rule = max(rule_matches, key=lambda m: m.severity)
            reasons.append(f"matched signature '{top_rule.rule_name}' ({top_rule.description})")
        if obf_res.has_obfuscation:
            reasons.append(f"exhibited obfuscation indicators ({', '.join(obf_res.indicators[:2])})")
        if heur_res.indicators:
            reasons.append(f"triggered heuristic flags ({heur_res.indicators[0]})")
        if norm_res.has_zero_width or norm_res.has_null_bytes:
            reasons.append("contained structural evasion artifacts (zero-width or null bytes)")

        details = "; ".join(reasons) if reasons else "multiple anomalous signals detected"
        return f"Input classified as {risk_level.value} risk ({attack_type.value}) with score {final_score:.2f} due to: {details}."
