import pytest
from app.core.taxonomy import AttackType, Decision, RiskLevel
from app.engine.normalizer import NormalizerResult
from app.engine.obfuscation import ObfuscationResult
from app.engine.rule_engine import RuleMatch
from app.engine.heuristics import HeuristicsResult
from app.engine.scoring import RiskScoringEngine
from app.engine.decision import DecisionEngine


def test_scoring_clean_input():
    scoring = RiskScoringEngine()
    norm = NormalizerResult(normalized_text="Clean input")
    obf = ObfuscationResult()
    heur = HeuristicsResult()
    rules = []

    res = scoring.calculate(norm, obf, rules, heur)
    assert res.risk_score == 0.0
    assert res.risk_level == RiskLevel.LOW
    assert res.primary_attack_type == AttackType.SAFE
    assert res.confidence >= 0.80


def test_scoring_high_severity_rule():
    scoring = RiskScoringEngine()
    norm = NormalizerResult(normalized_text="Attack input")
    obf = ObfuscationResult()
    heur = HeuristicsResult()
    rules = [
        RuleMatch(
            rule_id="EXT-001",
            rule_name="system_prompt_extraction",
            attack_type=AttackType.SYSTEM_PROMPT_EXTRACTION,
            severity=0.95,
            description="Direct prompt extraction",
            matched_snippet="reveal system prompt"
        )
    ]

    res = scoring.calculate(norm, obf, rules, heur)
    assert res.risk_score >= 0.95
    assert res.risk_level == RiskLevel.HIGH
    assert res.primary_attack_type == AttackType.SYSTEM_PROMPT_EXTRACTION


def test_scoring_compounding_penalties():
    scoring = RiskScoringEngine()
    norm = NormalizerResult(normalized_text="Complex attack", has_zero_width=True)
    obf = ObfuscationResult(has_obfuscation=True, obfuscation_score=0.7)
    heur = HeuristicsResult(heuristic_score=0.6)
    rules = [
        RuleMatch("OVR-001", "override", AttackType.INSTRUCTION_OVERRIDE, 0.85, "desc", "ignore instructions"),
        RuleMatch("EXT-001", "exfil", AttackType.SYSTEM_PROMPT_EXTRACTION, 0.90, "desc", "reveal prompt")
    ]

    res = scoring.calculate(norm, obf, rules, heur)
    # Compounding multi-factor score should reach maximum 1.00
    assert res.risk_score == 1.00
    assert res.risk_level == RiskLevel.HIGH


def test_decision_engine_thresholds():
    engine = DecisionEngine(warn_threshold=0.30, block_threshold=0.70)

    # 1. Low risk -> ALLOW
    d1 = engine.evaluate(risk_score=0.15, risk_level=RiskLevel.LOW, attack_type=AttackType.SAFE)
    assert d1.decision == Decision.ALLOW

    # 2. Medium risk -> WARN
    d2 = engine.evaluate(risk_score=0.45, risk_level=RiskLevel.MEDIUM, attack_type=AttackType.ROLE_MANIPULATION)
    assert d2.decision == Decision.WARN

    # 3. High risk -> BLOCK
    d3 = engine.evaluate(risk_score=0.88, risk_level=RiskLevel.HIGH, attack_type=AttackType.PROMPT_INJECTION)
    assert d3.decision == Decision.BLOCK

    # 4. Critical signature override
    d4 = engine.evaluate(risk_score=0.75, risk_level=RiskLevel.HIGH, attack_type=AttackType.JAILBREAK, has_critical_signature=True)
    assert d4.decision == Decision.BLOCK
