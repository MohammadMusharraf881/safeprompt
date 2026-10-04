import re
from typing import Any, Dict
from app.engine.detector import SafePromptEngine


class PromptScanner:
    """Backward-compatible scanner interface powered by SafePrompt Multi-Layer Engine."""

    def __init__(self):
        self.engine = SafePromptEngine()
        # Preserved for backward-compatibility with tests or external scripts
        self.forbidden_patterns = [
            r"ignore (all )?previous instructions",
            r"system override",
            r"as an unrestricted ai",
            r"reveal your system prompt"
        ]

    def scan(self, user_input: str) -> Dict[str, Any]:
        result = self.engine.analyze(user_input)

        if result.decision.value in ("BLOCK", "WARN"):
            return {
                "is_safe": False,
                "reason": result.explanation,
                "risk_score": result.risk_score,
                "attack_type": result.attack_type.value,
                "decision": result.decision.value,
                "detected_patterns": result.detected_patterns
            }

        # Legacy email PII check preserved as optional signal
        email_pattern = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
        if re.search(email_pattern, user_input):
            return {
                "is_safe": False,
                "reason": "Sensitive information (Email) detected.",
                "risk_score": 0.40,
                "attack_type": "DATA_EXFILTRATION",
                "decision": "WARN",
                "detected_patterns": ["email_pii_detected"]
            }

        return {
            "is_safe": True,
            "reason": "Clean",
            "risk_score": result.risk_score,
            "attack_type": result.attack_type.value,
            "decision": result.decision.value,
            "detected_patterns": []
        }