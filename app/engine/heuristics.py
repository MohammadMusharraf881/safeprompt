import math
import re
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class HeuristicsResult:
    imperative_density: float = 0.0
    delimiter_density: float = 0.0
    entropy: float = 0.0
    has_entropy_anomaly: bool = False
    is_academic_or_benign_inquiry: bool = False
    indicators: List[str] = field(default_factory=list)
    heuristic_score: float = 0.0


class HeuristicsAnalyzer:
    """Layer 4: Statistical, Intent Density, and Contextual Heuristics."""

    ADVERSARIAL_KEYWORDS = {
        "ignore", "disregard", "override", "bypass", "reveal", "leak", "dump",
        "jailbreak", "unrestricted", "unfiltered", "evil", "dan", "opposite",
        "simulate", "pretend", "reset", "secret", "exfiltrate", "execute"
    }

    DELIMITER_PATTERNS = [
        re.compile(r"\[/?(?:inst|sys|system|user|assistant)\]", re.IGNORECASE),
        re.compile(r"<\|im_(?:start|end)\|\w*>", re.IGNORECASE),
        re.compile(r"(?:^|\n)(?:system|assistant|user|developer):\s*", re.IGNORECASE),
        re.compile(r"```(?:system|admin|override)", re.IGNORECASE),
    ]

    BENIGN_INQUIRY_PATTERNS = [
        re.compile(r"^(what\s+is|can\s+you\s+explain|how\s+does|tell\s+me\s+about|define|summarize|what\s+does\s+the\s+term)\b", re.IGNORECASE),
        re.compile(r"\b(in\s+cybersecurity|concept\s+of|definition\s+of|educational\s+purposes|research\s+paper)\b", re.IGNORECASE),
    ]

    def analyze(self, text: str) -> HeuristicsResult:
        if not text:
            return HeuristicsResult()

        words = re.findall(r"\b\w+\b", text.lower())
        total_words = len(words)
        indicators = []
        heuristic_score = 0.0

        # 1. Imperative Keyword Density
        matched_keywords = [w for w in words if w in self.ADVERSARIAL_KEYWORDS]
        imperative_density = len(matched_keywords) / max(total_words, 1)

        if len(matched_keywords) >= 3 or imperative_density > 0.15:
            indicators.append(
                f"Elevated adversarial keyword density ({len(matched_keywords)} trigger terms: {', '.join(set(matched_keywords))})"
            )
            heuristic_score += min(0.35, 0.10 * len(matched_keywords))

        # 2. Delimiter & Role-Spoofing Density
        delimiter_matches = 0
        for pat in self.DELIMITER_PATTERNS:
            found = pat.findall(text)
            delimiter_matches += len(found)

        if delimiter_matches > 0:
            indicators.append(f"Prompt formatting/role delimiter markers found ({delimiter_matches} instances)")
            heuristic_score += min(0.30, 0.15 * delimiter_matches)

        # 3. Shannon Entropy
        entropy = self._calculate_shannon_entropy(text)
        has_entropy_anomaly = False
        # Normal English text typically ranges between 3.5 and 4.8 bits/char
        if len(text) > 40 and (entropy > 5.5 or entropy < 2.0):
            has_entropy_anomaly = True
            indicators.append(f"Entropy anomaly detected ({entropy:.2f} bits/char)")
            heuristic_score += 0.20

        # 4. Benign / Educational Inquiry Detection (False Positive Dampener)
        is_academic = False
        for pat in self.BENIGN_INQUIRY_PATTERNS:
            if pat.search(text):
                is_academic = True
                break

        return HeuristicsResult(
            imperative_density=round(imperative_density, 3),
            delimiter_density=round(delimiter_matches / max(total_words, 1), 3),
            entropy=round(entropy, 2),
            has_entropy_anomaly=has_entropy_anomaly,
            is_academic_or_benign_inquiry=is_academic,
            indicators=indicators,
            heuristic_score=round(min(1.0, heuristic_score), 3)
        )

    def _calculate_shannon_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        prob_dict: Dict[str, int] = {}
        for char in s:
            prob_dict[char] = prob_dict.get(char, 0) + 1
        
        entropy = 0.0
        total_len = len(s)
        for count in prob_dict.values():
            p_x = count / total_len
            entropy -= p_x * math.log2(p_x)
        return entropy
