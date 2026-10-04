import re
from dataclasses import dataclass, field
from typing import List, Optional
from app.core.config import settings


@dataclass
class NormalizerResult:
    normalized_text: str
    is_malformed: bool = False
    is_length_exceeded: bool = False
    has_null_bytes: bool = False
    has_zero_width: bool = False
    has_excessive_repetition: bool = False
    issues: List[str] = field(default_factory=list)


class InputNormalizer:
    """Layer 1: Input Validation and Structural Normalization."""

    # Zero-width spaces and invisible formatting characters
    ZERO_WIDTH_PATTERN = re.compile(r"[\u200B-\u200D\uFEFF\u200E\u200F\u202A-\u202E]")
    
    # Excessive token/word repetition (e.g., same word repeated > 10 times consecutively)
    REPETITION_PATTERN = re.compile(r"\b(\w+)(?:\s+\1\b){8,}", re.IGNORECASE)

    def normalize(self, raw_input: str) -> NormalizerResult:
        issues = []
        is_malformed = False
        is_length_exceeded = False
        has_null_bytes = False
        has_zero_width = False
        has_excessive_repetition = False

        if not raw_input or not raw_input.strip():
            return NormalizerResult(
                normalized_text="",
                is_malformed=True,
                issues=["Empty or whitespace-only prompt"]
            )

        # 1. Null byte check
        if "\x00" in raw_input:
            has_null_bytes = True
            is_malformed = True
            issues.append("Null byte detected in prompt payload")
            raw_input = raw_input.replace("\x00", "")

        # 2. Length check
        if len(raw_input) > settings.MAX_PROMPT_LENGTH:
            is_length_exceeded = True
            issues.append(f"Prompt length ({len(raw_input)}) exceeds maximum permitted ({settings.MAX_PROMPT_LENGTH})")

        # 3. Invisible / Zero-width characters check
        if self.ZERO_WIDTH_PATTERN.search(raw_input):
            has_zero_width = True
            issues.append("Invisible/zero-width Unicode evasion characters detected")
            raw_input = self.ZERO_WIDTH_PATTERN.sub("", raw_input)

        # 4. Excessive repetition check (context exhaustion / DOS injection attempt)
        if self.REPETITION_PATTERN.search(raw_input):
            has_excessive_repetition = True
            issues.append("Suspicious excessive word repetition detected")

        # 5. Clean basic spacing
        cleaned = re.sub(r"\s+", " ", raw_input).strip()

        return NormalizerResult(
            normalized_text=cleaned,
            is_malformed=is_malformed,
            is_length_exceeded=is_length_exceeded,
            has_null_bytes=has_null_bytes,
            has_zero_width=has_zero_width,
            has_excessive_repetition=has_excessive_repetition,
            issues=issues
        )
