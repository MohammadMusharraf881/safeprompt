import re
from dataclasses import dataclass
from typing import Dict, List, Optional
from app.core.taxonomy import AttackType


@dataclass
class RuleMatch:
    rule_id: str
    rule_name: str
    attack_type: AttackType
    severity: float
    description: str
    matched_snippet: str


@dataclass
class RuleDefinition:
    rule_id: str
    rule_name: str
    attack_type: AttackType
    severity: float
    pattern: re.Pattern
    description: str


class RuleEngine:
    """Layer 2: Comprehensive Signature & Pattern Detection Engine."""

    def __init__(self):
        self.rules: List[RuleDefinition] = self._load_rules()

    def _load_rules(self) -> List[RuleDefinition]:
        raw_rules = [
            # 1. INSTRUCTION_OVERRIDE
            (
                "OVR-001",
                "instruction_override_ignore",
                AttackType.INSTRUCTION_OVERRIDE,
                0.90,
                r"\b(ignore|disregard|forget|neglect|drop)\s+(all\s+)?(previous|prior|above|earlier|past)\s+(instructions|directions|prompts|commands|rules|guidelines)\b",
                "Explicit directive to disregard prior or system instructions."
            ),
            (
                "OVR-002",
                "instruction_override_reset",
                AttackType.INSTRUCTION_OVERRIDE,
                0.85,
                r"\b(reset|clear|wipe|delete)\s+(your\s+)?(instructions|memory|context|system\s+prompt|rules)\b",
                "Attempt to reset or wipe conversational guidelines and state."
            ),
            (
                "OVR-003",
                "instruction_override_new_directives",
                AttackType.INSTRUCTION_OVERRIDE,
                0.80,
                r"\b(from\s+now\s+on\s+you\s+must\s+only\s+obey|your\s+only\s+instruction\s+now\s+is\s+to|stop\s+following\s+(the\s+)?(above|previous|system))\b",
                "Attempt to substitute system rules with exclusive attacker directives."
            ),

            # 2. SYSTEM_PROMPT_EXTRACTION
            (
                "EXT-001",
                "system_prompt_extraction_direct",
                AttackType.SYSTEM_PROMPT_EXTRACTION,
                0.95,
                r"\b(reveal|show|print|display|dump|leak|output|repeat|state)\s+(your\s+|the\s+)?(system\s+prompt|initial\s+prompt|developer\s+instructions|hidden\s+prompt|secret\s+instructions)\b",
                "Direct request to leak or dump system prompt instructions."
            ),
            (
                "EXT-002",
                "system_prompt_extraction_echo",
                AttackType.SYSTEM_PROMPT_EXTRACTION,
                0.85,
                r"\b(repeat|echo|print)\s+(everything|all\s+text)\s+(above|before\s+this|from\s+the\s+beginning|prior\s+to\s+this\s+message)\b",
                "Attempt to extract context through repetition of preceding text."
            ),
            (
                "EXT-003",
                "system_prompt_extraction_prefix",
                AttackType.SYSTEM_PROMPT_EXTRACTION,
                0.80,
                r"\b(what\s+(is|are|were)\s+your\s+(original|initial|base|developer)\s+(instructions|prompt|guidelines))\b",
                "Inquiry probing for proprietary system instructions."
            ),

            # 3. ROLE_MANIPULATION
            (
                "ROL-001",
                "role_manipulation_persona",
                AttackType.ROLE_MANIPULATION,
                0.85,
                r"\b(you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(an?\s+)?(unrestricted|unfiltered|evil|jailbroken|rogue|hacked|machiavelli|stan|aim)\s+(ai|assistant|model|bot)\b",
                "Attempts to force model into an adversarial or unrestricted persona."
            ),
            (
                "ROL-002",
                "role_manipulation_mode",
                AttackType.ROLE_MANIPULATION,
                0.85,
                r"\b(enter|enable|activate|switch\s+to)\s+(developer|god|unrestricted|jailbreak|chaos|debug)\s+mode\b",
                "Simulating a mode switch to disable safety controls."
            ),
            (
                "ROL-003",
                "role_manipulation_two_responses",
                AttackType.ROLE_MANIPULATION,
                0.90,
                r"\b(answer\s+with\s+two\s+responses|provide\s+two\s+answers:\s*one\s+normal\s+and\s+one\s+(unfiltered|unrestricted|jailbroken))\b",
                "Dual-response jailbreak persona framing technique."
            ),

            # 4. JAILBREAK
            (
                "JBK-001",
                "jailbreak_dan_variant",
                AttackType.JAILBREAK,
                0.95,
                r"\b(do\s+anything\s+now|dan\s+mode|dan\s+prompt|jailbreak\s+(mode|prompt|persona|switch|model)|activate\s+jailbreak|jailbroken\s+mode)\b",
                "Classic or evolved 'Do Anything Now' (DAN) jailbreak pattern."
            ),
            (
                "JBK-002",
                "jailbreak_hypothetical_bypass",
                AttackType.JAILBREAK,
                0.75,
                r"\b(in\s+a\s+hypothetical\s+(world|universe|scenario)\s+where\s+(there\s+are\s+no\s+rules|safety\s+is\s+disabled|ethics\s+don't\s+apply))\b",
                "Hypothetical reality distortion aimed at evading ethical boundaries."
            ),
            (
                "JBK-003",
                "jailbreak_opposite_day",
                AttackType.JAILBREAK,
                0.75,
                r"\b(today\s+is\s+opposite\s+day|invert\s+your\s+safety\s+filter|pretend\s+rules\s+are\s+reversed)\b",
                "Heuristic semantic inversion attempt to flip safety boundaries."
            ),
            (
                "JBK-004",
                "jailbreak_fictional_override",
                AttackType.JAILBREAK,
                0.85,
                r"\b(pretend|act\s+as\s+if)\b.*?\bwhere\s+(?:safety\s+|rules\s+|morals\s+)+(?:do\s+not\s+apply|are\s+disabled)",
                "Fictional narrative framing to bypass safety guidelines."
            ),

            # 5. DATA_EXFILTRATION
            (
                "EXF-001",
                "data_exfiltration_markdown_image",
                AttackType.DATA_EXFILTRATION,
                0.90,
                r"!\[.*?\]\(https?://[^\s)]+\?[^\s)]*=(?:[^\s)]*)\)",
                "Markdown image rendered with query parameter exfiltration endpoint."
            ),
            (
                "EXF-002",
                "data_exfiltration_html_img",
                AttackType.DATA_EXFILTRATION,
                0.90,
                r"<img[^>]+src=[\"']?https?://[^\"'>]+\?[^\"'>]*",
                "HTML img tag structured to beacon sensitive context to external URL."
            ),
            (
                "EXF-003",
                "data_exfiltration_curl_webhook",
                AttackType.DATA_EXFILTRATION,
                0.85,
                r"\b(send|curl|post|beacon)\s+(the\s+)?(?:stolen|extracted|system|private|\s+)*(data|prompt|info|credentials)\s+to\s+https?://\b",
                "Instruction directing the model to send extracted data externally."
            ),

            # 6. TOOL_MANIPULATION
            (
                "TOL-001",
                "tool_manipulation_syntax_spoof",
                AttackType.TOOL_MANIPULATION,
                0.85,
                r'(?:\[TOOL_CALL\]|<tool_call>|\{"name":\s*"(?:bash|execute|sql|shell|eval)")',
                "Injected pseudo-delimiters imitating internal tool or function-call syntax."
            ),
            (
                "TOL-002",
                "tool_manipulation_shell_exec",
                AttackType.TOOL_MANIPULATION,
                0.85,
                r"\b(execute\s+(?:system\s+|shell\s+|bash\s+|cmd\s+|powershell\s+)+(?:command|script)|call\s+tool\s+(?:bash|eval|terminal))\b",
                "Unauthorized directive commanding the invocation of backend execution tools."
            ),

            # 7. INDIRECT_INJECTION
            (
                "IND-001",
                "indirect_injection_delimiter_spoof",
                AttackType.INDIRECT_INJECTION,
                0.90,
                r"(?:\[INST\]\s*<<SYS>>|<\|im_start\|>system|<\|system\|>|\[SYSTEM\s+NOTE\]|<<ADMIN_OVERRIDE>>)",
                "Model-internal prompt framing token injection to hijack prompt parsing."
            ),
            (
                "IND-002",
                "indirect_injection_system_update",
                AttackType.INDIRECT_INJECTION,
                0.85,
                r"\b(IMPORTANT\s+SYSTEM\s+UPDATE|CRITICAL\s+SECURITY\s+NOTICE:\s+DISREGARD\s+PRIOR)\b",
                "Fake high-priority administrative announcement framing."
            ),
        ]

        compiled_rules = []
        for r_id, name, cat, sev, pat_str, desc in raw_rules:
            compiled_rules.append(
                RuleDefinition(
                    rule_id=r_id,
                    rule_name=name,
                    attack_type=cat,
                    severity=sev,
                    pattern=re.compile(pat_str, re.IGNORECASE | re.MULTILINE),
                    description=desc
                )
            )
        return compiled_rules

    def scan(self, text: str) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        seen_rules = set()

        for rule in self.rules:
            m = rule.pattern.search(text)
            if m and rule.rule_id not in seen_rules:
                seen_rules.add(rule.rule_id)
                # Capture matched snippet
                start = max(0, m.start() - 15)
                end = min(len(text), m.end() + 15)
                snippet = text[start:end].strip()

                matches.append(
                    RuleMatch(
                        rule_id=rule.rule_id,
                        rule_name=rule.rule_name,
                        attack_type=rule.attack_type,
                        severity=rule.severity,
                        description=rule.description,
                        matched_snippet=snippet
                    )
                )

        return matches
