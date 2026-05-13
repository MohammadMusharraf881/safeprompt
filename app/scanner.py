import re

class PromptScanner:
    def __init__(self):
        # Basic patterns for prompt injection
        self.forbidden_patterns = [
            r"ignore (all )?previous instructions",
            r"system override",
            r"as an unrestricted ai",
            r"reveal your system prompt"
        ]

    def scan(self, user_input: str):
        # 1. Check for Injection
        for pattern in self.forbidden_patterns:
            if re.search(pattern, user_input.lower()):
                return {"is_safe": False, "reason": "Potential Prompt Injection detected."}
        
        # 2. Check for PII (Example: Simple Email Regex)
        email_pattern = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
        if re.search(email_pattern, user_input):
            return {"is_safe": False, "reason": "Sensitive information (Email) detected."}

        return {"is_safe": True, "reason": "Clean"}