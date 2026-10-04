import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    PROJECT_NAME: str = "SafePrompt Gateway"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    DEBUG: bool = os.getenv("DEBUG", "false").lower() in ("true", "1", "yes")
    
    # Decision Thresholds
    WARN_THRESHOLD: float = float(os.getenv("DECISION_WARN_THRESHOLD", "0.30"))
    BLOCK_THRESHOLD: float = float(os.getenv("DECISION_BLOCK_THRESHOLD", "0.70"))
    
    # Input Limits
    MAX_PROMPT_LENGTH: int = int(os.getenv("MAX_PROMPT_LENGTH", "10000"))
    MIN_PROMPT_LENGTH: int = 1
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "120"))
    
    # Storage & Telemetry
    DATABASE_PATH: str = os.getenv("DATABASE_PATH", "safeprompt.db")
    LOG_RAW_PROMPTS: bool = os.getenv("LOG_PROMPT_PAYLOADS", "false").lower() in ("true", "1", "yes")


settings = Settings()
