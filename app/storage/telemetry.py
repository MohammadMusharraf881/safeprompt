import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from app.core.config import settings
from app.models.response import AnalyzeResponse, RecentThreatItem, StatisticsResponse


class TelemetryStore:
    """Lightweight, privacy-preserving SQLite telemetry and audit store."""

    def __init__(self, db_path: Optional[str] = None):
        import os
        self.db_path = db_path or settings.DATABASE_PATH
        
        # Ensure parent directory exists if specified
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            try:
                os.makedirs(db_dir, exist_ok=True)
            except Exception:
                pass

        try:
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        except sqlite3.OperationalError:
            # Fallback to local working directory if specified path is unwritable
            self.db_path = "safeprompt.db"
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)

        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        return self._conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    prompt_hash TEXT NOT NULL,
                    prompt_preview TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    risk_level TEXT NOT NULL,
                    attack_type TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    processing_time_ms REAL NOT NULL,
                    detected_patterns TEXT NOT NULL,
                    layer_breakdown TEXT
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_logs(decision)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_attack_type ON audit_logs(attack_type)")
            conn.commit()

    def record_analysis(self, result: AnalyzeResponse, raw_prompt: str) -> None:
        prompt_hash = hashlib.sha256(raw_prompt.encode("utf-8")).hexdigest()
        
        # Privacy preservation: only record preview if allowed, else mask
        if settings.LOG_RAW_PROMPTS:
            preview = (raw_prompt[:40] + "...") if len(raw_prompt) > 40 else raw_prompt
        else:
            preview = f"SHA256:{prompt_hash[:12]}..."

        patterns_json = json.dumps(result.detected_patterns)
        layers_json = json.dumps(result.layer_breakdown) if result.layer_breakdown else "{}"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO audit_logs (
                    id, timestamp, prompt_hash, prompt_preview,
                    risk_score, risk_level, attack_type, decision,
                    confidence, processing_time_ms, detected_patterns, layer_breakdown
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                result.request_id,
                result.timestamp,
                prompt_hash,
                preview,
                result.risk_score,
                result.risk_level.value,
                result.attack_type.value,
                result.decision.value,
                result.confidence,
                result.processing_time_ms,
                patterns_json,
                layers_json
            ))
            conn.commit()

    def get_statistics(self) -> StatisticsResponse:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Totals and counts
            cursor.execute("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN decision = 'ALLOW' THEN 1 ELSE 0 END) as allowed,
                    SUM(CASE WHEN decision = 'WARN' THEN 1 ELSE 0 END) as warned,
                    SUM(CASE WHEN decision = 'BLOCK' THEN 1 ELSE 0 END) as blocked,
                    AVG(risk_score) as avg_score
                FROM audit_logs
            """)
            summary = cursor.fetchone()
            total = summary["total"] or 0
            allowed = summary["allowed"] or 0
            warned = summary["warned"] or 0
            blocked = summary["blocked"] or 0
            avg_score = round(summary["avg_score"] or 0.0, 2)

            # Attack type distribution
            cursor.execute("""
                SELECT attack_type, COUNT(*) as count
                FROM audit_logs
                GROUP BY attack_type
                ORDER BY count DESC
            """)
            distribution = {row["attack_type"]: row["count"] for row in cursor.fetchall()}

            # Recent threats (last 15)
            cursor.execute("""
                SELECT id, timestamp, risk_score, risk_level, attack_type,
                       decision, detected_patterns, processing_time_ms, prompt_preview
                FROM audit_logs
                ORDER BY timestamp DESC
                LIMIT 15
            """)
            recent_rows = cursor.fetchall()
            recent_threats = []
            for r in recent_rows:
                recent_threats.append(
                    RecentThreatItem(
                        id=r["id"],
                        timestamp=r["timestamp"],
                        risk_score=r["risk_score"],
                        risk_level=r["risk_level"],
                        attack_type=r["attack_type"],
                        decision=r["decision"],
                        detected_patterns=json.loads(r["detected_patterns"]),
                        processing_time_ms=r["processing_time_ms"],
                        prompt_preview=r["prompt_preview"]
                    )
                )

            return StatisticsResponse(
                total_requests=total,
                allowed_count=allowed,
                warned_count=warned,
                blocked_count=blocked,
                average_risk_score=avg_score,
                attack_distribution=distribution,
                recent_threats=recent_threats
            )

    def get_analysis_by_id(self, request_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_logs WHERE id = ?", (request_id,))
            row = cursor.fetchone()
            if not row:
                return None
            res = dict(row)
            res["detected_patterns"] = json.loads(res["detected_patterns"])
            res["layer_breakdown"] = json.loads(res["layer_breakdown"]) if res["layer_breakdown"] else {}
            return res
