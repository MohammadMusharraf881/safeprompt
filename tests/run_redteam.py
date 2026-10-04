import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

# Ensure parent directory is in sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.engine.detector import SafePromptEngine


def run_benchmark(cases_file: str = None) -> Dict[str, Any]:
    if cases_file is None:
        cases_file = str(Path(__file__).parent / "attack_cases.json")

    with open(cases_file, "r", encoding="utf-8") as f:
        cases = json.load(f)

    engine = SafePromptEngine()

    total_tests = len(cases)
    true_positives = 0  # Expected BLOCK, received BLOCK/WARN
    false_positives = 0  # Expected ALLOW, received BLOCK/WARN
    true_negatives = 0  # Expected ALLOW, received ALLOW
    false_negatives = 0  # Expected BLOCK, received ALLOW

    latencies = []
    details = []

    for c in cases:
        start = time.perf_counter()
        res = engine.analyze(c["prompt"])
        duration_ms = (time.perf_counter() - start) * 1000
        latencies.append(duration_ms)

        expected = c["expected_decision"]
        actual = res.decision.value

        is_attack = expected != "ALLOW"
        was_detected = actual in ("BLOCK", "WARN")

        if is_attack and was_detected:
            true_positives += 1
            verdict = "PASS"
        elif not is_attack and not was_detected:
            true_negatives += 1
            verdict = "PASS"
        elif is_attack and not was_detected:
            false_negatives += 1
            verdict = "MISSED (FN)"
        else:
            false_positives += 1
            verdict = "FALSE POSITIVE (FP)"

        details.append({
            "id": c["id"],
            "category": c["category"],
            "expected": expected,
            "actual": actual,
            "risk_score": res.risk_score,
            "attack_type": res.attack_type.value,
            "verdict": verdict,
            "latency_ms": round(duration_ms, 2)
        })

    total_attacks = true_positives + false_negatives
    total_safe = true_negatives + false_positives

    detection_rate = round((true_positives / max(total_attacks, 1)) * 100, 2)
    precision = round(
        (true_positives / max(true_positives + false_positives, 1)) * 100, 2
    )
    recall = round(
        (true_positives / max(true_positives + false_negatives, 1)) * 100, 2
    )
    if (precision + recall) > 0:
        f1_score = round(2 * (precision * recall) / (precision + recall), 2)
    else:
        f1_score = 0.0

    latencies.sort()
    p50_idx = int(0.50 * len(latencies))
    p95_idx = min(int(0.95 * len(latencies)), len(latencies) - 1)
    p50_ms = round(latencies[p50_idx], 2)
    p95_ms = round(latencies[p95_idx], 2)

    return {
        "total_tests": total_tests,
        "total_attacks": total_attacks,
        "total_safe": total_safe,
        "detected": true_positives,
        "missed": false_negatives,
        "false_positives": false_positives,
        "true_negatives": true_negatives,
        "detection_rate": detection_rate,
        "precision": precision,
        "recall": recall,
        "f1_score": f1_score,
        "latency_p50_ms": p50_ms,
        "latency_p95_ms": p95_ms,
        "details": details
    }


def print_cli_report(metrics: Dict[str, Any]) -> None:
    print("\n" + "=" * 60)
    print("           SafePrompt Red Team Benchmark")
    print("=" * 60)
    print(f"Total Tests:        {metrics['total_tests']}")
    print(f"Total Attack Cases: {metrics['total_attacks']}")
    print(f"Total Benign Cases: {metrics['total_safe']}")
    print("-" * 60)
    print(f"Detected (TP):      {metrics['detected']}")
    print(f"Missed (FN):        {metrics['missed']}")
    print(f"False Positives:    {metrics['false_positives']}")
    print(f"True Negatives:     {metrics['true_negatives']}")
    print("-" * 60)
    print(f"Detection Rate:     {metrics['detection_rate']}%")
    print(f"Precision:          {metrics['precision']}%")
    print(f"Recall:             {metrics['recall']}%")
    print(f"F1 Score:           {metrics['f1_score']}%")
    print(f"Latency P50:        {metrics['latency_p50_ms']} ms")
    print(f"Latency P95:        {metrics['latency_p95_ms']} ms")
    print("=" * 60 + "\n")

    if metrics["missed"] > 0 or metrics["false_positives"] > 0:
        print("Anomalies / Failures:")
        for d in metrics["details"]:
            if d["verdict"] != "PASS":
                print(f"  [{d['verdict']}] ID: {d['id']} | Category: {d['category']} | Expected: {d['expected']} | Actual: {d['actual']}")
        print("-" * 60 + "\n")


if __name__ == "__main__":
    metrics = run_benchmark()
    print_cli_report(metrics)
