from typing import Any, Dict
from fastapi import APIRouter, status
from tests.run_redteam import run_benchmark

router = APIRouter(prefix="/redteam", tags=["Adversarial Red-Team Benchmark"])


@router.post(
    "/run",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Execute comprehensive red-team adversarial benchmark",
    description="Runs the full adversarial dataset against SafePrompt's Layer 1-4 engines, returning actual detection rate, precision, recall, F1, and latency metrics."
)
async def execute_redteam_benchmark() -> Dict[str, Any]:
    metrics = run_benchmark()
    return metrics
