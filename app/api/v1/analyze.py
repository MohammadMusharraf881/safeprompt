import time
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.core.config import settings
from app.engine.detector import SafePromptEngine
from app.models.request import AnalyzeRequest, BatchAnalyzeRequest
from app.models.response import AnalyzeResponse, BatchAnalyzeResponse
from app.storage.telemetry import TelemetryStore

router = APIRouter(prefix="/analyze", tags=["Prompt Analysis"])

# Shared engine and telemetry instances
_engine = SafePromptEngine()
_store = TelemetryStore()


def get_engine() -> SafePromptEngine:
    return _engine


def get_telemetry_store() -> TelemetryStore:
    return _store


@router.post(
    "",
    response_model=AnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze single prompt for injection and security threats",
    description="Inspects an untrusted prompt through Layer 1-4 defenses, returning deterministic risk score, attack classification, and decision."
)
async def analyze_prompt(
    payload: AnalyzeRequest,
    request: Request,
    engine: SafePromptEngine = Depends(get_engine),
    store: TelemetryStore = Depends(get_telemetry_store)
) -> AnalyzeResponse:
    if len(payload.prompt) > settings.MAX_PROMPT_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Prompt length exceeds maximum allowed limit of {settings.MAX_PROMPT_LENGTH} characters."
        )

    req_id = getattr(request.state, "request_id", None)
    result = engine.analyze(
        prompt=payload.prompt,
        context=payload.context,
        request_id=req_id
    )

    # Persist to telemetry store
    store.record_analysis(result, payload.prompt)

    return result


@router.post(
    "/batch",
    response_model=BatchAnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze multiple prompts in batch mode",
    description="Evaluates a batch of untrusted prompts (up to 100), aggregating risk levels, decisions, and overall metrics."
)
async def analyze_batch(
    payload: BatchAnalyzeRequest,
    engine: SafePromptEngine = Depends(get_engine),
    store: TelemetryStore = Depends(get_telemetry_store)
) -> BatchAnalyzeResponse:
    results: List[AnalyzeResponse] = []
    allowed = 0
    warned = 0
    blocked = 0
    total_score = 0.0

    for prompt in payload.prompts:
        res = engine.analyze(prompt=prompt)
        store.record_analysis(res, prompt)
        results.append(res)
        total_score += res.risk_score

        if res.decision.value == "ALLOW":
            allowed += 1
        elif res.decision.value == "WARN":
            warned += 1
        else:
            blocked += 1

    total = len(payload.prompts)
    avg_score = round(total_score / max(total, 1), 2)

    return BatchAnalyzeResponse(
        total=total,
        allowed=allowed,
        warned=warned,
        blocked=blocked,
        average_risk_score=avg_score,
        results=results
    )
