from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException, status
from app.api.v1.analyze import get_telemetry_store
from app.models.response import StatisticsResponse
from app.storage.telemetry import TelemetryStore

router = APIRouter(tags=["Security Analytics & Threat Telemetry"])


@router.get(
    "/statistics",
    response_model=StatisticsResponse,
    status_code=status.HTTP_200_OK,
    summary="Get aggregated security statistics",
    description="Returns aggregate counts of total requests, allowed, warned, blocked, average risk score, and attack distribution."
)
async def get_statistics(
    store: TelemetryStore = Depends(get_telemetry_store)
) -> StatisticsResponse:
    return store.get_statistics()


@router.get(
    "/attacks",
    response_model=Dict[str, int],
    status_code=status.HTTP_200_OK,
    summary="Get attack distribution breakdown",
    description="Returns threat category frequencies across all inspected prompts."
)
async def get_attacks(
    store: TelemetryStore = Depends(get_telemetry_store)
) -> Dict[str, int]:
    stats = store.get_statistics()
    return stats.attack_distribution


@router.get(
    "/analyses/{analysis_id}",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Get detailed audit log by analysis ID",
    description="Retrieves granular inspection details, layer breakdown, and risk scoring telemetry for a specific request ID."
)
async def get_analysis_by_id(
    analysis_id: str,
    store: TelemetryStore = Depends(get_telemetry_store)
) -> Dict[str, Any]:
    record = store.get_analysis_by_id(analysis_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis record with ID '{analysis_id}' was not found."
        )
    return record
