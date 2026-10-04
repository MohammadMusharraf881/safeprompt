from fastapi import APIRouter
from app.api.v1.analyze import router as analyze_router
from app.api.v1.stats import router as stats_router
from app.api.v1.redteam import router as redteam_router

api_v1_router = APIRouter(prefix="/api/v1")

api_v1_router.include_router(analyze_router)
api_v1_router.include_router(stats_router)
api_v1_router.include_router(redteam_router)
