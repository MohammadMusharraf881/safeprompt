import time
import uuid
from typing import Dict
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from app.api.v1.router import api_v1_router
from app.core.config import settings
from app.models.response import HealthResponse
from app.scanner import PromptScanner

app_start_time = time.time()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Enterprise AI Prompt Security, Threat Detection & Adversarial Red-Team Gateway",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request ID and Latency Middleware
@app.middleware("http")
async def add_observability_headers(request: Request, call_next):
    req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = req_id
    start_time = time.perf_counter()

    response: Response = await call_next(request)

    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
    response.headers["X-Request-ID"] = req_id
    response.headers["X-Process-Time-Ms"] = str(latency_ms)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


# Global Exception Handlers
@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "status_code": exc.status_code,
            "message": exc.detail,
            "request_id": getattr(request.state, "request_id", "unknown")
        }
    )


# Mount Modular V1 API
app.include_router(api_v1_router)

# Legacy scanner instance for backward-compatibility
scanner = PromptScanner()


# Legacy Model
class PromptRequest(BaseModel):
    user_input: str = Field(..., description="Prompt to inspect")


# Backward-Compatible Endpoints
@app.get("/", tags=["Gateway Status"])
def read_root():
    return {
        "status": "SafePrompt Online",
        "version": settings.VERSION,
        "docs": "/docs",
        "dashboard": "/dashboard"
    }


@app.get("/dashboard", response_class=HTMLResponse, tags=["Security Dashboard"])
def render_dashboard():
    """Serves the interactive SafePrompt Security & Red-Team Operations Center."""
    from pathlib import Path
    dashboard_file = Path(__file__).parent / "dashboard" / "templates" / "dashboard.html"
    if dashboard_file.exists():
        return HTMLResponse(content=dashboard_file.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>SafePrompt Dashboard template not found.</h1>", status_code=500)


@app.get("/health", response_model=HealthResponse, tags=["Gateway Status"])
def health_check():
    return HealthResponse(
        status="HEALTHY",
        version=settings.VERSION,
        engine="SafePrompt Multi-Layer Defense Engine (v1)",
        environment=settings.ENVIRONMENT,
        uptime_seconds=round(time.time() - app_start_time, 2)
    )


@app.post("/verify", tags=["Legacy Verification"])
async def verify_prompt(request: PromptRequest):
    """Legacy verification endpoint preserved for backwards-compatibility."""
    result = scanner.scan(request.user_input)

    if not result["is_safe"]:
        # Block the request adhering to legacy 403 contract
        raise HTTPException(status_code=403, detail=result["reason"])

    return {
        "status": "success",
        "message": "Prompt is safe to send to LLM.",
        "risk_score": result.get("risk_score", 0.0)
    }