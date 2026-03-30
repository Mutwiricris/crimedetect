"""
AI Crime Detection Engine — Production FastAPI Application
Compatible with Laravel integration via X-API-Key authentication.
"""

import os
from datetime import datetime, timezone
from typing import Union, Optional, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Request, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security.api_key import APIKeyHeader
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn

from src.features import FeatureExtractor
from src.predictor import CrimeDetector
from src.config import API_KEY, ALLOWED_ORIGINS, PORT

# ── Startup / Shutdown ─────────────────────────────────────────────────────────

detector: Optional[CrimeDetector] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global detector
    detector = CrimeDetector()
    loaded = detector.models_loaded
    unloaded = [k for k, v in loaded.items() if not v]
    if unloaded:
        print(
            f"⚠  Models not found: {unloaded}. "
            "Run `python train.py` to train them first."
        )
    else:
        print("✓ All models loaded successfully.")
    yield
    # Cleanup on shutdown (nothing needed for in-memory models)


# ── App ────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="AI Crime Detection Engine",
    description=(
        "Stateless inference API for detecting Phishing URLs, "
        "Network Intrusions, and Cyberbullying. "
        "Authenticate with the X-API-Key header."
    ),
    version="2.0.0",
    lifespan=lifespan,
)

# CORS — allows Laravel (or any configured origin) to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ── Authentication ────────────────────────────────────────────────────────────

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(key: str = Security(_api_key_header)):
    if key != API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key. Provide X-API-Key header.",
        )
    return key


# ── Request / Response Models ──────────────────────────────────────────────────

class NetworkLog(BaseModel):
    """UNSW-NB15 compatible network flow features."""
    dur: float = Field(0.0, description="Duration of connection")
    spkts: float = Field(0.0, description="Source-to-destination packet count")
    dpkts: float = Field(0.0, description="Destination-to-source packet count")
    sbytes: float = Field(0.0, description="Source-to-destination bytes")
    dbytes: float = Field(0.0, description="Destination-to-source bytes")
    rate: float = Field(0.0, description="Transfer rate")
    sttl: float = Field(0.0, description="Source TTL")
    dttl: float = Field(0.0, description="Destination TTL")
    sload: float = Field(0.0, description="Source bits per second")
    dload: float = Field(0.0, description="Destination bits per second")
    sloss: float = Field(0.0)
    dloss: float = Field(0.0)
    sinpkt: float = Field(0.0)
    dinpkt: float = Field(0.0)
    sjit: float = Field(0.0)
    djit: float = Field(0.0)
    swin: float = Field(0.0)
    dwin: float = Field(0.0)
    ct_srv_src: float = Field(0.0)
    ct_state_ttl: float = Field(0.0)
    ct_dst_ltm: float = Field(0.0)
    ct_src_ltm: float = Field(0.0)
    ct_srv_dst: float = Field(0.0)


class CyberbullyingStats(BaseModel):
    """Structured cyberbullying user-pair statistics."""
    total_messages: float = Field(..., description="Total messages exchanged")
    aggressive_count: float = Field(..., description="Number of aggressive messages")
    intent_to_harm: float = Field(..., description="Intent-to-harm score 0.0–1.0")
    peerness: float = Field(..., description="Peerness score 0.0–1.0")


class AnalyzeRequest(BaseModel):
    type: str = Field(
        ...,
        description="Input type: 'url', 'network', or 'cyberbullying'",
    )
    data: Union[str, NetworkLog, CyberbullyingStats, dict] = Field(
        ...,
        description=(
            "Payload: a URL string for type=url, "
            "a NetworkLog object for type=network, "
            "or a text string / CyberbullyingStats for type=cyberbullying"
        ),
    )


class AnalyzeResponse(BaseModel):
    is_threat: bool
    confidence_score: float
    threat_category: str
    model_used: str
    timestamp: str


class HealthResponse(BaseModel):
    status: str
    models_loaded: dict
    timestamp: str


# ── Helper ─────────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _run_prediction(input_type: str, raw_data: Any) -> AnalyzeResponse:
    try:
        features = FeatureExtractor.process_input(input_type, raw_data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        result = detector.predict(input_type, features)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference error: {e}")

    return AnalyzeResponse(
        is_threat=result["is_threat"],
        confidence_score=result["confidence_score"],
        threat_category=result["threat_category"],
        model_used=result["model_used"],
        timestamp=_now_iso(),
    )


# ── Endpoints ──────────────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse, tags=["Utility"])
async def health():
    """Health check — no auth required. Returns model load status."""
    return HealthResponse(
        status="ok",
        models_loaded=detector.models_loaded if detector else {},
        timestamp=_now_iso(),
    )


@app.post(
    "/analyze",
    response_model=AnalyzeResponse,
    tags=["Detection"],
    summary="Analyze a single input for threats",
)
async def analyze(request: AnalyzeRequest, _key: str = Depends(require_api_key)):
    """
    Analyze one input and return a threat assessment.

    - **type=url**: Pass the full URL as `data` string.
    - **type=network**: Pass a NetworkLog JSON object as `data`.
    - **type=cyberbullying**: Pass a plain text string or CyberbullyingStats object as `data`.
    """
    return _run_prediction(request.type, request.data)


@app.post(
    "/batch",
    response_model=list[AnalyzeResponse],
    tags=["Detection"],
    summary="Analyze multiple inputs in one request",
)
async def batch_analyze(
    requests: list[AnalyzeRequest],
    _key: str = Depends(require_api_key),
):
    """
    Analyze a batch of inputs (max 100). Useful for bulk scanning from Laravel queues.
    """
    if len(requests) > 100:
        raise HTTPException(
            status_code=400, detail="Batch size exceeds 100 items."
        )
    return [_run_prediction(req.type, req.data) for req in requests]


# ── Legacy redirect: keep "text" type working ──────────────────────────────────

@app.exception_handler(422)
async def validation_exception_handler(request: Request, exc):
    """Return clean JSON on validation failures."""
    return JSONResponse(
        status_code=422,
        content={"detail": "Request validation failed", "errors": str(exc.errors())},
    )


# ── Dev server ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=PORT, reload=False, workers=1)
