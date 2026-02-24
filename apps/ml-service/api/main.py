"""
Shadow AI Sentinel — ML Classifier Service
FastAPI application with scan endpoint for the proxy service.
"""

import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import structlog

from .classifier import get_classifier, MLDetection, SensitivityLevel

logger = structlog.get_logger()


# ============================================================
# STARTUP / SHUTDOWN
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Pre-load the classifier on startup so first request isn't slow."""
    logger.info("Loading ML classifier on startup...")
    get_classifier()
    logger.info("ML classifier ready.")
    yield
    logger.info("ML service shutting down.")


app = FastAPI(
    title="Shadow AI Sentinel — ML Classifier",
    version="0.1.0",
    lifespan=lifespan,
)


# ============================================================
# REQUEST / RESPONSE MODELS
# ============================================================

class ScanRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50000)
    language: str = Field(default="en", max_length=5)
    context: Optional[str] = Field(default=None, description="Additional context about the text source")


class DetectionResponse(BaseModel):
    entity_type: str
    text: str
    start: int
    end: int
    confidence: float
    source: str
    context_risk_score: str
    redacted_text: str


class ScanResponse(BaseModel):
    detections: list[DetectionResponse]
    combined_risk: str
    scan_duration_ms: float
    model_version: str = "presidio-spacy-v1"


# ============================================================
# ENDPOINTS
# ============================================================

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "ml-classifier",
        "version": "0.1.0",
    }


@app.post("/api/v1/classify", response_model=ScanResponse)
async def classify(request: ScanRequest):
    """
    Run ML classification on input text.
    Returns detected entities with confidence scores and context-aware risk levels.
    """
    classifier = get_classifier()

    try:
        result = classifier.scan(request.text, request.language)
    except Exception as e:
        logger.error("Classification failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Classification error: {str(e)}")

    detections = [
        DetectionResponse(
            entity_type=d.entity_type,
            text=d.text,
            start=d.start,
            end=d.end,
            confidence=round(d.confidence, 3),
            source=d.source,
            context_risk_score=d.context_risk_score.value,
            redacted_text=d.redacted_text,
        )
        for d in result.detections
    ]

    return ScanResponse(
        detections=detections,
        combined_risk=result.combined_risk.value,
        scan_duration_ms=round(result.scan_duration_ms, 2),
    )


@app.post("/api/v1/classify/batch")
async def classify_batch(requests: list[ScanRequest]):
    """Batch classification for multiple texts."""
    classifier = get_classifier()
    results = []

    for req in requests[:20]:  # Max 20 per batch
        try:
            result = classifier.scan(req.text, req.language)
            results.append({
                "detections": [
                    {
                        "entity_type": d.entity_type,
                        "text": d.text,
                        "start": d.start,
                        "end": d.end,
                        "confidence": round(d.confidence, 3),
                        "context_risk_score": d.context_risk_score.value,
                    }
                    for d in result.detections
                ],
                "combined_risk": result.combined_risk.value,
                "scan_duration_ms": round(result.scan_duration_ms, 2),
            })
        except Exception as e:
            results.append({"error": str(e)})

    return {"results": results}


@app.get("/api/v1/supported-entities")
async def supported_entities():
    """List all entity types the classifier can detect."""
    return {
        "entities": [
            {"type": "PERSON", "source": ["presidio", "spacy"], "description": "Person names"},
            {"type": "EMAIL", "source": ["presidio"], "description": "Email addresses"},
            {"type": "PHONE", "source": ["presidio"], "description": "Phone numbers"},
            {"type": "SSN", "source": ["presidio"], "description": "US Social Security Numbers"},
            {"type": "CREDIT_CARD", "source": ["presidio"], "description": "Credit card numbers"},
            {"type": "IBAN", "source": ["presidio"], "description": "International Bank Account Numbers"},
            {"type": "MEDICAL_ID", "source": ["presidio"], "description": "Medical license/NPI numbers"},
            {"type": "ORGANIZATION", "source": ["spacy"], "description": "Organization names"},
            {"type": "LOCATION", "source": ["spacy", "presidio"], "description": "Geographic locations"},
            {"type": "CREDENTIALS", "source": ["presidio"], "description": "Passwords, tokens, secrets"},
            {"type": "FINANCIAL_ACCOUNT", "source": ["presidio", "spacy"], "description": "Bank accounts, routing numbers"},
            {"type": "IP_ADDRESS", "source": ["presidio"], "description": "IP addresses"},
        ]
    }
