"""Event submission endpoints.

These routes are deliberately thin: they parse/validate the request shape and
delegate the whole normalize -> detect -> enrich -> build pipeline to the
shared pipeline object on ``app.state``. No detection logic lives here.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ingest"])


@router.post("/ingest")
async def ingest_events(request: Request) -> JSONResponse:
    """Ingest a JSON array of raw CloudTrail events through the full pipeline."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"detail": "Request body must be valid JSON."})

    if not isinstance(body, list):
        return JSONResponse(
            status_code=400,
            content={"detail": "Request body must be a JSON array of CloudTrail events."},
        )

    pipeline = request.app.state.pipeline
    processed, alerts = pipeline.process_batch(body)
    return JSONResponse(
        status_code=200,
        content={
            "events_processed": processed,
            "alerts_generated": len(alerts),
            "alerts": [a.model_dump(mode="json") for a in alerts],
        },
    )


@router.post("/analyze")
async def analyze_event(request: Request) -> JSONResponse:
    """Run a single raw CloudTrail event through the pipeline (interactive)."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"detail": "Request body must be valid JSON."})

    if not isinstance(body, dict):
        return JSONResponse(
            status_code=400,
            content={"detail": "Request body must be a single CloudTrail event (JSON object)."},
        )

    pipeline = request.app.state.pipeline
    alerts = pipeline.process_one(body)
    return JSONResponse(
        status_code=200,
        content={"alerts": [a.model_dump(mode="json") for a in alerts]},
    )
