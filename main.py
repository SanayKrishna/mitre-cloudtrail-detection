"""FastAPI application entry point.

Wires together the detection components, owns the in-memory alert store, and
exposes the orchestration pipeline that the API routes call. No detection logic
lives in the route handlers -- they delegate to ``app.state.pipeline``.

Run with::

    uvicorn main:app --reload
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse

from api.routes_alerts import router as alerts_router
from api.routes_coverage import router as coverage_router
from api.routes_dashboard import router as dashboard_router
from api.routes_ingest import router as ingest_router
from core.alert_builder import build_alert
from core.enricher import Enricher, get_enricher
from core.models import Alert
from core.normalizer import normalize_event
from core.rules_engine import RulesEngine
from rules.cloud_ttp_rules import get_all_rules

load_dotenv()

logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO),
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger("mitre_detection_engine")


class DetectionPipeline:
    """Orchestrates normalize -> detect -> enrich -> build for the API layer.

    Generated alerts are appended to the shared in-memory store. The store is a
    plain ``list``; this is safe because FastAPI/uvicorn drives our synchronous
    handlers on a single event loop, so there is no concurrent mutation. If the
    app were ever run with multiple workers/threads this would need a lock.
    """

    def __init__(self, engine: RulesEngine, enricher: Enricher, store: list[Alert]) -> None:
        self._engine = engine
        self._enricher = enricher
        self._store = store

    def _detect(self, raw: dict) -> list[Alert]:
        event = normalize_event(raw)
        if event is None:
            return []
        alerts: list[Alert] = []
        for match in self._engine.evaluate(event):
            metadata = self._enricher.get_technique(match.rule.technique_id)
            alert = build_alert(match.rule, event, metadata)
            self._store.append(alert)
            alerts.append(alert)
        return alerts

    def process_one(self, raw: dict) -> list[Alert]:
        """Process a single raw CloudTrail event."""
        return self._detect(raw)

    def process_batch(self, raws: list[dict]) -> tuple[int, list[Alert]]:
        """Process a batch; returns (events_normalized, alerts_generated)."""
        processed = 0
        alerts: list[Alert] = []
        for raw in raws:
            event = normalize_event(raw)
            if event is None:
                continue
            processed += 1
            for match in self._engine.evaluate(event):
                metadata = self._enricher.get_technique(match.rule.technique_id)
                alert = build_alert(match.rule, event, metadata)
                self._store.append(alert)
                alerts.append(alert)
        return processed, alerts


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load STIX data and build the detection components once at startup."""
    logger.info("Starting MITRE ATT&CK Cloud TTP Detection Engine")
    enricher = get_enricher()  # fails fast with a clear error if STIX missing
    engine = RulesEngine(get_all_rules())
    alert_store: list[Alert] = []

    app.state.enricher = enricher
    app.state.engine = engine
    app.state.alert_store = alert_store
    app.state.pipeline = DetectionPipeline(engine, enricher, alert_store)

    logger.info(
        "Ready: %d rules loaded, %d techniques in STIX (%d cloud)",
        engine.rule_count,
        enricher.total_technique_count,
        enricher.cloud_technique_count,
    )
    yield
    logger.info("Shutting down")


app = FastAPI(
    title="MITRE ATT&CK Cloud TTP Detection Engine",
    description="Ingests CloudTrail events, detects ATT&CK Cloud techniques, "
    "enriches with official STIX metadata, and reports coverage.",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(ingest_router)
app.include_router(alerts_router)
app.include_router(coverage_router)
app.include_router(dashboard_router)


@app.get("/", include_in_schema=False)
async def root() -> RedirectResponse:
    return RedirectResponse(url="/dashboard")


@app.get("/health", tags=["health"])
async def health(request: Request) -> JSONResponse:
    return JSONResponse(
        status_code=200,
        content={
            "status": "healthy",
            "rules_loaded": request.app.state.engine.rule_count,
            "techniques_in_stix": request.app.state.enricher.total_technique_count,
            "alerts_in_memory": len(request.app.state.alert_store),
        },
    )
