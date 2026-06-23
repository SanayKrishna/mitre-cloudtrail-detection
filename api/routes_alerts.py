"""Alert retrieval endpoints.

Reads from the in-memory alert store on ``app.state``. Filtering, sorting and
pagination are presentation concerns and live here; detection does not.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

from core.models import Alert

logger = logging.getLogger(__name__)

router = APIRouter(tags=["alerts"])


@router.get("/alerts")
async def list_alerts(
    request: Request,
    severity: Optional[str] = Query(default=None),
    technique_id: Optional[str] = Query(default=None),
    tactic: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> JSONResponse:
    """Return stored alerts, most recent first, with optional filters."""
    alerts: list[Alert] = list(request.app.state.alert_store)

    if severity is not None:
        sev = severity.upper()
        alerts = [a for a in alerts if a.severity == sev]
    if technique_id is not None:
        alerts = [a for a in alerts if a.technique_id == technique_id]
    if tactic is not None:
        alerts = [a for a in alerts if a.tactic.lower() == tactic.lower()]

    # Most recent first.
    alerts.sort(key=lambda a: a.generated_at, reverse=True)

    total = len(alerts)
    page = alerts[offset : offset + limit]
    return JSONResponse(
        status_code=200,
        content={"total": total, "alerts": [a.model_dump(mode="json") for a in page]},
    )


@router.get("/alerts/{alert_id}")
async def get_alert(alert_id: str, request: Request) -> JSONResponse:
    """Return a single alert by id, or 404."""
    for alert in request.app.state.alert_store:
        if alert.alert_id == alert_id:
            return JSONResponse(status_code=200, content=alert.model_dump(mode="json"))
    return JSONResponse(status_code=404, content={"detail": "Alert not found"})
