"""Coverage reporting endpoints.

Coverage is computed dynamically from the STIX data (never hardcoded): the
universe of cloud techniques is every IaaS-tagged technique the enricher
loaded, and a technique is "covered" if at least one detection rule targets it.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from core.enricher import Enricher
from core.models import CoverageReport, DetectionRule

logger = logging.getLogger(__name__)

router = APIRouter(tags=["coverage"])


def build_coverage_report(enricher: Enricher, rules: list[DetectionRule]) -> CoverageReport:
    """Compute detection coverage of the cloud (IaaS) technique universe."""
    rule_technique_ids = {r.technique_id for r in rules}
    universe = enricher.get_cloud_techniques()  # IaaS-tagged techniques

    covered: list[dict] = []
    uncovered: list[dict] = []
    by_tactic: dict[str, dict] = {}

    for tech in universe:
        is_covered = tech.technique_id in rule_technique_ids
        entry = {
            "id": tech.technique_id,
            "name": tech.technique_name,
            "tactic": ", ".join(tech.tactic_names) if tech.tactic_names else "Unknown",
        }
        (covered if is_covered else uncovered).append(entry)

        for tactic in tech.tactic_names or ["Unknown"]:
            stats = by_tactic.setdefault(tactic, {"covered": 0, "total": 0})
            stats["total"] += 1
            if is_covered:
                stats["covered"] += 1

    total = len(universe)
    covered_count = len(covered)
    percentage = round((covered_count / total) * 100, 2) if total else 0.0

    return CoverageReport(
        total_cloud_techniques=total,
        techniques_covered=covered_count,
        coverage_percentage=percentage,
        covered_techniques=sorted(covered, key=lambda e: e["id"]),
        uncovered_techniques=sorted(uncovered, key=lambda e: e["id"]),
        coverage_by_tactic=dict(sorted(by_tactic.items())),
    )


@router.get("/coverage")
async def get_coverage(request: Request) -> JSONResponse:
    """Return the full coverage report."""
    report = build_coverage_report(
        request.app.state.enricher, request.app.state.engine.rules
    )
    return JSONResponse(status_code=200, content=report.model_dump(mode="json"))


@router.get("/coverage/technique/{technique_id}")
async def get_technique_coverage(technique_id: str, request: Request) -> JSONResponse:
    """Return ATT&CK metadata for a technique plus whether a rule covers it."""
    enricher: Enricher = request.app.state.enricher
    metadata = enricher.get_technique(technique_id)
    if metadata is None:
        return JSONResponse(
            status_code=404, content={"detail": "Technique not found in ATT&CK data"}
        )

    rules = [r for r in request.app.state.engine.rules if r.technique_id == technique_id]
    return JSONResponse(
        status_code=200,
        content={
            "metadata": metadata.model_dump(mode="json"),
            "has_detection_rule": bool(rules),
            "rules": [r.model_dump(mode="json") for r in rules],
        },
    )
