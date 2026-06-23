"""Assemble analyst-ready :class:`~core.models.Alert` objects.

Input:  a matched DetectionRule, the NormalizedEvent that triggered it, and
        optional :class:`TechniqueMetadata` enrichment.
Output: a fully populated Alert with a fresh UUID4 id.

Contains no detection logic and no STIX lookups -- it only joins the three
inputs into the final alert shape.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from core.models import Alert, DetectionRule, NormalizedEvent, TechniqueMetadata

logger = logging.getLogger(__name__)


def build_alert(
    rule: DetectionRule,
    event: NormalizedEvent,
    enrichment: Optional[TechniqueMetadata] = None,
) -> Alert:
    """Build an Alert from a (rule, event, enrichment) triple."""
    actor = event.user_arn or event.user_type
    description = (
        f"Detected {rule.technique_name} ({rule.technique_id}): "
        f"{event.event_name} was called by {actor} from "
        f"{event.source_ip} in {event.aws_region}"
    )

    # Prefer the canonical URL from enrichment; fall back to deriving it from
    # the technique id so the alert is never missing a reference link.
    mitre_url = enrichment.mitre_url if enrichment else _fallback_url(rule.technique_id)

    return Alert(
        alert_id=str(uuid.uuid4()),
        generated_at=datetime.now(timezone.utc),
        severity=rule.severity,
        rule_id=rule.rule_id,
        technique_id=rule.technique_id,
        technique_name=rule.technique_name,
        tactic=rule.tactic,
        mitre_url=mitre_url,
        event_name=event.event_name,
        event_source=event.event_source,
        event_time=event.timestamp,
        actor_arn=event.user_arn,
        actor_type=event.user_type,
        source_ip=event.source_ip,
        aws_region=event.aws_region,
        description=description,
        raw_event=event.raw_event,
        enrichment=enrichment,
    )


def _fallback_url(technique_id: str) -> str:
    base = "https://attack.mitre.org/techniques/"
    if "." in technique_id:
        parent, sub = technique_id.split(".", 1)
        return f"{base}{parent}/{sub}/"
    return f"{base}{technique_id}/"
