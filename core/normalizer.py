"""CloudTrail record -> :class:`~core.models.NormalizedEvent`.

The normalizer is deliberately tolerant: real CloudTrail data is messy and a
single malformed record must never crash the pipeline. Anything that cannot be
normalized is logged at WARNING level (with the offending eventName + reason)
and ``None`` is returned so the caller can skip it.

The normalizer contains NO detection logic. It only reshapes data.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from core.models import NormalizedEvent

logger = logging.getLogger(__name__)


def _parse_event_time(value: object) -> Optional[datetime]:
    """Parse a CloudTrail eventTime into a tz-aware datetime.

    Accepts ISO 8601 strings (``2024-01-01T12:00:00Z``) and, defensively,
    values already typed as datetime. Returns ``None`` on failure.
    """
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    # Python's fromisoformat accepts "+00:00" but historically not "Z".
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    # Normalize naive timestamps to UTC for consistent comparisons/sorting.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def normalize_event(raw: object) -> Optional[NormalizedEvent]:
    """Convert a single raw CloudTrail record (dict) to a NormalizedEvent.

    Returns ``None`` (and logs a warning) when the record is not a dict, is
    missing the minimal fields needed to be useful, or has an unparseable
    eventTime.
    """
    if not isinstance(raw, dict):
        logger.warning("Skipping non-dict CloudTrail record of type %s", type(raw).__name__)
        return None

    event_name = raw.get("eventName")
    event_source = raw.get("eventSource")
    if not event_name or not event_source:
        logger.warning(
            "Skipping record missing eventName/eventSource (eventName=%r, eventSource=%r)",
            event_name,
            event_source,
        )
        return None

    timestamp = _parse_event_time(raw.get("eventTime"))
    if timestamp is None:
        # eventTime is missing or unparseable. Rather than drop an otherwise
        # actionable security event, fall back to ingestion time and warn.
        logger.warning(
            "Event %r has missing/unparseable eventTime %r; defaulting to now()",
            event_name,
            raw.get("eventTime"),
        )
        timestamp = datetime.now(timezone.utc)

    # userIdentity is a nested object whose available keys depend on the
    # identity type (IAMUser, AssumedRole, Root, AWSService, ...). Read safely.
    user_identity = raw.get("userIdentity")
    if not isinstance(user_identity, dict):
        user_identity = {}

    user_type = user_identity.get("type") or "Unknown"
    user_arn = user_identity.get("arn")
    account_id = user_identity.get("accountId")

    request_params = raw.get("requestParameters")
    if request_params is not None and not isinstance(request_params, dict):
        request_params = None
    response_elements = raw.get("responseElements")
    if response_elements is not None and not isinstance(response_elements, dict):
        response_elements = None

    try:
        return NormalizedEvent(
            event_id=str(raw.get("eventID") or ""),
            timestamp=timestamp,
            event_name=str(event_name),
            event_source=str(event_source),
            aws_region=str(raw.get("awsRegion") or "unknown"),
            source_ip=str(raw.get("sourceIPAddress") or "unknown"),
            user_agent=str(raw.get("userAgent") or "unknown"),
            user_identity=user_identity,
            user_type=str(user_type),
            user_arn=user_arn,
            account_id=account_id,
            request_params=request_params,
            response_elements=response_elements,
            error_code=raw.get("errorCode"),
            error_message=raw.get("errorMessage"),
            read_only=bool(raw.get("readOnly", False)),
            raw_event=raw,
        )
    except Exception as exc:  # pragma: no cover - defensive last resort
        logger.warning("Failed to build NormalizedEvent for %r: %s", event_name, exc)
        return None
