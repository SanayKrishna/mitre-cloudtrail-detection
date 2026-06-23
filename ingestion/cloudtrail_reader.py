"""Read raw CloudTrail events from a file/directory or live via boto3.

Both readers return a ``list[dict]`` of raw CloudTrail records in the same
shape the normalizer expects. This module does no normalization or detection.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)


def _extract_records(payload: object) -> list[dict]:
    """Pull CloudTrail records out of a parsed JSON payload.

    Supports the common shapes:
      * ``{"Records": [ ... ]}``  (CloudTrail log file / S3 export)
      * ``[ ... ]``               (bare list of events)
      * ``{ ... }``               (a single event)
    """
    if isinstance(payload, dict) and isinstance(payload.get("Records"), list):
        return [r for r in payload["Records"] if isinstance(r, dict)]
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if isinstance(payload, dict):
        return [payload]
    logger.warning("Unrecognised CloudTrail payload shape: %s", type(payload).__name__)
    return []


def read_from_file(path: str) -> list[dict]:
    """Read CloudTrail records from a single .json file or a directory of them."""
    if os.path.isdir(path):
        records: list[dict] = []
        for name in sorted(os.listdir(path)):
            if name.lower().endswith(".json"):
                records.extend(read_from_file(os.path.join(path, name)))
        logger.info("Read %d records from directory %s", len(records), path)
        return records

    if not os.path.isfile(path):
        raise FileNotFoundError(f"CloudTrail log path not found: {path}")

    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    records = _extract_records(payload)
    logger.info("Read %d records from %s", len(records), path)
    return records


def read_from_aws(
    *,
    region: Optional[str] = None,
    profile: Optional[str] = None,
    max_events: int = 50,
) -> list[dict]:
    """Fetch recent management events live from CloudTrail via boto3.

    Requires valid AWS credentials (resolved by boto3 from the named profile,
    environment, or instance role). The ``CloudTrailEvent`` field returned by
    ``lookup_events`` is a JSON string; we parse it back into a dict so the
    output matches :func:`read_from_file`.
    """
    import boto3  # imported lazily so the rest of the app works without boto3 configured

    region = region or os.getenv("AWS_REGION")
    profile = profile or os.getenv("AWS_PROFILE")

    session = boto3.Session(profile_name=profile, region_name=region)
    client = session.client("cloudtrail")

    records: list[dict] = []
    paginator = client.get_paginator("lookup_events")
    for page in paginator.paginate(PaginationConfig={"MaxItems": max_events}):
        for event in page.get("Events", []):
            raw = event.get("CloudTrailEvent")
            if not raw:
                continue
            try:
                records.append(json.loads(raw))
            except json.JSONDecodeError:
                logger.warning("Could not parse CloudTrailEvent for %s", event.get("EventId"))
    logger.info("Fetched %d live CloudTrail records (region=%s)", len(records), region)
    return records
