"""All Pydantic v2 models for the MITRE ATT&CK Cloud TTP Detection Engine.

This module is the single source of truth for every structured data shape that
flows between the ingest -> normalize -> detect -> enrich -> alert layers. No
other module defines Pydantic models.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Callable, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class SeverityEnum(str, Enum):
    """Severity levels for detection rules and alerts.

    Inherits from ``str`` so values serialize cleanly to JSON and compare as
    plain strings (e.g. ``SeverityEnum.HIGH == "HIGH"``).
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class NormalizedEvent(BaseModel):
    """A CloudTrail record reduced to the fields the detection engine needs.

    Produced by :mod:`core.normalizer`. Optional fields are ``None`` when the
    source record omits them (which is normal — fields like ``arn`` or
    ``errorCode`` depend on identity type and outcome).
    """

    event_id: str
    timestamp: datetime
    event_name: str
    event_source: str
    aws_region: str
    source_ip: str
    user_agent: str
    user_identity: dict
    user_type: str
    user_arn: Optional[str] = None
    account_id: Optional[str] = None
    request_params: Optional[dict] = None
    response_elements: Optional[dict] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    read_only: bool = False

    # Preserve the untouched CloudTrail record so downstream layers (alert
    # builder) can attach it for analyst review without re-reading from source.
    raw_event: dict = Field(default_factory=dict)


class DetectionRule(BaseModel):
    """A single detection rule expressed as data.

    The rules engine is generic: it only knows how to compare ``event_source``,
    ``event_names`` and run the optional ``condition`` callable. All
    technique-specific knowledge lives in the rule object itself.
    """

    # arbitrary_types_allowed lets us hold a Python callable as a field value.
    model_config = ConfigDict(arbitrary_types_allowed=True)

    rule_id: str
    technique_id: str
    technique_name: str
    tactic: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    description: str
    event_source: str
    event_names: list[str]
    # The condition is excluded from serialization: callables are not JSON
    # serializable and API responses must not attempt to emit them.
    condition: Optional[Callable[["NormalizedEvent"], bool]] = Field(
        default=None, exclude=True
    )


class TechniqueMetadata(BaseModel):
    """ATT&CK technique metadata resolved from the official STIX bundle."""

    technique_id: str
    technique_name: str
    tactic_names: list[str]
    description: str
    platforms: list[str]
    data_sources: list[str]
    mitre_url: str
    is_subtechnique: bool


class Alert(BaseModel):
    """An analyst-ready alert: the join of a matched rule, its triggering event
    and (optionally) enriched ATT&CK metadata."""

    alert_id: str
    generated_at: datetime
    severity: str
    rule_id: str
    technique_id: str
    technique_name: str
    tactic: str
    mitre_url: str
    event_name: str
    event_source: str
    event_time: datetime
    actor_arn: Optional[str] = None
    actor_type: str
    source_ip: str
    aws_region: str
    description: str
    raw_event: dict
    enrichment: Optional[TechniqueMetadata] = None


class CoverageReport(BaseModel):
    """Detection coverage of cloud (IaaS) ATT&CK techniques."""

    total_cloud_techniques: int
    techniques_covered: int
    coverage_percentage: float
    covered_techniques: list[dict]
    uncovered_techniques: list[dict]
    coverage_by_tactic: dict[str, dict]
