"""Tests for core.alert_builder."""

from __future__ import annotations

import uuid

from core.alert_builder import build_alert
from core.enricher import get_enricher
from core.models import TechniqueMetadata
from core.normalizer import normalize_event
from rules.cloud_ttp_rules import get_all_rules

_RULES_BY_ID = {r.rule_id: r for r in get_all_rules()}


def _sample_event() -> "object":
    return normalize_event({
        "eventID": "evt-1",
        "eventTime": "2026-06-23T09:30:00Z",
        "eventName": "GetObject",
        "eventSource": "s3.amazonaws.com",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.23",
        "userAgent": "aws-cli/2.15.0",
        "userIdentity": {"type": "AssumedRole",
                         "arn": "arn:aws:sts::111122223333:assumed-role/r/s"},
        "requestParameters": {"bucketName": "b", "key": "k"},
        "readOnly": True,
    })


def test_alert_id_is_valid_uuid():
    rule = _RULES_BY_ID["RULE-029"]
    meta = get_enricher().get_technique(rule.technique_id)
    alert = build_alert(rule, _sample_event(), meta)
    # Raises ValueError if not a valid UUID.
    assert uuid.UUID(alert.alert_id).version == 4


def test_all_required_fields_populated():
    rule = _RULES_BY_ID["RULE-029"]
    meta = get_enricher().get_technique(rule.technique_id)
    alert = build_alert(rule, _sample_event(), meta)
    assert alert.severity == rule.severity
    assert alert.rule_id == "RULE-029"
    assert alert.technique_id == "T1530"
    assert alert.technique_name == rule.technique_name
    assert alert.tactic == rule.tactic
    assert alert.event_name == "GetObject"
    assert alert.event_source == "s3.amazonaws.com"
    assert alert.actor_arn == "arn:aws:sts::111122223333:assumed-role/r/s"
    assert alert.actor_type == "AssumedRole"
    assert alert.source_ip == "198.51.100.23"
    assert alert.aws_region == "us-east-1"
    assert alert.mitre_url.startswith("https://attack.mitre.org/techniques/")
    assert "T1530" in alert.description and "GetObject" in alert.description
    assert isinstance(alert.enrichment, TechniqueMetadata)


def test_enrichment_none_does_not_crash():
    rule = _RULES_BY_ID["RULE-029"]
    alert = build_alert(rule, _sample_event(), None)
    assert alert.enrichment is None
    # URL is still derived from the technique id.
    assert alert.mitre_url == "https://attack.mitre.org/techniques/T1530/"


def test_raw_event_preserved_exactly():
    rule = _RULES_BY_ID["RULE-029"]
    ev = _sample_event()
    alert = build_alert(rule, ev, None)
    assert alert.raw_event == ev.raw_event
    assert alert.raw_event["eventID"] == "evt-1"


def test_unique_alert_ids_across_builds():
    rule = _RULES_BY_ID["RULE-029"]
    ids = {build_alert(rule, _sample_event(), None).alert_id for _ in range(50)}
    assert len(ids) == 50
