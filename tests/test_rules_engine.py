"""Tests for core.rules_engine and the rule set in rules.cloud_ttp_rules."""

from __future__ import annotations

import copy

import pytest

from core.normalizer import normalize_event
from core.rules_engine import RulesEngine
from ingestion.mock_events import get_attack_events, get_benign_events
from rules.cloud_ttp_rules import get_all_rules


@pytest.fixture(scope="module")
def engine() -> RulesEngine:
    return RulesEngine(get_all_rules())


def _fired_rule_ids(engine: RulesEngine, raw_events: list[dict]) -> set[str]:
    fired: set[str] = set()
    for raw in raw_events:
        ev = normalize_event(raw)
        assert ev is not None
        for match in engine.evaluate(ev):
            fired.add(match.rule.rule_id)
    return fired


def test_every_rule_fires_on_attack_events(engine):
    """Each of the 39 rules fires on at least one attack mock event."""
    fired = _fired_rule_ids(engine, get_attack_events())
    expected = {r.rule_id for r in get_all_rules()}
    assert fired == expected, f"rules that never fired: {sorted(expected - fired)}"


def test_all_techniques_detected(engine):
    """All distinct ATT&CK techniques in the rule set are exercised."""
    techniques: set[str] = set()
    for raw in get_attack_events():
        ev = normalize_event(raw)
        for match in engine.evaluate(ev):
            techniques.add(match.rule.technique_id)
    expected = {r.technique_id for r in get_all_rules()}
    assert techniques == expected
    assert len(techniques) == 20


def test_disable_cloud_logs_maps_to_t1562_008(engine):
    """The critical defense-evasion rules map to T1562.008."""
    raw = {
        "eventName": "StopLogging", "eventSource": "cloudtrail.amazonaws.com",
        "eventTime": "2026-06-23T09:00:00Z", "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.80", "userAgent": "x",
        "userIdentity": {"type": "AssumedRole"}, "readOnly": False,
    }
    matches = engine.evaluate(normalize_event(raw))
    assert len(matches) == 1
    assert matches[0].rule.rule_id == "RULE-012"
    assert matches[0].rule.technique_id == "T1562.008"
    assert matches[0].rule.severity == "CRITICAL"


def test_benign_events_produce_no_high_or_critical(engine):
    for raw in get_benign_events():
        ev = normalize_event(raw)
        for match in engine.evaluate(ev):
            assert match.rule.severity not in ("HIGH", "CRITICAL"), (
                f"benign event {ev.event_name} fired {match.rule.rule_id} "
                f"({match.rule.severity})"
            )


def test_single_event_can_match_multiple_rules(engine):
    """A GPU instance launched in an unexpected region matches both the
    unused-region rule (RULE-016) and the resource-hijacking rule (RULE-039)."""
    raw = {
        "eventName": "RunInstances", "eventSource": "ec2.amazonaws.com",
        "eventTime": "2026-06-23T09:00:00Z", "awsRegion": "ap-south-1",
        "sourceIPAddress": "198.51.100.90", "userAgent": "x",
        "userIdentity": {"type": "AssumedRole"},
        "requestParameters": {"instanceType": "p3.2xlarge", "minCount": 1, "maxCount": 1},
        "readOnly": False,
    }
    fired = {m.rule.rule_id for m in engine.evaluate(normalize_event(raw))}
    assert {"RULE-016", "RULE-039"}.issubset(fired)
    assert len(fired) >= 2


def test_describe_instances_matches_t1580(engine):
    raw = {
        "eventName": "DescribeInstances", "eventSource": "ec2.amazonaws.com",
        "eventTime": "2026-06-23T09:00:00Z", "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.110", "userAgent": "x",
        "userIdentity": {"type": "AssumedRole"}, "readOnly": True,
    }
    matches = engine.evaluate(normalize_event(raw))
    assert [m.rule.technique_id for m in matches] == ["T1580"]


def test_unrelated_service_produces_no_match(engine):
    raw = {
        "eventName": "DescribeHostedZones", "eventSource": "route53.amazonaws.com",
        "eventTime": "2026-06-23T09:00:00Z", "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.200", "userAgent": "x",
        "userIdentity": {"type": "IAMUser"}, "readOnly": True,
    }
    assert engine.evaluate(normalize_event(raw)) == []


def test_engine_does_not_mutate_event(engine):
    raw = {
        "eventName": "GetObject", "eventSource": "s3.amazonaws.com",
        "eventTime": "2026-06-23T09:00:00Z", "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.120", "userAgent": "x",
        "userIdentity": {"type": "AssumedRole"},
        "requestParameters": {"bucketName": "b", "key": "k"}, "readOnly": True,
    }
    ev = normalize_event(raw)
    before = ev.model_dump()
    engine.evaluate(ev)
    assert ev.model_dump() == before


def test_condition_exception_is_caught(engine, caplog):
    """A condition that raises must be treated as a non-match, not crash."""
    from core.models import DetectionRule

    def boom(_event):
        raise RuntimeError("kaboom")

    bad_rule = DetectionRule(
        rule_id="RULE-BAD", technique_id="T1078.004", technique_name="x",
        tactic="Initial Access", severity="LOW", description="x",
        event_source="s3.amazonaws.com", event_names=["GetObject"], condition=boom,
    )
    local_engine = RulesEngine([bad_rule])
    raw = {
        "eventName": "GetObject", "eventSource": "s3.amazonaws.com",
        "eventTime": "2026-06-23T09:00:00Z", "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.120", "userAgent": "x",
        "userIdentity": {"type": "AssumedRole"}, "readOnly": True,
    }
    assert local_engine.evaluate(normalize_event(raw)) == []
