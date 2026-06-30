"""Tests for ingestion.mock_events."""

from __future__ import annotations

from core.normalizer import normalize_event
from ingestion.mock_events import (
    ALL_MOCK_EVENTS,
    get_attack_events,
    get_benign_events,
    get_mock_events,
)

_REQUIRED_FIELDS = (
    "eventID", "eventTime", "eventName", "eventSource",
    "awsRegion", "sourceIPAddress", "userAgent", "userIdentity",
)


def test_every_mock_event_normalizes():
    for raw in get_mock_events():
        ev = normalize_event(raw)
        assert ev is not None, f"failed to normalize {raw.get('eventName')}"


def test_every_mock_event_has_required_fields():
    for raw in get_mock_events():
        for field in _REQUIRED_FIELDS:
            assert field in raw, f"{raw.get('eventName')} missing {field}"
        ui = raw["userIdentity"]
        assert "type" in ui


def test_event_ids_are_unique():
    events = get_mock_events()
    ids = [e["eventID"] for e in events]
    assert len(ids) == len(set(ids))


def test_source_ips_in_test_range():
    for raw in get_mock_events():
        assert raw["sourceIPAddress"].startswith("198.51.100."), raw["eventName"]


def test_read_only_flag_consistency():
    for raw in get_mock_events():
        name = raw["eventName"]
        if name.startswith(("Describe", "List", "Get")):
            assert raw.get("readOnly") is True, f"{name} should be readOnly"


def test_minimum_event_counts():
    # At least 2 events per technique (>=40) plus 5 benign.
    assert len(get_attack_events()) >= 40
    assert len(get_benign_events()) == 5
    assert len(ALL_MOCK_EVENTS) == len(get_attack_events()) + len(get_benign_events())
