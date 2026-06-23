"""Tests for core.normalizer."""

from __future__ import annotations

from datetime import datetime

from core.normalizer import normalize_event


def _known_event() -> dict:
    return {
        "eventID": "abc-123",
        "eventTime": "2026-06-23T09:30:00Z",
        "eventName": "GetObject",
        "eventSource": "s3.amazonaws.com",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.23",
        "userAgent": "aws-cli/2.15.0",
        "userIdentity": {
            "type": "AssumedRole",
            "arn": "arn:aws:sts::111122223333:assumed-role/r/s",
            "accountId": "111122223333",
        },
        "requestParameters": {"bucketName": "corp-secrets", "key": "db.sql"},
        "responseElements": None,
        "errorCode": "AccessDenied",
        "errorMessage": "nope",
        "readOnly": True,
    }


def test_all_field_extraction():
    ev = normalize_event(_known_event())
    assert ev is not None
    assert ev.event_id == "abc-123"
    assert isinstance(ev.timestamp, datetime)
    assert ev.timestamp.year == 2026 and ev.timestamp.month == 6 and ev.timestamp.day == 23
    assert ev.event_name == "GetObject"
    assert ev.event_source == "s3.amazonaws.com"
    assert ev.aws_region == "us-east-1"
    assert ev.source_ip == "198.51.100.23"
    assert ev.user_agent == "aws-cli/2.15.0"
    assert ev.user_type == "AssumedRole"
    assert ev.user_arn == "arn:aws:sts::111122223333:assumed-role/r/s"
    assert ev.account_id == "111122223333"
    assert ev.request_params == {"bucketName": "corp-secrets", "key": "db.sql"}
    assert ev.error_code == "AccessDenied"
    assert ev.error_message == "nope"
    assert ev.read_only is True
    # Raw event is preserved verbatim.
    assert ev.raw_event["eventID"] == "abc-123"
    # userIdentity dict preserved.
    assert ev.user_identity["accountId"] == "111122223333"


def test_empty_dict_returns_none():
    assert normalize_event({}) is None


def test_non_dict_returns_none():
    assert normalize_event("not a dict") is None
    assert normalize_event(None) is None


def test_minimal_event_uses_defaults():
    ev = normalize_event({"eventName": "ListBuckets", "eventSource": "s3.amazonaws.com"})
    assert ev is not None
    assert ev.event_name == "ListBuckets"
    assert ev.event_source == "s3.amazonaws.com"
    # Optional fields default safely.
    assert ev.user_arn is None
    assert ev.account_id is None
    assert ev.request_params is None
    assert ev.error_code is None
    assert ev.user_type == "Unknown"
    assert ev.aws_region == "unknown"
    assert ev.read_only is False
    # Missing eventTime defaults to a real datetime rather than crashing.
    assert isinstance(ev.timestamp, datetime)


def test_invalid_event_time_handled():
    ev = normalize_event({
        "eventName": "ConsoleLogin",
        "eventSource": "signin.amazonaws.com",
        "eventTime": "not-a-real-timestamp",
    })
    assert ev is not None
    assert isinstance(ev.timestamp, datetime)


def test_missing_event_name_returns_none():
    assert normalize_event({"eventSource": "s3.amazonaws.com",
                            "eventTime": "2026-06-23T09:30:00Z"}) is None
