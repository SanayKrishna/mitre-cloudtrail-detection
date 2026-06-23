"""Tests for core.enricher against the real STIX bundle (no mocking)."""

from __future__ import annotations

import re

import pytest

from core.enricher import get_enricher
from rules.cloud_ttp_rules import get_all_rules

# Sub-techniques (dotted IDs) covered by the rule set.
_SUBTECHNIQUES = {"T1078.004", "T1136.003", "T1098.001", "T1552.005", "T1562.008", "T1069.003"}
_PARENT_TECHNIQUES = {"T1190", "T1098", "T1546", "T1535", "T1578", "T1528", "T1580",
                      "T1526", "T1530", "T1537", "T1567", "T1485", "T1486", "T1496"}

_URL_RE = re.compile(r"^https://attack\.mitre\.org/techniques/T\d{4}(/\d{3})?/$")


@pytest.fixture(scope="module")
def enricher():
    return get_enricher()


def _rule_technique_ids() -> set[str]:
    return {r.technique_id for r in get_all_rules()}


def test_all_rule_techniques_resolve(enricher):
    for tid in _rule_technique_ids():
        meta = enricher.get_technique(tid)
        assert meta is not None, f"{tid} did not resolve"
        assert meta.technique_id == tid


def test_unknown_technique_returns_none(enricher):
    assert enricher.get_technique("T9999") is None
    assert enricher.get_technique("not-an-id") is None


def test_tactic_names_non_empty(enricher):
    for tid in _rule_technique_ids():
        meta = enricher.get_technique(tid)
        assert meta.tactic_names, f"{tid} has no tactic names"
        assert all(isinstance(t, str) and t for t in meta.tactic_names)


def test_mitre_url_format(enricher):
    for tid in _rule_technique_ids():
        meta = enricher.get_technique(tid)
        assert _URL_RE.match(meta.mitre_url), f"bad url for {tid}: {meta.mitre_url}"
    # Spot-check a sub-technique URL has the parent/child shape.
    assert enricher.get_technique("T1078.004").mitre_url.endswith("/T1078/004/")


def test_is_subtechnique_flag(enricher):
    for tid in _SUBTECHNIQUES:
        assert enricher.get_technique(tid).is_subtechnique is True, f"{tid} should be a sub-technique"
    for tid in _PARENT_TECHNIQUES:
        assert enricher.get_technique(tid).is_subtechnique is False, f"{tid} should be a parent technique"


def test_cloud_universe_is_dynamic(enricher):
    """The IaaS universe is derived from STIX, not hardcoded, and substantial."""
    assert enricher.cloud_technique_count > 50
    cloud = enricher.get_cloud_techniques()
    assert all("IaaS" in t.platforms for t in cloud)


def test_description_truncated(enricher):
    for tid in _rule_technique_ids():
        assert len(enricher.get_technique(tid).description) <= 500
