"""Generic detection rules engine.

The engine is intentionally dumb about ATT&CK: it knows how to compare an
event's ``event_source`` / ``event_name`` against a rule and how to run a
rule's optional ``condition`` callable. It works with ANY set of
:class:`~core.models.DetectionRule` objects.

Contract:
  * The engine MUST NOT modify the event or the rule.
  * The engine MUST NOT enrich -- that happens downstream.
  * A single event MAY match multiple rules (returned as multiple matches).
  * If a condition callable raises, the error is logged and the rule is
    treated as non-matching; the pipeline must never crash on one bad rule.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from core.models import DetectionRule, NormalizedEvent

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RuleMatch:
    """A single (rule, event) match produced by the engine. Internal to the
    detection layer; the alert builder turns it into an :class:`Alert`."""

    rule: DetectionRule
    event: NormalizedEvent


class RulesEngine:
    """Evaluates normalized events against a fixed set of detection rules."""

    def __init__(self, rules: list[DetectionRule]) -> None:
        self._rules = list(rules)
        logger.info("RulesEngine initialised with %d rules", len(self._rules))

    @property
    def rules(self) -> list[DetectionRule]:
        return list(self._rules)

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def evaluate(self, event: NormalizedEvent) -> list[RuleMatch]:
        """Return every rule that matches ``event`` (possibly more than one)."""
        matches: list[RuleMatch] = []
        for rule in self._rules:
            # Step 1: event source must match exactly.
            if event.event_source != rule.event_source:
                continue
            # Step 2: event name must be one the rule cares about.
            if event.event_name not in rule.event_names:
                continue
            # Step 3: run the optional contextual condition, defensively.
            if rule.condition is not None:
                try:
                    if not rule.condition(event):
                        continue
                except Exception:
                    logger.exception(
                        "Condition for rule %s raised on event %s (%s); "
                        "treating as non-match",
                        rule.rule_id,
                        event.event_id,
                        event.event_name,
                    )
                    continue
            # Step 4: it's a match.
            matches.append(RuleMatch(rule=rule, event=event))
        return matches
