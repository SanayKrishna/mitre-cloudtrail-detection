"""ATT&CK enrichment: load the official STIX bundle once and resolve technique
metadata by ID.

Responsibilities:
  * Load ``enterprise-attack.json`` exactly once (lazy singleton) using the
    ``stix2`` library.
  * Build a ``dict[str, TechniqueMetadata]`` keyed by ATT&CK technique ID
    (e.g. ``T1078.004``) for O(1) lookup.
  * Expose the set of cloud-relevant (IaaS) techniques for coverage reporting.

The enricher contains NO detection logic. It only resolves metadata.
"""

from __future__ import annotations

import logging
import os
from functools import lru_cache
from typing import Optional

from stix2 import Filter, MemoryStore

from core.models import TechniqueMetadata

logger = logging.getLogger(__name__)

_ATTACK_BASE_URL = "https://attack.mitre.org/techniques/"
_CTI_DOWNLOAD_URL = "https://github.com/mitre/cti"

# Default location of the STIX bundle relative to the project root. Overridable
# via the STIX_DATA_PATH environment variable.
_DEFAULT_STIX_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "enterprise-attack.json",
)


def _tactic_name_from_shortname(shortname: str) -> str:
    """Convert a kill-chain phase shortname to its display tactic name.

    ``"defense-evasion"`` -> ``"Defense Evasion"``.
    """
    return shortname.replace("-", " ").title()


def _build_mitre_url(technique_id: str) -> str:
    """Build the canonical attack.mitre.org URL for a (sub-)technique."""
    if "." in technique_id:
        parent, sub = technique_id.split(".", 1)
        return f"{_ATTACK_BASE_URL}{parent}/{sub}/"
    return f"{_ATTACK_BASE_URL}{technique_id}/"


class Enricher:
    """Loads ATT&CK STIX data and resolves :class:`TechniqueMetadata`."""

    def __init__(self, stix_path: Optional[str] = None) -> None:
        self.stix_path = stix_path or os.getenv("STIX_DATA_PATH", _DEFAULT_STIX_PATH)
        if not os.path.isfile(self.stix_path):
            raise FileNotFoundError(
                f"ATT&CK STIX bundle not found at '{self.stix_path}'. "
                f"Download 'enterprise-attack.json' from {_CTI_DOWNLOAD_URL} "
                "(enterprise-attack/enterprise-attack.json) or set the "
                "STIX_DATA_PATH environment variable to its location."
            )
        self._by_id: dict[str, TechniqueMetadata] = {}
        self._cloud_ids: set[str] = set()
        self._load()

    def _load(self) -> None:
        logger.info("Loading ATT&CK STIX bundle from %s", self.stix_path)
        # allow_custom=True is required: ATT&CK attack-pattern objects carry
        # x_mitre_* custom properties that strict parsing would reject.
        store = MemoryStore(allow_custom=True)
        store.load_from_file(self.stix_path)
        techniques = store.query([Filter("type", "=", "attack-pattern")])

        # The bundle can contain more than one object per external_id (e.g. a
        # superseded/revoked object alongside the current one). Resolve such
        # collisions preferring the non-revoked, most-recently-modified object.
        chosen: dict[str, object] = {}
        for tech in techniques:
            # Deprecated techniques are removed from the matrix entirely -- drop
            # them. Revoked techniques are KEPT: revocation usually reflects a
            # taxonomy change (e.g. T1562.008 'Disable or Modify Cloud Logs'),
            # not that the underlying behaviour stopped being a threat, so they
            # remain valid detection targets.
            if getattr(tech, "x_mitre_deprecated", False):
                continue
            technique_id = self._external_id(tech)
            if technique_id is None:
                continue
            if self._prefer(tech, chosen.get(technique_id)):
                chosen[technique_id] = tech

        for technique_id, tech in chosen.items():
            tactic_names = [
                _tactic_name_from_shortname(phase.phase_name)
                for phase in getattr(tech, "kill_chain_phases", [])
                if getattr(phase, "kill_chain_name", "") == "mitre-attack"
            ]
            platforms = list(getattr(tech, "x_mitre_platforms", []) or [])
            data_sources = list(getattr(tech, "x_mitre_data_sources", []) or [])
            description = (getattr(tech, "description", "") or "")[:500]
            is_sub = bool(getattr(tech, "x_mitre_is_subtechnique", False))

            self._by_id[technique_id] = TechniqueMetadata(
                technique_id=technique_id,
                technique_name=getattr(tech, "name", technique_id),
                tactic_names=tactic_names,
                description=description,
                platforms=platforms,
                data_sources=data_sources,
                mitre_url=_build_mitre_url(technique_id),
                is_subtechnique=is_sub,
            )
            if "IaaS" in platforms:
                self._cloud_ids.add(technique_id)

        logger.info(
            "Loaded %d techniques (%d cloud/IaaS-relevant) from STIX bundle",
            len(self._by_id),
            len(self._cloud_ids),
        )

    @staticmethod
    def _prefer(candidate: object, incumbent: Optional[object]) -> bool:
        """Decide whether ``candidate`` should replace ``incumbent`` for the
        same external_id. Non-revoked beats revoked; otherwise newer wins."""
        if incumbent is None:
            return True
        cand_revoked = bool(getattr(candidate, "revoked", False))
        inc_revoked = bool(getattr(incumbent, "revoked", False))
        if cand_revoked != inc_revoked:
            return not cand_revoked
        return str(getattr(candidate, "modified", "")) > str(getattr(incumbent, "modified", ""))

    @staticmethod
    def _external_id(tech: object) -> Optional[str]:
        """Return the mitre-attack external_id (e.g. 'T1078.004') or None."""
        for ref in getattr(tech, "external_references", []):
            if getattr(ref, "source_name", "") == "mitre-attack":
                return getattr(ref, "external_id", None)
        return None

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def get_technique(self, technique_id: str) -> Optional[TechniqueMetadata]:
        """Return metadata for a technique ID, or ``None`` if unknown."""
        return self._by_id.get(technique_id)

    def get_cloud_techniques(self) -> list[TechniqueMetadata]:
        """All IaaS-tagged techniques (used for coverage reporting)."""
        return [self._by_id[tid] for tid in sorted(self._cloud_ids)]

    @property
    def cloud_technique_count(self) -> int:
        return len(self._cloud_ids)

    @property
    def total_technique_count(self) -> int:
        return len(self._by_id)


@lru_cache(maxsize=1)
def get_enricher() -> Enricher:
    """Return the process-wide Enricher singleton (loaded on first call)."""
    return Enricher()
