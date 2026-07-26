from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from ..models import Mitigation

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "mitre_mitigations.json"

_MITIGATION_RE = re.compile(r"\A(?P<id>M\d{4})\s*-\s*(?P<name>.+)\Z")


@lru_cache
def _mitigation_index() -> dict[str, list[Mitigation]]:
    if not DATA_FILE.exists():
        return {}
    raw: dict[str, list[str]] = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    index: dict[str, list[Mitigation]] = {}
    for technique_id, entries in raw.items():
        parsed = []
        for entry in entries:
            match = _MITIGATION_RE.match(entry.strip())
            if match:
                parsed.append(Mitigation(id=match["id"], name=match["name"].strip()))
        index[technique_id.upper()] = parsed
    return index


def mitigations_for(technique_id: str) -> list[Mitigation]:
    """Return the MITRE ATT&CK mitigations recommended against `technique_id`.

    A sub-technique with no entry of its own inherits its parent technique's
    mitigations, matching how the ATT&CK matrix presents them.

    Args:
        technique_id: An ATT&CK technique id, such as `T1055` or `T1027.002`.

    Returns:
        The recommended mitigations, empty when the technique is not covered by
        the bundled dataset.
    """
    index = _mitigation_index()
    key = technique_id.strip().upper()
    if key in index:
        return index[key]
    parent, _, _ = key.partition(".")
    return index.get(parent, [])


def covered_techniques() -> int:
    """Return how many ATT&CK techniques the bundled mitigation dataset covers."""
    return len(_mitigation_index())
