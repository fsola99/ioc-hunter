from __future__ import annotations

import csv
import io
import json
from functools import lru_cache
from pathlib import Path

from ..models import (
    AttackMatrix,
    AttackTactic,
    AttackTechnique,
    AttackTechniqueSummary,
    Mitigation,
)

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "attack.json"

CSV_COLUMNS = ["id", "name", "tactics", "platforms", "mitigations", "description", "url"]


@lru_cache
def _catalogue() -> tuple[list[AttackTactic], dict[str, AttackTechnique], str]:
    if not DATA_FILE.exists():
        return [], {}, "missing"

    raw = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    tactics = [AttackTactic(**tactic) for tactic in raw.get("tactics", [])]
    techniques = {
        entry["id"]: AttackTechnique(
            id=entry["id"],
            name=entry["name"],
            description=entry.get("description", ""),
            platforms=entry.get("platforms", []),
            tactics=entry.get("tactics", []),
            is_subtechnique=entry.get("is_subtechnique", False),
            parent=entry.get("parent"),
            url=entry.get("url"),
            mitigations=[Mitigation(**item) for item in entry.get("mitigations", [])],
        )
        for entry in raw.get("techniques", [])
    }
    return tactics, techniques, raw.get("version", "unknown")


def mitigations_for(technique_id: str) -> list[Mitigation]:
    """Return the ATT&CK mitigations recommended against `technique_id`.

    A sub-technique with no mitigations of its own inherits its parent's, matching
    how the ATT&CK matrix presents them.

    Args:
        technique_id: An ATT&CK technique id, such as `T1055` or `T1027.002`.

    Returns:
        The recommended mitigations, empty when the technique is not in the catalogue.
    """
    _, techniques, _ = _catalogue()
    key = technique_id.strip().upper()

    technique = techniques.get(key)
    if technique and technique.mitigations:
        return technique.mitigations

    parent = techniques.get(key.split(".")[0])
    return parent.mitigations if parent else []


def technique(technique_id: str) -> AttackTechnique | None:
    """Return the catalogue entry for `technique_id`, or `None` when it is unknown."""
    _, techniques, _ = _catalogue()
    return techniques.get(technique_id.strip().upper())


def subtechniques_of(technique_id: str) -> list[AttackTechnique]:
    """Return the sub-techniques belonging to `technique_id`, in identifier order."""
    _, techniques, _ = _catalogue()
    key = technique_id.strip().upper()
    return sorted(
        (entry for entry in techniques.values() if entry.parent == key),
        key=lambda entry: entry.id,
    )


def _summarise(entry: AttackTechnique, child_count: int) -> AttackTechniqueSummary:
    return AttackTechniqueSummary(
        id=entry.id,
        name=entry.name,
        tactics=entry.tactics,
        platforms=entry.platforms,
        mitigation_count=len(entry.mitigations),
        subtechnique_count=child_count,
    )


def matrix(query: str = "", platform: str = "") -> AttackMatrix:
    """Return the ATT&CK matrix, optionally narrowed by text and platform.

    Only top-level techniques appear in the matrix itself; sub-techniques are
    reachable through their parent. A sub-technique matching `query` surfaces its
    parent, so searching for a sub-technique name still finds it.

    Args:
        query: Case-insensitive text matched against technique ids and names.
        platform: An ATT&CK platform name, such as `Windows`. Empty matches all.

    Returns:
        The tactics in matrix order, each carrying the techniques that matched.
    """
    tactics, techniques, version = _catalogue()

    needle = query.strip().lower()
    wanted_platform = platform.strip().lower()

    children: dict[str, int] = {}
    matching_parents: set[str] = set()
    for entry in techniques.values():
        if entry.parent:
            children[entry.parent] = children.get(entry.parent, 0) + 1
            if needle and (needle in entry.id.lower() or needle in entry.name.lower()):
                matching_parents.add(entry.parent)

    def keeps(entry: AttackTechnique) -> bool:
        if wanted_platform and not any(
            wanted_platform == item.lower() for item in entry.platforms
        ):
            return False
        if not needle:
            return True
        return (
            needle in entry.id.lower()
            or needle in entry.name.lower()
            or entry.id in matching_parents
        )

    top_level = [entry for entry in techniques.values() if not entry.is_subtechnique]
    kept = sorted((entry for entry in top_level if keeps(entry)), key=lambda e: e.id)

    by_tactic: dict[str, list[AttackTechniqueSummary]] = {tactic.id: [] for tactic in tactics}
    for entry in kept:
        for tactic_id in entry.tactics:
            if tactic_id in by_tactic:
                by_tactic[tactic_id].append(_summarise(entry, children.get(entry.id, 0)))

    return AttackMatrix(
        version=version,
        technique_count=len(kept),
        platforms=sorted({item for entry in techniques.values() for item in entry.platforms}),
        tactics=[
            AttackTactic(
                id=tactic.id,
                name=tactic.name,
                shortname=tactic.shortname,
                description=tactic.description,
                url=tactic.url,
                techniques=by_tactic[tactic.id],
            )
            for tactic in tactics
        ],
    )


def catalogue_size() -> int:
    """Return how many techniques and sub-techniques the catalogue holds."""
    _, techniques, _ = _catalogue()
    return len(techniques)


def to_csv() -> str:
    """Render the whole catalogue as CSV, one row per technique and sub-technique.

    Returns:
        The CSV document, including its header row.
    """
    tactics, techniques, _ = _catalogue()
    tactic_names = {tactic.id: tactic.name for tactic in tactics}

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()

    for key in sorted(techniques):
        entry = techniques[key]
        writer.writerow(
            {
                "id": entry.id,
                "name": entry.name,
                "tactics": ", ".join(
                    tactic_names.get(tactic, tactic) for tactic in entry.tactics
                ),
                "platforms": ", ".join(entry.platforms),
                "mitigations": ", ".join(
                    f"{item.id} - {item.name}" for item in entry.mitigations
                ),
                "description": entry.description,
                "url": entry.url or "",
            }
        )

    return buffer.getvalue()
