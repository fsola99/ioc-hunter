#!/usr/bin/env python3
"""Rebuild the bundled ATT&CK catalogue from MITRE's official release.

Reads the Enterprise ATT&CK STIX bundle and writes `backend/app/data/attack.json`,
holding the ordered tactics, every technique and sub-technique with its
description and platforms, and the mitigations ATT&CK recommends against each one.

Usage:
    python tools/refresh_attack_data.py [--version v18.0] [--output PATH]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack{suffix}.json"
)

DEFAULT_OUTPUT = (
    Path(__file__).resolve().parent.parent / "backend" / "app" / "data" / "attack.json"
)


def attack_id(stix_object: dict) -> str | None:
    """Return the ATT&CK identifier of `stix_object`, when it carries one."""
    for reference in stix_object.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            return reference.get("external_id")
    return None


def attack_url(stix_object: dict) -> str | None:
    """Return the attack.mitre.org page for `stix_object`, when it has one."""
    for reference in stix_object.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            return reference.get("url")
    return None


def is_live(stix_object: dict) -> bool:
    """Whether `stix_object` is neither revoked nor deprecated."""
    return not stix_object.get("revoked") and not stix_object.get("x_mitre_deprecated")


def fetch_bundle(version: str | None) -> dict:
    """Download the Enterprise ATT&CK STIX bundle.

    Args:
        version: An ATT&CK release such as `v18.0`, or `None` for the current one.

    Returns:
        The parsed STIX bundle.

    Raises:
        SystemExit: If the bundle could not be downloaded.
    """
    url = BUNDLE_URL.format(suffix=f"-{version}" if version else "")
    print(f"Downloading {url}", file=sys.stderr)
    try:
        with urllib.request.urlopen(url, timeout=180) as response:
            return json.load(response)
    except (urllib.error.URLError, urllib.error.HTTPError) as exc:
        raise SystemExit(f"Could not download the ATT&CK bundle: {exc}") from exc


_MARKDOWN_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_CITATION = re.compile(r"\s*\(Citation:[^)]*\)")


def collapse(text: str | None, limit: int = 1200) -> str:
    """Return `text` as one trimmed paragraph of prose, capped at `limit` characters.

    ATT&CK descriptions are authored in markdown and carry inline `(Citation: …)`
    markers; both are reduced to their readable text so the catalogue holds prose
    rather than source markup.
    """
    if not text:
        return ""
    cleaned = _MARKDOWN_LINK.sub(r"\1", text)
    cleaned = _CITATION.sub("", cleaned)
    flattened = " ".join(cleaned.split())
    if len(flattened) <= limit:
        return flattened
    return f"{flattened[: limit - 1].rstrip()}…"


def build_catalogue(bundle: dict, version: str | None) -> dict:
    """Assemble the catalogue the service reads from a STIX `bundle`."""
    tactics_by_ref: dict[str, dict] = {}
    tactics_by_shortname: dict[str, str] = {}
    techniques: dict[str, dict] = {}
    mitigations: dict[str, tuple[str, str]] = {}
    mitigates: list[tuple[str, str]] = []
    matrix_order: list[str] = []
    technique_refs: dict[str, str] = {}

    for stix_object in bundle.get("objects", []):
        kind = stix_object.get("type")

        if kind == "x-mitre-matrix":
            matrix_order = stix_object.get("tactic_refs", []) or matrix_order

        elif kind == "x-mitre-tactic" and is_live(stix_object):
            identifier = attack_id(stix_object)
            shortname = stix_object.get("x_mitre_shortname")
            if identifier and shortname:
                tactics_by_ref[stix_object["id"]] = {
                    "id": identifier,
                    "name": stix_object.get("name", ""),
                    "shortname": shortname,
                    "description": collapse(stix_object.get("description"), 400),
                    "url": attack_url(stix_object),
                }
                tactics_by_shortname[shortname] = identifier

        elif kind == "attack-pattern" and is_live(stix_object):
            identifier = attack_id(stix_object)
            if not identifier:
                continue
            technique_refs[stix_object["id"]] = identifier
            phases = [
                phase["phase_name"]
                for phase in stix_object.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name")
            ]
            techniques[identifier] = {
                "id": identifier,
                "name": stix_object.get("name", ""),
                "description": collapse(stix_object.get("description")),
                "platforms": sorted(stix_object.get("x_mitre_platforms", []) or []),
                "tactic_shortnames": phases,
                "is_subtechnique": bool(stix_object.get("x_mitre_is_subtechnique")),
                "parent": identifier.split(".")[0] if "." in identifier else None,
                "url": attack_url(stix_object),
                "mitigations": [],
            }

        elif kind == "course-of-action" and is_live(stix_object):
            identifier = attack_id(stix_object)
            if identifier:
                mitigations[stix_object["id"]] = (identifier, stix_object.get("name", ""))

        elif kind == "relationship" and stix_object.get("relationship_type") == "mitigates":
            mitigates.append((stix_object["source_ref"], stix_object["target_ref"]))

    linked: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for source, target in mitigates:
        mitigation = mitigations.get(source)
        technique_id = technique_refs.get(target)
        if mitigation and technique_id:
            linked[technique_id].add(mitigation)

    for technique_id, entries in linked.items():
        if technique_id in techniques:
            techniques[technique_id]["mitigations"] = [
                {"id": identifier, "name": name} for identifier, name in sorted(entries)
            ]

    # Resolve each technique's tactics to ATT&CK ids, and drop the working field.
    for technique in techniques.values():
        technique["tactics"] = [
            tactics_by_shortname[shortname]
            for shortname in technique.pop("tactic_shortnames")
            if shortname in tactics_by_shortname
        ]

    ordered_refs = [ref for ref in matrix_order if ref in tactics_by_ref]
    ordered_refs += [ref for ref in tactics_by_ref if ref not in ordered_refs]
    ordered_tactics = [tactics_by_ref[ref] for ref in ordered_refs]

    return {
        "version": version or "latest",
        "generated_at": datetime.now(tz=UTC).isoformat(timespec="seconds"),
        "tactics": ordered_tactics,
        "techniques": [techniques[key] for key in sorted(techniques)],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", help="ATT&CK release to pin, such as v18.0.")
    parser.add_argument(
        "--output", type=Path, default=DEFAULT_OUTPUT, help="Where to write the catalogue."
    )
    args = parser.parse_args()

    catalogue = build_catalogue(fetch_bundle(args.version), args.version)
    if not catalogue["techniques"]:
        raise SystemExit("The bundle yielded no techniques.")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(catalogue, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
    )

    techniques = catalogue["techniques"]
    subtechniques = sum(1 for technique in techniques if technique["is_subtechnique"])
    mitigated = sum(1 for technique in techniques if technique["mitigations"])
    size_mb = args.output.stat().st_size / 1_048_576

    print(
        f"Wrote {len(catalogue['tactics'])} tactics, "
        f"{len(techniques) - subtechniques} techniques, "
        f"{subtechniques} sub-techniques "
        f"({mitigated} with mitigations) to {args.output} [{size_mb:.1f} MB]",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
