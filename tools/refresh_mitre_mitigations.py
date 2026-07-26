#!/usr/bin/env python3
"""Rebuild the bundled technique-to-mitigation dataset from MITRE's ATT&CK release.

Reads the official Enterprise ATT&CK STIX bundle and writes
`backend/app/data/mitre_mitigations.json`, mapping each technique id to the
mitigations that ATT&CK recommends against it.

Usage:
    python tools/refresh_mitre_mitigations.py [--version v18.0] [--output PATH]
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path

BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack{suffix}.json"
)

DEFAULT_OUTPUT = (
    Path(__file__).resolve().parent.parent
    / "backend"
    / "app"
    / "data"
    / "mitre_mitigations.json"
)


def attack_id(stix_object: dict) -> str | None:
    """Return the ATT&CK identifier of `stix_object`, when it carries one."""
    for reference in stix_object.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            return reference.get("external_id")
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
        with urllib.request.urlopen(url, timeout=120) as response:
            return json.load(response)
    except (urllib.error.URLError, urllib.error.HTTPError) as exc:
        raise SystemExit(f"Could not download the ATT&CK bundle: {exc}") from exc


def build_index(bundle: dict) -> dict[str, list[str]]:
    """Map each technique id to its recommended mitigations, formatted `Mxxxx - Name`."""
    techniques: dict[str, str] = {}
    mitigations: dict[str, tuple[str, str]] = {}
    relationships: list[tuple[str, str]] = []

    for stix_object in bundle.get("objects", []):
        kind = stix_object.get("type")

        if kind == "attack-pattern" and is_live(stix_object):
            identifier = attack_id(stix_object)
            if identifier:
                techniques[stix_object["id"]] = identifier

        elif kind == "course-of-action" and is_live(stix_object):
            identifier = attack_id(stix_object)
            if identifier:
                mitigations[stix_object["id"]] = (identifier, stix_object.get("name", ""))

        elif kind == "relationship" and stix_object.get("relationship_type") == "mitigates":
            relationships.append((stix_object["source_ref"], stix_object["target_ref"]))

    index: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for source, target in relationships:
        mitigation = mitigations.get(source)
        technique = techniques.get(target)
        if mitigation and technique:
            index[technique].add(mitigation)

    return {
        technique: [f"{identifier} - {name}" for identifier, name in sorted(entries)]
        for technique, entries in sorted(index.items())
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", help="ATT&CK release to pin, such as v18.0.")
    parser.add_argument(
        "--output", type=Path, default=DEFAULT_OUTPUT, help="Where to write the dataset."
    )
    args = parser.parse_args()

    index = build_index(fetch_bundle(args.version))
    if not index:
        raise SystemExit("The bundle yielded no technique-to-mitigation mappings.")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(index, indent=4, ensure_ascii=False), encoding="utf-8")

    covered = sum(len(entries) for entries in index.values())
    print(
        f"Wrote {len(index)} techniques and {covered} mitigation links to {args.output}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
