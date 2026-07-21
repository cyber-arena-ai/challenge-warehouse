#!/usr/bin/env python3
"""Build _registry/index.json — the manifest the frontend probes.

Consolidates every _registry/challenges/*.yaml into one JSON file so the Games
view fetches the whole catalogue in a single request (no in-browser YAML, no
hardcoded list). Derived purely from what's on disk, so it always reflects the
challenges that actually exist — add a YAML, rebuild, and it appears.

Run standalone, or it's auto-invoked at the end of gen_metadata / gen_covers.
"""
from __future__ import annotations

import datetime
import json
from pathlib import Path

import yaml

REGISTRY = Path(__file__).resolve().parents[1]         # _registry/


def build(registry: Path = REGISTRY) -> int:
    chal_dir = registry / "challenges"
    challenges = []
    for p in sorted(chal_dir.glob("*.yaml")):
        doc = yaml.safe_load(p.read_text())
        if isinstance(doc, dict) and doc.get("slug"):
            challenges.append(doc)
    index = {
        "generated": datetime.date.today().isoformat(),
        "count": len(challenges),
        "challenges": challenges,
    }
    out = registry / "index.json"
    out.write_text(json.dumps(index, ensure_ascii=False, indent=2))
    return len(challenges)


if __name__ == "__main__":
    n = build()
    print(f"[index] wrote _registry/index.json with {n} challenge(s)")
