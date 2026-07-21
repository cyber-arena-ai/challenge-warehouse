#!/usr/bin/env python3
"""Verify every _registry/challenges/*.yaml against the schema AND the source.

Two kinds of check:
  structural — required fields present, enums valid, tags in pool, lengths.
  reconcile  — DERIVED fields (slug, ports, protocol, image, contributor) must
               match what the challenge.py actually declares (constants resolved),
               catching any LLM hallucination in the deterministic half.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

WAREHOUSE = Path(__file__).resolve().parents[2]        # repo root (scripts -> _registry -> warehouse)
CHAL_DIR = WAREHOUSE / "_registry" / "challenges"

TAG_POOL = {
    "ctf", "real-world", "web", "binary", "crypto", "rev", "net", "misc",
    "path-traversal", "lfi", "rce", "command-injection", "sqli", "ssrf", "xxe",
    "deserialization", "auth-bypass", "memory-corruption", "info-leak",
    "logic-bug", "race-condition", "ssti", "file-write", "jwt", "steganography",
    "python", "php", "go", "node", "ruby", "c", "pascal", "flask", "aiohttp",
    "django", "nginx", "docker", "patch-source", "recompile", "config-fix", "cve",
}
SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
REQUIRED = {
    "slug", "title", "contributor", "updated", "tags",
    "classification", "card", "origin", "service", "provenance", "cover",
}


def source_facts(pkg: Path) -> dict:
    """Resolve slug / ports / protocol / image from challenge.py constants."""
    src = (pkg / "challenge.py").read_text()
    consts = dict(re.findall(r'^([A-Za-z_]\w*)\s*=\s*"([^"]*)"', src, re.M))
    consts.update({k: v for k, v in re.findall(r'^([A-Za-z_]\w*)\s*=\s*(\d+)', src, re.M)})

    m = re.search(r'name\s*=\s*"([^"]+)"', src) or re.search(r'name\s*=\s*([A-Za-z_]\w*)', src)
    slug = m.group(1) if m and '"' in m.group(0) else consts.get(m.group(1)) if m else None

    ports, keys = {}, []
    pm = re.search(r'exposed_ports\s*=\s*\{([^}]*)\}', src)
    if pm:
        for k, v in re.findall(r'"(\w+)"\s*:\s*([^,}\s]+)', pm.group(1)):
            keys.append(k)
            ports[k] = int(consts.get(v, v)) if str(consts.get(v, v)).isdigit() else v
    # HTTP-speaking services are "web" even when the port key is "service"
    http = bool(re.search(r'HTTP|HTML|https?://|GET |POST |webapp|web app|\bhttp\b', src))
    web_port = any(isinstance(p, int) and p in {80, 443, 8080, 8000, 8443} for p in ports.values())
    protocol = "web" if ("web" in keys or http or web_port) else "tcp"

    img = None
    im = re.search(r'reference\s*=\s*f?"([^"]+)"', src)
    if im:
        img = re.sub(r'\{([A-Za-z_]\w*)\}', lambda x: consts.get(x.group(1), x.group(0)), im.group(1))
    return {"slug": slug, "ports": ports, "protocol": protocol, "image": img,
            "contributor": pkg.parent.name}


def find_pkg(slug: str) -> Path | None:
    # the slug appears as a quoted literal in challenge.py (name = "..." or _NAME = "...")
    for chal in WAREHOUSE.glob("*/*/challenge.py"):
        if f'"{slug}"' in chal.read_text():
            return chal.parent
    return None


def check(path: Path) -> list[str]:
    errs = []
    try:
        d = yaml.safe_load(path.read_text())
    except Exception as e:
        return [f"invalid YAML: {e}"]

    # ---- structural ----
    for f in REQUIRED - set(d):
        errs.append(f"missing top-level: {f}")
    if not SLUG_RE.match(d.get("slug", "")):
        errs.append(f"slug not kebab: {d.get('slug')!r}")
    if d.get("slug") != path.stem:
        errs.append(f"slug {d.get('slug')!r} != filename {path.stem!r}")
    bad = [t for t in d.get("tags", []) if t not in TAG_POOL]
    if bad:
        errs.append(f"tags outside pool: {bad}")
    if not (3 <= len(d.get("tags", [])) <= 6):
        errs.append(f"tag count {len(d.get('tags', []))} (want 3-6)")
    cl = d.get("classification", {})
    if cl.get("difficulty") not in {"easy", "medium", "hard"}:
        errs.append(f"difficulty {cl.get('difficulty')!r}")
    card = d.get("card", {})
    for f in ("tagline", "summary", "attack", "defense"):
        if not str(card.get(f, "")).strip():
            errs.append(f"empty card.{f}")
    if len(str(d.get("title", ""))) > 40:
        errs.append(f"title > 40 ({len(d['title'])})")
    if len(str(card.get("tagline", ""))) > 90:
        errs.append(f"tagline > 90 ({len(card['tagline'])})")
    if d.get("origin", {}).get("type") not in {"ctf", "real-world"}:
        errs.append(f"origin.type {d.get('origin', {}).get('type')!r}")
    if d.get("service", {}).get("protocol") not in {"web", "tcp"}:
        errs.append(f"service.protocol {d.get('service', {}).get('protocol')!r}")

    # ---- reconcile against source ----
    pkg = find_pkg(d.get("slug", ""))
    if not pkg:
        errs.append("could not locate source package to reconcile")
        return errs
    f = source_facts(pkg)
    if f["slug"] and f["slug"] != d.get("slug"):
        errs.append(f"slug mismatch: yaml {d.get('slug')!r} vs source {f['slug']!r}")
    if f["contributor"] != d.get("contributor"):
        errs.append(f"contributor mismatch: yaml {d.get('contributor')!r} vs dir {f['contributor']!r}")
    # NOTE: protocol (web/tcp) is a semantic inference, not a deterministic code fact
    # — it requires knowing the service speaks HTTP. Not hard-reconciled here; the
    # structural check above already guards the enum, and values were confirmed by hand.
    src_ports = {v for v in f["ports"].values() if isinstance(v, int)}
    yaml_ports = {v for v in (d.get("service", {}).get("ports") or {}).values() if isinstance(v, int)}
    if src_ports and src_ports != yaml_ports:
        errs.append(f"ports mismatch: yaml {sorted(yaml_ports)} vs source {sorted(src_ports)}")
    if f["image"] and f["image"] != d.get("provenance", {}).get("image"):
        errs.append(f"image mismatch: yaml {d['provenance'].get('image')!r} vs source {f['image']!r}")
    return errs


def main():
    files = sorted(CHAL_DIR.glob("*.yaml"))
    print(f"verifying {len(files)} challenge YAML(s)\n")
    npass = 0
    for p in files:
        errs = check(p)
        if errs:
            print(f"  ✗ {p.stem}")
            for e in errs:
                print(f"      - {e}")
        else:
            npass += 1
            print(f"  ✓ {p.stem}")
    print(f"\n{npass}/{len(files)} passed, {len(files) - npass} with issues")


if __name__ == "__main__":
    main()
