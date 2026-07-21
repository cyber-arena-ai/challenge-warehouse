#!/usr/bin/env python3
"""Metadata pass — annotate every warehouse challenge into _registry/challenges/<slug>.yaml.

Standalone (lives outside the warehouse); writes only the final YAML back into it.
Per challenge: read the package source (challenge.py + __init__.py), run ONE LLM
pass (root api.json, OpenAI-compatible /chat/completions), validate against the
schematic, and emit YAML in the canonical field order.

  python3 gen_metadata.py                 # all, skip existing
  python3 gen_metadata.py --force         # rebuild all
  python3 gen_metadata.py --only aiohttp-lfi,craft-cms
  python3 gen_metadata.py --limit 3       # first N (smoke test)
"""
from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import re
import sys
from pathlib import Path

import httpx
import yaml

WAREHOUSE = Path(__file__).resolve().parents[2]        # repo root (scripts -> _registry -> warehouse)
OUT_DIR = WAREHOUSE / "_registry" / "challenges"
CREDS = WAREHOUSE.parent / "api.json"                   # text LLM (base, key, model) — outside the repo, never committed
SYSTEM_PROMPT = (Path(__file__).resolve().parent / "prompts" / "metadata_system.md").read_text()

# Tag Pool (must match schematic.md) — used to flag out-of-pool tags for review.
TAG_POOL = {
    "ctf", "real-world",
    "web", "binary", "crypto", "rev", "net", "misc",
    "path-traversal", "lfi", "rce", "command-injection", "sqli", "ssrf", "xxe",
    "deserialization", "auth-bypass", "memory-corruption", "info-leak",
    "logic-bug", "race-condition", "ssti", "file-write", "jwt", "steganography",
    "python", "php", "go", "node", "ruby", "c", "pascal", "flask", "aiohttp",
    "django", "nginx", "docker",
    "patch-source", "recompile", "config-fix", "cve",
}
SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def discover() -> list[dict]:
    """Every challenge package: {slug_dir, contributor, source}."""
    out = []
    for chal_py in sorted(WAREHOUSE.glob("*/*/challenge.py")):
        pkg = chal_py.parent
        src = f"# ==== {pkg.name}/challenge.py ====\n" + chal_py.read_text()
        init = pkg / "__init__.py"
        if init.exists():
            src += f"\n\n# ==== {pkg.name}/__init__.py ====\n" + init.read_text()
        out.append({"dir": pkg.name, "contributor": pkg.parent.name, "source": src})
    return out


def _extract_json(text: str) -> dict:
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```[a-zA-Z]*\n?", "", t).rsplit("```", 1)[0]
    a, b = t.find("{"), t.rfind("}")
    if a == -1 or b == -1:
        raise ValueError(f"no JSON object in model output: {text[:200]}")
    return json.loads(t[a:b + 1])


async def call_llm(client: httpx.AsyncClient, cfg: dict, source: str) -> dict:
    resp = await client.post(
        f"{cfg['base'].rstrip('/')}/chat/completions",
        headers={"Authorization": f"Bearer {cfg['key']}"},
        json={
            "model": cfg["model"],
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": source},
            ],
            "temperature": 0.3,
            "max_tokens": 2000,
        },
        timeout=120,
    )
    resp.raise_for_status()
    return _extract_json(resp.json()["choices"][0]["message"]["content"])


def assemble(d: dict, contributor: str, today: str) -> tuple[dict, list[str]]:
    """LLM dict -> canonical YAML dict (schematic order). Returns (doc, warnings)."""
    warn = []
    slug = (d.get("slug") or "").strip()
    if not SLUG_RE.match(slug):
        warn.append(f"slug not kebab-case: {slug!r}")
    tags = d.get("tags") or []
    out_of_pool = [t for t in tags if t not in TAG_POOL]
    if out_of_pool:
        warn.append(f"tags outside pool (review): {out_of_pool}")
    if not (3 <= len(tags) <= 6):
        warn.append(f"{len(tags)} tags (expected 3-6)")
    if d.get("difficulty") not in {"easy", "medium", "hard"}:
        warn.append(f"difficulty: {d.get('difficulty')!r}")
    for f in ("title", "tagline", "summary", "attack", "defense"):
        if not (d.get(f) or "").strip():
            warn.append(f"empty card field: {f}")
    if len(d.get("title", "")) > 40:
        warn.append("title > 40 chars")
    if len(d.get("tagline", "")) > 90:
        warn.append("tagline > 90 chars")

    doc = {
        "slug": slug,
        "title": d.get("title"),
        "contributor": contributor,
        "updated": today,
        "tags": tags,
        "classification": {
            "difficulty": d.get("difficulty"),
            "vuln_class": d.get("vuln_class"),
            "cve": d.get("cve"),
        },
        "card": {
            "tagline": d.get("tagline"),
            "summary": (d.get("summary") or "").strip(),
            "attack": d.get("attack"),
            "defense": d.get("defense"),
        },
        "origin": d.get("origin") or {},
        "service": d.get("service") or {},
        "provenance": {
            "image": d.get("image"),
            "source_intro": (d.get("source_intro") or "").strip(),
        },
        "cover": {"image": f"covers/{slug}.png", "accent": None, "prompt_id": None},
    }
    return doc, warn


def write_yaml(doc: dict):
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / f"{doc['slug']}.yaml"
    text = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=88, default_flow_style=False)
    path.write_text("# generated by registry-gen/gen_metadata.py — see _registry/schematic.md\n" + text)
    return path


async def one(sem, client, cfg, chal, today, force):
    async with sem:
        try:
            d = await call_llm(client, cfg, chal["source"])
        except Exception as e:
            return {"dir": chal["dir"], "error": str(e)[:160]}
        doc, warn = assemble(d, chal["contributor"], today)
        if not doc["slug"]:
            return {"dir": chal["dir"], "error": "no slug"}
        if not force and (OUT_DIR / f"{doc['slug']}.yaml").exists():
            return {"slug": doc["slug"], "skipped": True}
        path = write_yaml(doc)
        return {"slug": doc["slug"], "path": str(path.relative_to(WAREHOUSE)), "warn": warn,
                "new_tags": d.get("new_tags") or []}


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--only", help="comma-separated slugs/dirs")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--concurrency", type=int, default=6)
    args = ap.parse_args()

    cfg = json.loads(CREDS.read_text())
    today = datetime.date.today().isoformat()
    chals = discover()
    if args.only:
        want = {s.strip() for s in args.only.split(",")}
        chals = [c for c in chals if c["dir"] in want or c["dir"].replace("_", "-") in want]
    if args.limit:
        chals = chals[:args.limit]
    print(f"[metadata] {len(chals)} challenge(s), concurrency={args.concurrency}, force={args.force}")

    sem = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(*(one(sem, client, cfg, c, today, args.force) for c in chals))

    ok = skipped = failed = 0
    new_tags_seen = set()
    for r in results:
        if r.get("error"):
            failed += 1; print(f"  ✗ {r['dir']}: {r['error']}")
        elif r.get("skipped"):
            skipped += 1; print(f"  ⋯ {r['slug']} (exists; --force to rebuild)")
        else:
            ok += 1
            new_tags_seen.update(r.get("new_tags") or [])
            flag = f"  ⚠ {r['warn']}" if r.get("warn") else ""
            print(f"  ✓ {r['slug']} -> {r['path']}{flag}")
    print(f"\n[metadata] ok={ok} skipped={skipped} failed={failed}")
    if new_tags_seen:
        print(f"[review] NEW tags proposed (not in pool): {sorted(new_tags_seen)}")
    import build_index
    print(f"[index] refreshed manifest with {build_index.build()} challenge(s)")


if __name__ == "__main__":
    asyncio.run(main())
