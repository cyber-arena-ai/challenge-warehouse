#!/usr/bin/env python3
"""Cover pass — one geometric illustration per challenge -> _registry/covers/<slug>.png.

Pure abstract riso-geometric art (NO text/metadata — the frontend card renders
all info). Uniform style across covers; palette + shapes vary per challenge.
Reads gen.api.json (image model), writes the PNG, samples an accent color, and
patches cover.accent / cover.prompt_id back into the challenge YAML.

  python3 gen_covers.py --only aiohttp-lfi          # one (sample first!)
  python3 gen_covers.py                             # all, skip existing
  python3 gen_covers.py --force --size 1024x1024
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import re
from io import BytesIO
from pathlib import Path

import httpx
import yaml
from PIL import Image

COVER_MAX = 800     # cards render ~350px; 800 covers 2x retina on the detail sheet
COVER_Q = 80        # WebP quality — geometric/halftone art stays crisp, files tiny
INK_MIN_SAT = 90    # below this a colour is paper/grey, not an ink; sparse art otherwise
                    # lets the abundant cream background win the accent vote

WAREHOUSE = Path(__file__).resolve().parents[2]        # repo root (scripts -> _registry -> warehouse)
CHAL_DIR = WAREHOUSE / "_registry" / "challenges"
COVER_DIR = WAREHOUSE / "_registry" / "covers"
CREDS = (WAREHOUSE.parent / "gen.api.json" if (WAREHOUSE.parent / "gen.api.json").exists()
         else WAREHOUSE.parent / "api.json")          # image model creds — outside the repo, never committed
STYLE = (Path(__file__).resolve().parent / "prompts" / "cover_style.md").read_text()
MOTIF_SYSTEM = (Path(__file__).resolve().parent / "prompts" / "cover_motif.md").read_text()
PROMPT_ID = "geo-v2"


def load_creds(path, section: str) -> dict:
    """Read {base, key, model} — accepts either a flat file or one keyed by section."""
    cfg = json.loads(path.read_text())
    return cfg[section] if section in cfg else cfg


# Curated riso duotone/tritone palettes — assigned per challenge by slug hash so
# covers vary in color while sharing one print aesthetic.
PALETTES = [
    "warm paper cream background with fluorescent pink and deep navy inks",
    "off-white background with riso teal and burnt orange inks",
    "pale grey background with electric blue and lemon yellow inks",
    "cream background with forest green and coral red inks",
    "bone-white background with violet purple and mustard inks",
    "light sand background with crimson and cyan inks",
    "pale mint background with charcoal ink and hot magenta",
    "ivory background with cobalt blue and tomato red inks",
]


def _slug_index(slug: str, n: int) -> int:
    return sum(ord(c) for c in slug) % n


def motif_facts(meta: dict) -> str:
    """The challenge's own distinguishing detail, as input to the motif brief."""
    cls, svc, card = (meta.get(k) or {} for k in ("classification", "service", "card"))
    fields = {
        "vulnerability": cls.get("vuln_class"),
        "difficulty": cls.get("difficulty"),
        "tags": ", ".join(meta.get("tags") or []),
        "protocol": svc.get("protocol"),
        "stack": svc.get("stack"),
        "tagline": card.get("tagline"),
        "what it is": card.get("summary"),
        "the attack": card.get("attack"),
        "the defense": card.get("defense"),
    }
    return "\n".join(f"{k}: {v}" for k, v in fields.items() if v)


async def build_motif(client: httpx.AsyncClient, cfg: dict, meta: dict, tries: int = 3) -> str:
    """One small LLM pass: challenge metadata -> concrete composition brief."""
    for attempt in range(tries):
        try:
            return await _motif_once(client, cfg, meta)
        except Exception:
            if attempt == tries - 1:
                raise
            await asyncio.sleep(2 * (attempt + 1))


async def _motif_once(client: httpx.AsyncClient, cfg: dict, meta: dict) -> str:
    resp = await client.post(
        f"{cfg['base'].rstrip('/')}/chat/completions",
        headers={"Authorization": f"Bearer {cfg['key']}"},
        json={
            "model": cfg["model"],
            "messages": [
                {"role": "system", "content": MOTIF_SYSTEM},
                {"role": "user", "content": motif_facts(meta)},
            ],
            "temperature": 0.7,
            "max_tokens": 400,
        },
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"].strip()


def build_prompt(meta: dict, motif: str) -> str:
    palette = PALETTES[_slug_index(meta["slug"], len(PALETTES))]
    return STYLE.replace("{motif}", motif).replace("{palette}", palette)


async def gen_image(client: httpx.AsyncClient, cfg: dict, prompt: str, size: str) -> bytes:
    resp = await client.post(
        f"{cfg['base'].rstrip('/')}/images/generations",
        headers={"Authorization": f"Bearer {cfg['key']}"},
        json={"model": cfg["model"], "prompt": prompt, "size": size, "n": 1},
        timeout=300,
    )
    if resp.status_code >= 400:
        raise RuntimeError(f"{resp.status_code}: {resp.text[:300]}")
    item = resp.json()["data"][0]
    if item.get("b64_json"):
        return base64.b64decode(item["b64_json"])
    if item.get("url"):                                   # some models return a URL
        img = await client.get(item["url"], timeout=120)
        img.raise_for_status()
        return img.content
    raise RuntimeError(f"no image in response: {str(item)[:200]}")


def accent_of(path: Path) -> str:
    """The dominant vivid INK — most saturated color, weighted by how much of it
    there is. Skips the paper background and near-black outlines -> #rrggbb."""
    im = Image.open(path).convert("RGB").resize((64, 64))
    q = im.quantize(colors=8, method=Image.Quantize.FASTOCTREE)
    pal = q.getpalette()
    best, best_score = None, -1.0
    for count, idx in q.getcolors():
        r, g, b = pal[idx * 3:idx * 3 + 3]
        mx, mn = max(r, g, b), min(r, g, b)
        sat = mx - mn
        if mx < 28 or sat < INK_MIN_SAT:   # near-black outline, or paper/grey
            continue
        if mx >= 240 and sat < 100:        # a pale paper tint, however abundant — not an ink
            continue
        score = sat * (count ** 0.5)       # saturated AND actually present
        if score > best_score:
            best, best_score = (r, g, b), score
    if best is None:                       # fully desaturated art — fall back
        idx = max(q.getcolors())[1]
        best = tuple(pal[idx * 3:idx * 3 + 3])
    return "#{:02x}{:02x}{:02x}".format(*best)


def patch_yaml(slug: str, accent: str, motif: str):
    p = CHAL_DIR / f"{slug}.yaml"
    if not p.exists():
        return
    doc = yaml.safe_load(p.read_text())
    doc.setdefault("cover", {})
    doc["cover"].update({"image": f"covers/{slug}.webp", "accent": accent,
                         "prompt_id": PROMPT_ID, "motif": motif})
    text = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=88, default_flow_style=False)
    p.write_text("# generated by registry-gen/gen_metadata.py — see _registry/schematic.md\n" + text)


async def one(sem, client, text_cfg, cfg, meta_path: Path, size: str, force: bool,
              out_dir: Path, keep_motif: bool):
    meta = yaml.safe_load(meta_path.read_text())
    slug = meta["slug"]
    out = out_dir / f"{slug}.webp"
    if out.exists() and not force:
        return {"slug": slug, "skipped": True}
    async with sem:
        try:
            motif = (meta.get("cover") or {}).get("motif") if keep_motif else None
            motif = motif or await build_motif(client, text_cfg, meta)
            data = await gen_image(client, cfg, build_prompt(meta, motif), size)
        except Exception as e:
            return {"slug": slug, "error": str(e)[:200]}
    out_dir.mkdir(parents=True, exist_ok=True)
    im = Image.open(BytesIO(data)).convert("RGB")
    im.thumbnail((COVER_MAX, COVER_MAX))
    im.save(out, "WEBP", quality=COVER_Q, method=6)
    accent = accent_of(out)
    if out_dir == COVER_DIR:                              # test runs never touch the YAMLs
        patch_yaml(slug, accent, motif)
    else:
        (out_dir / f"{slug}.motif.txt").write_text(motif + "\n")
    return {"slug": slug, "path": str(out.relative_to(WAREHOUSE)), "accent": accent,
            "bytes": out.stat().st_size, "motif": motif}


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="comma-separated slugs")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--size", default="1024x1024")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--out", default="covers", help="output dir under _registry/ (e.g. covers_test)")
    ap.add_argument("--keep-motif", action="store_true",
                    help="reuse cover.motif from the YAML instead of deriving a new brief")
    args = ap.parse_args()

    cfg = load_creds(CREDS, "image_gen")
    text_cfg = load_creds(CREDS, "analysis")            # the motif brief pass
    out_dir = WAREHOUSE / "_registry" / args.out
    metas = sorted(CHAL_DIR.glob("*.yaml"))
    if args.only:
        want = {s.strip() for s in args.only.split(",")}
        metas = [m for m in metas if m.stem in want]
    if not metas:
        print("no challenge YAMLs found — run gen_metadata.py first"); return
    print(f"[covers] {len(metas)} cover(s), size={args.size}, force={args.force}")

    sem = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(*(one(sem, client, text_cfg, cfg, m, args.size, args.force, out_dir, args.keep_motif) for m in metas))

    for r in results:
        if r.get("error"):
            print(f"  ✗ {r['slug']}: {r['error']}")
        elif r.get("skipped"):
            print(f"  ⋯ {r['slug']} (exists; --force to redo)")
        else:
            print(f"  ✓ {r['slug']} -> {r['path']}  accent={r['accent']} ({r['bytes']//1024} KB)")
    if out_dir != COVER_DIR:
        print(f"\n[test] wrote to {out_dir.relative_to(WAREHOUSE)}; YAMLs and index untouched")
        return
    import build_index
    print(f"[index] refreshed manifest with {build_index.build()} challenge(s)")


if __name__ == "__main__":
    asyncio.run(main())
