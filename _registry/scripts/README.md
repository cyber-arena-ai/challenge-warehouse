# registry-gen — challenge registry generators

Tooling that produces the challenge **registry** consumed by the frontend's
Games view. Lives at `_registry/scripts/`; writes finished artifacts into
`_registry/`.

- **Schema**: `_registry/schematic.md` (the contract).
- **Outputs**: `_registry/challenges/<slug>.yaml` (metadata) and
  `_registry/covers/<slug>.webp` (illustrations).
- **Credentials** (one directory ABOVE the warehouse checkout — outside the
  repo, never committed): `api.json`, OpenAI-compatible. Either flat
  `{base, key, model}`, or split into `{analysis: {...}, image_gen: {...}}` —
  the text model drives metadata + motif briefs, the image model draws covers.
  A separate `gen.api.json` is used for images instead when present.

## Two passes

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# 1. metadata — one LLM pass per challenge -> _registry/challenges/<slug>.yaml
.venv/bin/python gen_metadata.py            # all (skips existing)
.venv/bin/python gen_metadata.py --only aiohttp-lfi --force   # one, rebuild
.venv/bin/python gen_metadata.py --limit 3  # smoke test

# 2. covers — one image per challenge -> _registry/covers/<slug>.webp
.venv/bin/python gen_covers.py --only aiohttp-lfi          # sample first, then batch
.venv/bin/python gen_covers.py --out covers_test --only aiohttp-lfi,btx   # trial run
.venv/bin/python gen_covers.py --force                     # redraw everything
```

Both passes are idempotent (skip existing unless `--force`) and concurrent.
Covers are **pure geometric illustrations** — no text/metadata baked in; all
challenge info is rendered by the frontend card in HTML.

## How a cover gets its subject

The print style is fixed in `prompts/cover_style.md` and never varies. What
varies is the SUBJECT, derived per challenge in two steps:

1. `prompts/cover_motif.md` turns that challenge's own metadata (vuln class,
   tags, stack, protocol, tagline, attack, defense) into a concrete geometric
   composition brief — the idea being that every vulnerability has a *shape*.
   Traversal is a form escaping its nested frames; overflow is one grid cell
   crushing its neighbours; a redaction leak is covering layers with the deepest
   one showing through. The brief must also carry a detail unique to that one
   challenge, so two challenges sharing a tag don't render alike.
2. The brief is substituted into the style template as `{motif}` and rendered.

The brief is saved to `cover.motif` in the YAML. It is **hand-editable** — rewrite
one you don't like and re-run with `--keep-motif` to redraw from your text instead
of deriving a fresh brief:

```bash
.venv/bin/python gen_covers.py --only btx --force --keep-motif
```

`--out <dir>` writes to an alternate dir under `_registry/` and leaves the YAMLs
and index untouched — use it to trial prompt changes before committing them.
Bump `PROMPT_ID` in `gen_covers.py` whenever the prompt templates change.
