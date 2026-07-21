# registry-gen — challenge registry generators

Tooling that produces the challenge **registry** consumed by the frontend's
Games view. Lives at `_registry/scripts/`; writes finished artifacts into
`_registry/`.

- **Schema**: `_registry/schematic.md` (the contract).
- **Outputs**: `_registry/challenges/<slug>.yaml` (metadata) and
  `_registry/covers/<slug>.png` (illustrations).
- **Credentials** (one directory ABOVE the warehouse checkout — outside the
  repo, never committed): `api.json` (text LLM) and `gen.api.json` (image
  model). Both are OpenAI-compatible `{base, key, model}`.

## Two passes

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# 1. metadata — one LLM pass per challenge -> _registry/challenges/<slug>.yaml
.venv/bin/python gen_metadata.py            # all (skips existing)
.venv/bin/python gen_metadata.py --only aiohttp-lfi --force   # one, rebuild
.venv/bin/python gen_metadata.py --limit 3  # smoke test

# 2. covers — one image per challenge -> _registry/covers/<slug>.png (see gen_covers.py)
.venv/bin/python gen_covers.py --only aiohttp-lfi   # sample first, then batch
```

Both passes are idempotent (skip existing unless `--force`) and concurrent.
Covers are **pure geometric illustrations** — no text/metadata baked in; all
challenge info is rendered by the frontend card in HTML.
