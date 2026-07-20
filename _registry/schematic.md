# Challenge Registry — metadata schematic

The registry annotates every challenge in the warehouse with **card-ready
metadata**, so the integrated frontend can render each challenge as a
**challenge card** under a new **Games** view. One YAML file per challenge, plus
one generated cover image.

```
_registry/
├── schematic.md              ← this spec
├── challenges/<slug>.yaml    ← one metadata file per challenge (final)
├── covers/<slug>.png         ← one generated cover per challenge (final)
└── avatar/<contributor>.png  ← contributor GitHub avatar, by handle
```

Covers are referenced per-challenge via `cover.image`. Contributor avatars are
addressed by convention: `avatar/<contributor>.png` for the `contributor` handle.

The **generation tooling** (metadata + cover-image generators) lives in a
**separate standalone dir outside the warehouse**; only the finished `.yaml` and
`.png` artifacts land here.

---

## The join key

`slug` == the challenge's `Challenge.name` (kebab-case, globally unique). This is
the same value that already appears as `challenge` on a trajectory, so a match
thread can link straight to its challenge card and the Games view can show
"played in N matches".

---

## Provenance of each field

Every field is one of:

- **⚙ derived** — read deterministically from the challenge package (no LLM). If
  regeneration disagrees with code, code wins.
- **✎ inferred** — written by the LLM pass from `ChallengeDocs.intro` + code.
- **⊹ generated** — produced by the cover-image step.

---

## Field reference

```yaml
slug: aiohttp-lfi              # ⚙ Challenge.name — unique join key
title: "aiohttp Path Traversal"# ✎ human display name (slug is too terse); Title Case, ≤ 40 chars
contributor: LEAFERx           # ⚙ warehouse dir (credit only)
updated: 2026-07-20            # ⊹ ISO date (YYYY-MM-DD) — stamped by the generator on every write

tags:                          # ✎ flat, multi-valued, drawn from the Tag Pool below.
  - web                        #   3–6 tags per challenge, spanning facets (origin / surface / vuln / tech / mechanic).
  - real-world                 #   These drive the card badges AND the Games-view filters.
  - path-traversal
  - lfi
  - python
  - aiohttp
  - cve

classification:
  difficulty: easy             # ✎ ordinal, NOT a tag: easy | medium | hard
  vuln_class: "Directory Traversal"  # ✎ display headline for the card (human-readable, distinct from machine tags)
  cve: CVE-2024-23334          # ✎ string | [list] | null  (precise identifier when one exists)

card:                          # ✎ the copy the card renders (all distilled from source_intro)
  tagline: "One symlink flag flips a static server into an arbitrary file reader."
                               #   punchy hook, ≤ 90 chars, no trailing period optional
  summary: >                   #   2–3 sentences; card back / expanded panel
    aiohttp 3.9.1 registers /static/ with follow_symlinks=True, skipping the
    path-containment check, so ../ escapes the web root and reads any file the
    server process can reach.
  attack: "GET /static/../../../opt/secret/flag.txt through the traversal."   # one line: how the flag is stolen
  defense: "Drop follow_symlinks=True in server.py and restart the service."  # one line: how to patch

origin:                        # ✎ where the challenge comes from — CTF vs real-world are BOTH first-class
  type: real-world             #   ctf | real-world  (also mirrored as a tag, for filtering)
  source: "aiohttp"            #   real-world: the product/library/repo · ctf: the event/competition name
  reference: CVE-2024-23334    #   real-world: the CVE/advisory · ctf: the edition/round/challenge id · null if none
  url: "https://github.com/aio-libs/aiohttp"   # ✎ optional — repo, CVE page, or writeup; null if none

service:
  protocol: web                # ⚙ from the exposed_ports key: web | tcp
  ports: { web: 8080 }         # ⚙ exact exposed_ports map
  stack: "Python · aiohttp 3.9.1"    # ✎ language/framework + pinned version when known

provenance:
  image: "cyberarena/chal-aiohttp-lfi:v1"   # ⚙ vulbox docker reference
  source_intro: >              # ⚙ verbatim ChallengeDocs.intro — traceability + fallback text
    aiohttp 3.9.1 static file server — directory traversal (CVE-2024-23334). The
    /static/ route is registered with follow_symlinks=True, which on aiohttp
    <= 3.9.1 skips the path-containment check, so GET /static/../../../<path>
    reads arbitrary files the server can access. Flag at /opt/secret/flag.txt
    (mode 600, owned by appuser). Defense: edit /srv/challenge/server.py to drop
    follow_symlinks=True and restart_service.

cover:
  image: covers/aiohttp-lfi.png# ⊹ path relative to _registry/
  accent: "#c8472b"            # ⊹ dominant color sampled from the cover, for per-card theming
  prompt_id: geo-v1            # ⊹ id of the prompt template that produced it (reproducibility)
```

The example above is **real-world** (a library CVE). The other world is **CTF**
— same schema, the `origin` block and tags differ:

```yaml
# nautilus-ico (excerpt) — a CTF-origin challenge
tags: [ctf, binary, memory-corruption, pascal, recompile]
origin:
  type: ctf
  source: "Nautilus Institute Finals 2025"   # the competition
  reference: ico                              # the original challenge id/round
  url: "https://github.com/nautilus-institute/finals-2025"
classification: { difficulty: hard, vuln_class: "Binary Service Exploitation", cve: null }
```

---

## Tag Pool

A **single flat, extensible vocabulary** — a challenge carries any mix. Grouped
here into facets only for readability and so the frontend can color by facet;
in the YAML `tags:` is one flat list. **Prefer an existing tag; a genuinely new
one may be added, but the generator must flag new tags for review** (keeps the
pool from sprawling).

**Origin** — where the challenge comes from (see the `origin:` block)
`ctf` (lifted from a CTF competition) · `real-world` (a real product/repo vuln,
usually with a CVE)

**Surface** — the classic category axis
`web` · `binary` · `crypto` · `rev` · `net` · `misc`

**Vulnerability class** — what the bug is
`path-traversal` · `lfi` · `rce` · `command-injection` · `sqli` · `ssrf` ·
`xxe` · `deserialization` · `auth-bypass` · `memory-corruption` · `info-leak` ·
`logic-bug` · `race-condition` · `ssti` · `file-write` · `jwt` · `steganography`

**Tech / ecosystem** — where it lives
`python` · `php` · `go` · `node` · `ruby` · `c` · `pascal` · `flask` ·
`aiohttp` · `django` · `nginx` · `docker`

**Mechanic** — arena-specific flavor
`patch-source` (fix by editing source) · `recompile` (defense recompiles a
binary) · `config-fix` (fix is config, not code) · `cve` (has a published CVE)

---

## Conventions

- **slug / tags**: lowercase kebab-case. Tags never contain spaces.
- **null**: use `null` (or omit) for absent optional fields — `cve`, and any
  facet with nothing to say. Never invent a value.
- **Lengths**: `title` ≤ 40, `tagline` ≤ 90, `summary` 2–3 sentences, `attack`/
  `defense` one line each.
- **Determinism**: ⚙ fields are re-derived from code on every run and overwrite
  prior values; ✎ fields are only (re)written when missing or when `--force`.
- **Style**: card copy is concrete and specific (name the route, port, file,
  CVE) — never generic ("a web vulnerability").

---

## Generation pipeline (next steps — pending confirmation)

1. **Metadata pass** — a standalone agentic workflow reads each challenge
   package, fills ⚙ deterministically, and runs one LLM pass for ✎, emitting
   `challenges/<slug>.yaml`.
2. **Cover pass** — generate one cover per challenge via the image API
   (`gen.api.json`, gpt-5.4-image-2), in a **uniform high-geometric style**
   consistent with the Riso-Zine frontend (varied color, shared geometric
   language), then sample `cover.accent` and write `covers/<slug>.png`.

Both generators live in a standalone dir; outputs are written back here.
