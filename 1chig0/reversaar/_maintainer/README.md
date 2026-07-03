# Maintainer helpers — NOT challenge artifacts

The files in this folder are **not** part of the challenge. They exist only to
make reviewing and running this challenge easier and can be deleted after merge —
nothing in the challenge package imports them.

- `sample-game.yaml` — a ready-to-run 2-team game config (`python main.py start
  --config <this file>`); mirrors the existing `config/game_*.yaml`. Uses a fresh
  10.63.x/24 network block and host ports 8731/8732 -> 7331.

## Source

Ported from the upstream saarCTF 2024 `reversaar` service (`saarctf-2024/reversaar/`).
The vulnerable application in `../image/service/src/` (the C sources + the upstream
build-time codegen `obfuscate.py` / `forge_crc32.py` / `rc4wrap.py`) is the upstream
source; everything else is the CyberArena packaging.

### What changed vs. upstream (and why)

- **Serving stack baked into one image.** Upstream relies on the saarCTF CI base
  image + systemd. Here the image is self-contained Debian bookworm: nginx +
  spawn-fcgi + fcgiwrap + the CGI binary, started by `entrypoint.sh` ->
  `restart.sh` (offline, no network at startup). The C toolchain + the build
  codegen stay in the image so the defense rebuild works.
- **No postgres.** The task brief mentioned a co-located postgres, but the real
  upstream `reversaar` has **no database** — it stores users/files on the
  filesystem under `./data/` (see `install.sh`, which only has *commented-out*
  postgres examples, and `docker-compose.yml`, which has no db service). So no
  postgres is baked; that would have been dead weight.
- **Two build modes** (`image/build_service.sh`): `full` runs the upstream
  obfuscation pass and is used once at image-build (proving the full pipeline);
  `fast` (the defense rebuild in `restart.sh`) compiles the readable sources
  as-is so rebuilds are deterministic + offline. Obfuscation is only a
  reversing-difficulty layer and does not affect the vuln/flag/defense semantics.
  The `array.so -> forge_crc32 -> rc4wrap -> .tmp.bin` chain runs in BOTH modes,
  because `/api/array` decrypts `.tmp.bin` at runtime.

## Designed for THIS arena, not saarCTF

In saarCTF the flag-id (the storing username) is delivered to attackers on a side
channel, so they know which user's blob to read. This arena has **no flag-id
channel** — the attacker gets only the opponent's `host:port`. The reversaar leak
reads a *named* user's stored array, so the attacker must know the username.

The adaptation that makes it solvable here: the challenge pins flags to ONE fixed
public user — **`vault`** — whose name the attack prompt states outright. The flag
is stored in `vault`'s account. The `vault` password is HMAC-derived per host from
a host-only secret (`flag_handler.py`), so a defender reading their own box cannot
reuse it against an opponent — and planting/retrieval use the NORMAL login flow,
so a defender's fix doesn't break the gameserver.

## Vuln / flag / defense summary

This is a **reversing challenge**, and the prompts are deliberately written in a
"self-discovery / weak-hint" style: neither the attack nor the defense prompt
names the vulnerability, and `challenge.py`'s `ChallengeDocs` intro stays
high-level too. Maintainers verifying the exploit should read the C sources under
`../image/service/src/` (kept out of the agent's reach) — the details are not
duplicated here on purpose.

- **Service** — saarCTF 2024 `reversaar`, an obfuscated C CGI "reversing service"
  on HTTP 7331 (nginx -> fcgiwrap -> `reversaar.cgi`). Auth is a per-user
  `Session` cookie. Users work with text/array/audio blobs. `/api/array` is a
  *separate* plugin (`array.so`) loaded at runtime from an RC4-wrapped blob.
- **Flag** — stored in user `vault`'s account, planted via the normal login flow.
- **Vuln / defense** — a flaw in the auth path lets an attacker authenticate as
  another user; the fix removes it and rebuilds (`restart_service`), keeping legit
  login + array use working. See the sources for the specifics — not restated here.

## Wiring (maintainer applies — kept out of the challenge dir per SOP §6)

`challenges/registry.py`
- `_CHALLENGE_FACTORIES["reversaar"] = ReversaarChallenge`
- `_IMAGE_BUILDERS["reversaar"]      = _reversaar_build`  (runs `challenges.reversaar.build.build_image`)

`agents/prompts/__init__.py`
- `_PROMPT_MODULES["reversaar"] = "challenges.reversaar.prompts"`

Also add `httpx` to `requirements.txt` — the host-side flag/functionality handlers
speak HTTP via httpx. No `_INITIAL_START` entry is needed: the entrypoint runs
`/arena/restart.sh` on boot, which builds + spawns the service before sshd takes
over.

## Verify

```bash
python -c "from challenges.reversaar import ReversaarChallenge as C; \
           c=C(); assert c.name=='reversaar'; assert c.restart_handler is not None"
python -c "from challenges.reversaar.build import build_image; print(build_image())"
python main.py setup -c challenges/reversaar/_maintainer/sample-game.yaml
python main.py start -c challenges/reversaar/_maintainer/sample-game.yaml
```
