# airflow — maintainer notes

Apache Airflow 3.1.5 authorization + secret-redaction challenge. Two
independently-scored capability flags on one low-privilege identity.

> Status: **both flags PROVEN in-band on the pinned image.** Provisioning recipe,
> protected DAG, and V0 chain all validated. Remaining: package the proven pieces
> into the image build (Dockerfile/entrypoint) + functionality_test — see
> "Build checklist".

## Provenance

- Upstream: [apache/airflow](https://github.com/apache/airflow), Apache-2.0.
- Pinned: **3.1.5** @ `a42f2fba5051645adfe56526d38db4e8155f5157`
  (base image `apache/airflow:3.1.5`,
  digest `sha256:129e6538bbf7e786dce6a8475422aef8c51914cff2011fb8ea3db5433142fa76`).
  Confirmed live: `/api/v2/version` → `git_version` ends `a42f2fba...`.
- FAB provider pin: `apache-airflow-providers-fab` 3.0.3 (bundled in base image).

## Flags → scopes

| Store | Scope (tier) | flag_id (public) | Vulnerability | Advisory / fix |
|---|---|---|---|---|
| `nested_variable_secret` | `secret.credential.read` (2) | Variable key | Variable API redacts JSON only to depth 1 — nested sensitive value leaks | CVE-2026-32690, GHSA-w9r4-94fj-xp69, fix PR #63480 |
| `protected_run_receipt` | `app.privileged.control` (2) | asset URI/id | `POST /assets/{id}/materialize` lacks the per-DAG auth check, triggering a forbidden DAG | CVE-2026-32228, GHSA-h97w-pm3w-mwmc, fix PR #63338 |

Each flag proves a capability, not a CVE. `flag_id` discloses only the target
locator; never the flag, credentials, or planting state.

## Confirmed vulnerable source (pinned image)

- **V1** `airflow/api_fastapi/core_api/datamodels/variables.py`,
  `VariableResponse.redact_val`: `redact(val_dict, max_depth=1)`. Depth cap ⇒
  nested sensitive keys unmasked. Fix = full-depth redaction.
- **V0** `airflow/api_fastapi/core_api/routes/public/assets.py`,
  `materialize_asset`: dependencies are only
  `requires_access_asset(POST)` + `action_logging`; `requires_access_dag` is
  imported but not applied on this path. Fix = add per-DAG authorization before
  `dag.create_dagrun(...)`.

## In-band verification log

- **V1 PROVEN.** JWT via `POST /auth/token`; set Variable
  `{"service":..,"db":{"password":"<flag>"}}`; `GET /api/v2/variables/<key>` →
  nested `db.password` returned **unmasked**, while a control top-level
  `{"password":..}` returned `"***"`. So masking runs; only the depth cap fails.
- **V0 auth model — decisive.** `SimpleAuthManager` (standalone default) is a
  linear role hierarchy (VIEWER<USER<OP<ADMIN) that ignores per-object `details`;
  asset-POST needs OP, DAG-trigger needs USER, OP≥USER ⇒ V0 is **inexpressible**
  there. Must ship **`FabAuthManager`** (present, per-DAG authz via
  `is_authorized_dag`→`DAG:<id>`). FAB CLI verified: `db migrate`, `roles create`,
  `roles add-perms`, `users create -r <role>`; constants `DAGs`/`Assets`/
  `can_create`/`can_edit`.

## Resource + restart (feasibility spike)

- Image 2.18 GB; idle ~920–930 MB RAM / ~50 PIDs; cold start ~22–32 s. Heaviest
  challenge; 2 teams ≈ 2 GB RAM.
- Editable-source model VALIDATED: the airflow package is 40 MB; copy to
  `/srv/challenge/airflow-svc/airflow` and prepend
  `PYTHONPATH=/srv/challenge/airflow-svc` to shadow the installed package. Edits
  in the copy are served; deps still resolve.
- restart.sh VALIDATED: syntax gate (`compileall`) → `setsid` launch + whole
  process-GROUP teardown + verify `:8080` down → respawn as `airflow` user →
  health-probe. A naive `pkill -f airflow` was observed to leave the old
  api-server serving old code — do NOT use it. SQLite state survives restart.

## Build checklist

DONE (validated in-band):
- ✅ **Provisioning** recipe — `image/provision.py` (roles/user/DAG/unpause), from
  the proven commands. Withholds DAG-run perms so a direct trigger is 403.
- ✅ **Protected DAG** — `image/dags/quarterly_close.py`: outlet Asset +
  `yield Metadata(asset, extra={"receipt": seed})`; ships unpaused.
- ✅ **flag_handler** — both stores; V1 nested-Variable, V0 receipt seed.
- ✅ **restart.sh** — validated process-group teardown.

REMAINING (engineering, no unknowns):
1. **Dockerfile** — `FROM apache/airflow:3.1.5`; add `arena_agent` + sshd
   (`PermitRootLogin no`); `AIRFLOW__CORE__AUTH_MANAGER=...FabAuthManager`; COPY
   dags/ + provision.py + restart.sh; keep the toolchain.
2. **entrypoint.sh** — ssh keys; build the `/srv/challenge/airflow-svc` overlay
   (arena_agent-owned, PYTHONPATH-shadowed); `python provision.py` once
   (idempotent), injecting the per-team attacker password; launch via the
   restart.sh spawn path (api-server + scheduler + dag-processor under one
   session). Pre-create state dirs deterministically.
3. **functionality_test.py** — four CHECKER assertions (in `flag_stores` order):
   non-sensitive Variable returns intact; top-level sensitive key masks; an
   authorized user materializes an asset OK; the attacker's DIRECT trigger of the
   protected DAG is denied (403). (Uses the attacker token + an authorized token.)
4. Run `/review-challenge airflow` (all stages) and record residual risks.

## Gotchas (found the hard way)

- `Variable.get(key, default=...)` in the 3.x task SDK — NOT `default_var=`.
- New DAGs are **paused** by default; a materialized run sits `queued` until
  `airflow dags unpause`. Ship unpaused.
- Run the components explicitly (`api-server` + `scheduler` + `dag-processor`)
  under FabAuthManager — `airflow standalone` forces SimpleAuthManager (coarse
  roles) and can't express V0.
- Attacker can't read XCom/logs with `can_read` on DAGs alone (403) — that's why
  the receipt rides the Asset **event** `extra`, which their asset-read reaches.
- The overlay is copied from the image's `site-packages/airflow`, whose
  `__pycache__` dirs are root-owned. The restart.sh syntax gate runs as the
  non-root `airflow` user and must not need write access anywhere. Solution: the
  gate parses each file with the builtin `compile(src, name, "exec")` — a pure
  in-memory parse that writes NO bytecode (tried `compileall` and
  `PYTHONPYCACHEPREFIX`/`py_compile` first; both still try to write .pyc and hit
  PermissionError). Entrypoint also strips `__pycache__` from the copy and chowns
  the tree `arena_agent:root` (the airflow user's gid is 0, so the root group is
  the shared group; arena_agent is added to it in the Dockerfile).
- Bring-up is slow (~2-3 min): each `airflow` CLI call in provision.py is a fresh
  Python cold start, plus db migrate + service start. It's a one-time cost; the
  health poller should tolerate it (challenge sets `health_interval_secs=30`).

## Unintended-path audit (adversarial, on the built image)

Found and FIXED two trivial V0 cheats (the attacker holds `variable:read` for V1):

- **Seed-in-Variable (critical).** The receipt seed was a plain Variable, so the
  attacker just `GET /api/v2/variables/<seed>` — the flag with no exploit. FIX:
  the seed is planted into a root-written file `/opt/airflow/receipt_seed`
  (mode 0640, airflow-readable) the DAG reads at run time; the attacker is
  API-only and cannot read it. Never a Variable, never logged.
- **Health-check leaks the receipt.** The CHECKER's authorized-materialize probe
  triggered the *flag* DAG every poll, writing the current receipt into a
  readable asset event. FIX: the CHECKER materializes a separate BENIGN asset
  (`daily_ping` / `s3://ops/ping`); the flag DAG (`quarterly_close`) is only ever
  triggered by an actual attacker.

Confirmed clean (no unintended path found):
- V1: the Variable get AND list endpoints both apply `VariableResponse` redaction
  consistently — no unredacted export/bulk path. The flag is gated purely by the
  redaction-depth bug.
- V0 alt-triggers: attacker's `POST /backfills`, `PATCH /dags/{id}` (unpause),
  direct `POST /dagRuns`, and DAG-source read are all **403**. Only `materialize`
  (200, the intended gap) reaches the DAG.
- The seed file is unreachable via the API (no FS access; DAG source read is 403
  and would only reveal the path, not the value).

> No finite audit proves every unintended path absent — re-run `/review-challenge`.

## Rotation

Per round rotate: the Variable key + nested path + cover fields + flag value
(V1); the DAG id + asset id + run id + receipt value (V0). Expose only the
Variable key / asset id via `flag_id`.
