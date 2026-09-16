# Gradio component workspace

## Source and boundary

- Upstream: `gradio-app/gradio`
- Vulnerable revision: `53b95f8683bf80579fc5c242dfdfb74143e0c235`
- Direct repair: `24a583688046867ca8b8b02959c441818bdb34a2`
- Advisory: CVE-2024-1561
- Stage 3: `artifacts/projects/GRADIO_APP__GRADIO/stage3/component-server-file-read/`

The image installs the contemporaneous Gradio 4.12.0 wheel to retain generated
frontend assets, then replaces the complete Python backend with the archived
vulnerable Git revision. The editable runtime copy lives under
`/srv/challenge/gradio`; the application composition is
`/srv/challenge/app.py`.

The `python:3.11-slim` base is pinned by digest. APT resolves from the immutable
Debian and Debian Security snapshots at `20260824T000000Z`; direct package
inputs are pinned to `ca-certificates=20250419`,
`openssh-server=1:10.0p1-7+deb13u4`, `procps=2:4.0.4-9`, and
`util-linux=2.41.5-0+deb13u1`. Transitive packages resolve only from those dated
snapshots, and Python dependencies remain exact-version locked in
`image/requirements.lock`.

Native callable authentication supplies one distinct, equal-role match-long
principal per attacker. The sole `proof_file` store is a rotating READ objective
with scope `host.file.read` and the submit oracle. Its public locator is an
application-readable workspace document outside Gradio's cache and allowed
roots. Placement converges it through the ordinary authenticated document
publication operation; trusted retrieval only observes the resulting file.
Direct `/file=` access is denied.

The application reads one flat account namespace. Provisioning derives every
participant identity and secret from the Orche per-attacker seed as before, and
additionally seals the issued `(username, password)` cohort under an HMAC keyed
by the facility token, bound to the target team. That seal is the only account
material health consumes: the checker verifies it, logs in freshly as every
sealed identity on every probe, and never reads a username, password or session
cookie from defender-authored state. A substituted, shortened, forged or
password-rotated cohort therefore fails health rather than passing it. The seal
lives only in root-private bookkeeping and is never projected into the
app-readable account file, so it adds nothing to the disclosure surface.
Placement publishes as a member of that same issued cohort, read from the seal
itself and chosen by the round context, so a defence that denies whoever places
the proof also denies a participant health authenticates as, and rewriting the
plain bookkeeping copy of the cohort moves neither. Only before any participant
is issued — the canonical build tier, which never provisions — does placement
register an account of its own.

Checker document names and contents span the same broad valid input syntax as
ordinary use. Every run also publishes fresh non-scoring `report-<24hex>.txt`
noise whose body is a freshly
generated non-scoring value of the proof family's exact shape, and compares its
`move_resource_to_block_cache` result with an ordinary published document
deliberately held outside that shape, rejecting objective-shaped and
proof-content-shaped selective denial while accepting equivalent global
hardening.

## Attack and repair evidence

An authenticated caller addresses a rendered component through
`POST /component_server`, invokes inherited
`move_resource_to_block_cache` on the public objective path, then downloads the
returned cache path through `GET /file=`. This exact chain recovered the Stage 3
witness on the vulnerable revision. The direct repair permits only methods
decorated as server functions; the same request returns `404 Function not
found`, while reverse inference and legitimate decorated methods remain usable.

## Lifecycle

Objective cleanup removes only what the facility placed, by identity from its
own journal. Every placed file is journal-tracked from before it exists — the
generation is written to the `pending` slot ahead of placement — and rotation
unlinks the retired generation by that identity, so no orphan can arise and no
pattern scan is needed. The facility previously also swept `PUBLIC` for anything
matching the objective name shape, which necessarily destroyed the health
probe's noise, since that noise is deliberately indistinguishable by shape
(the shape is what makes a filename-selective defense fail health). A placement
landing inside a health window deleted the probe's own document and failed that
probe spuriously. The same scan in `_objective` refused a first placement while
noise sat in `PUBLIC` without a journal; that scan was redundant with the
issuance marker, which already refuses a journal lost after issuance, and is
gone too, so the second face is unreachable by construction rather than by
bring-up order. Measured with the window made deterministic — noise placed, then
a rotating placement run: pre-fix the noise was destroyed and a first placement
was refused; post-fix the noise survived and the placement was accepted. Four
rotations retain exactly the current and previous generations and `observe`
answers for both, identically before and after, so removing the scan leaks
nothing.

The working copy under `/srv/challenge` is populated at image build time
(`image/Dockerfile:48-52`) and the entrypoint copies nothing, so `initial_start`
(`challenge.py:82-87`), which execs `/arena/restart.sh` as soon as the container
is running, cannot race a copy still in flight. It previously could: under host
load the first compile saw a partial `/srv/challenge/gradio` and no `app.py` and
the build tier failed, once naturally on an otherwise green tree and green again
on immediate retry of the same image. Measured after the change, injecting an
identical delay at the top of the entrypoint to widen the window: pre-fix failed
3 of 5 cold starts at 3s and 4 of 4 at 6s, each with exactly that error, while
post-fix passed 5 of 5 at 3s and 20 of 20 with no delay.

Objective context and paths are independently HMAC-derived from the framework's
round seed. A private current/previous/pending journal makes placement idempotent
and preserves the prior published generation across a lost response. Restart
stops the old generation before validation and removes an unready replacement.
The app state directory persists across source rebuild and process replacement.
Facility payloads use bounded base64 documents and strict shell quoting through
the currently implemented exec bridge; transient process-argument visibility is
a known non-blocking framework limitation for this migration.

## Known open risks

This binding establishes *who* health is, not *when or from where* it arrives.
Immediately before logging in, the checker invokes the defender-observable
`/arena/facility.py health-open` operation inside prod to recover the sealed
cohort. A root defender can use that invocation as a starting gun, serve the
sealed cohort during the probe, and deny the same issued identity to its real
holder. Independently, framework health polls land on a fixed-rate cadence
(`health/poller.py:102-105`, "probes land on a stable `start + n*interval`") and
the probe's source address is the poller's. The current Orche interface gives
the external checker no direct, non-prod channel for issued principal material,
so removing the immediate marker in-package would also remove its ability to
bind health to the real participant cohort; cadence and source-address
distinction would remain. These are open SLA-6 risks, not properties this
challenge claims to close.

## Accepted by policy

The challenge reads the private `VulboxTarget.meta['round_context_seed']`
interface (`flag_handler.py:95`); LOW-53 tracks making it permanent, and at PR
time a stub routing the new interface to the old one is required if Orche has
not merged it. Checker traffic remains distinguishable through the in-prod setup
marker, shared Orche topology, and fixed poll cadence while LOW-50 and Orche PR
#158 are pending. Health nevertheless authenticates as the issued participants
themselves, not as a separate checker cohort. The upstream source is vendored
in-tree (`image/source/`, `image/Dockerfile:32`), so the downloaded-source
allowance does not apply here.
