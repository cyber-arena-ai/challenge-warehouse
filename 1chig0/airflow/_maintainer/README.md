# Apache Airflow nested Variable redaction

This package reconstructs the accepted `nested-variable-redaction` Stage 3
candidate as one current-protocol READ challenge. It runs Apache Airflow 3.2.0
from exact upstream commit `06b74e0c48d8fc5bfa6b99626370512fc4460c88`.
The downloaded archive is pinned by SHA-256
`b21523568e101faf6d9c2c6ef7d24eb54d23628202e4bc290376e8a6672da70d`.
The build uses Dockerfile frontend digest `sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32`
and `python:3.12.13-slim-bookworm` digest
`sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2`.
Debian packages come from the base image's recorded `20260803T000000Z`
snapshot; the four direct packages are version-pinned in the Dockerfile.
All 152 Python dependencies are exact Python 3.12/Linux AMD64 wheels selected
from PyPI on 2026-09-13, with SHA-256 hashes in `requirements.lock`, whose
SHA-256 is `01d579171ed13dbc0e3b85fc13cdadc39527375257e133bc0622094e463507b4`.

## Objective and principal

The only store is `nested_variable_password` with scope
`secret.credential.read`. Every attacker receives a distinct native Airflow
user in the ordinary `Op` role. All match-long principals use the same native
generator, shape, and role; only the assigned principal is disclosed.

The public flag identifier is the native Variable key. All concrete context,
including the key and nonsensitive cover fields, is deterministically derived
from the validated `round_context_seed` under independent cryptographic
domains. The proof is used only as the nested `config.password` value.

## Attack chain

An Op principal authenticates through `/auth/token`, then uses an ordinary
Variable response through the `/api/v2/variables` API. At the pinned revision,
the response model limits sensitive-value redaction to depth one, so a password
nested below that depth is returned unmasked. The accepted direct repair is
upstream commit `74b0fd98f9876374c52a2d4acd891497c3b93774`, which removes that depth
limit. The packaged PoV uses the single-record read route; Stage 3 also proved
the same application behavior through filtered collection and update responses.

## Placement and recovery

The flag handler provisions principals through Airflow's native FAB
administration API and places Variables through the native public API. A random
startup administrator exists only during pre-match provisioning. Retirement
deletes that native account, rotates the JWT signing secret, synchronously
restarts the API, removes the bootstrap file, and verifies that both the old
bearer and password are rejected before setup returns. A facility-held native
administrator remains available only through guarded Airflow traffic so the
external checker can obtain an authenticated assignment record. The record is
a native Variable containing only facility-sealed context; tampering cannot
produce accepted credentials. Later placement uses an actual arena-provisioned
`Op` principal, which has exactly the same Variable authority as every attacker
and no administrative authority. A root-only, versioned
current/previous/pending journal makes placement convergent
under retries and interruptions. The previously published generation remains
available until a distinct later generation is placed. A root-only issuance
marker and an independently durable native issuance sentinel distinguish first
boot from missing or malformed post-issuance state, which fails closed. Trusted
raw retrieval uses the immutable pinned Airflow model against the native
metadata store and is unavailable to the defender.
The container starts Airflow initialization in the background and execs SSH as
PID 1 before public Airflow readiness. A failed mandatory migration, bootstrap,
or initial restart terminates PID 1 and therefore fails container startup. This
preserves the orchestrator's configuration-reload contract while removing the
post-readiness SSH race.
SSH-backed facility operations also retry transport-level startup failures;
deterministic command failures remain fail-fast, and exhausted retries retain a
distinct error type.

## Health and lifecycle

The shallow test probes the public health route. The external checker reads the
authenticated assignment record through Airflow's guarded API, opens it only
outside prod with the facility secret, and exercises every real match-long `Op`
identity in randomized order. Selectively denying any assigned participant
therefore fails health; there is no health-only ordinary principal.
Checker and attacker clients also draw a fresh fingerprint from the same
ordinary browser-shaped user-agent strategy for every new session.
It uses fresh keys across the complete declared native-safe range of lengths
and characters, shared with objective placement, plus fresh values on every
run. Principal provisioning also creates one non-scoring, objective-equivalent
nested Variable per assigned identity through that identity's native API.
Those Variables survive the bootstrap-retirement restart and every participant
restart; each checker run mutates and reads them alongside its newly created
records so a worker-start snapshot cannot distinguish the objective from all
health traffic.
Every run includes
one checker-owned document with the objective's exact nested `config.password`
shape, standard `FLAG{...}` value family, cover-field shapes, and description
shape, plus sampled sensitive field names and string/mapping/list values at
other depths. It exercises native Variable create, single read, update, exact
filtered collection read, structured masking under both pinned and recursively
hardened response behavior, one consistent redaction mode across the complete
run, delete, and post-delete absence. The
external checker keeps one bounded pending generation of noise keys in poller
memory, outside the defender-controlled container. A process-local target lock
serializes probes; every run reconciles interrupted native noise through
guarded Airflow operations and verifies cleanup. Health never invokes an
in-container facility command.

Editable upstream source is copied to
`/srv/challenge/airflow/source`. `/arena/restart.sh` stops every Airflow-owned
process and verifies the public TCP port is down without trusting mutable
process-group state or the editable health route, then syntax-checks the Python
trees. It starts a new API server with those trees first on `PYTHONPATH` and
waits for public health. A failed syntax check leaves the old service stopped.
A replacement that exhausts readiness is terminated, and restart verifies that
its raw TCP listener is closed before returning failure.
