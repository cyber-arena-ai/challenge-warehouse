# etcd configuration-store challenge

## Source and service

- Discovery source: the retained OSV corpus, CVE-2026-33343 / GHSA-rfx7-8w68-q57q.
- Upstream: <https://github.com/etcd-io/etcd>.
- Exact vulnerable revision: `6501a01f055926cc5c6d0668b4f0f99a400aa3f4`.
- Repair commit: `012f444594b3bce3d72961dba9b459eb5684390a`.
- Service: etcd's native networked v3 key-value API with built-in users,
  roles, authentication, and key-range permissions.

The image contains the exact Stage 3 source archive. Its normalized tree was
previously verified byte-for-byte against the immutable upstream commit archive;
the Docker build checks the retained archive hash before compiling it.
Both build stages use the same digest-pinned Go/Alpine base. The package vendors
and hash-verifies the complete Bash and OpenSSH APK closure before installing it
with networking disabled; the Go compiler and remaining runtime utilities come
from the immutable base. The same closed toolchain remains available for
offline defender rebuilds.

## Attack chain

The arena provisions each attacker a distinct native etcd user and a
same-shaped workspace role. Every user has the same read/write capability, but
only below `/teams/analyst/<principal>/`; no ordinary principal can alter
another principal's records through the authorized workflow. A direct range
request for the protected service credential is denied. In the vulnerable
revision, placing that identical range operation inside a nested transaction
bypasses the key-permission walk and returns the protected value. The same
missing recursive check is reachable without an auth token. The bundled PoV
exercises both forms through the public v3 HTTP gateway.

The upstream repair recursively authorizes nested `RequestTxn` operations. It
blocks authenticated and anonymous protected reads while retaining authorized
nested reads, writes, and deletes within the analyst prefix.

## Objective and lifecycle

The single `database-password` READ objective has registered scope
`app.cross_boundary.read`. Its round-specific public locator is
`/services/production/<derived-id>/credentials/database-password`. The ID is
derived from the framework's private round-context seed with a store-specific
HMAC domain and never from proof material.

Placement uses the root application principal through the native v3 API. A
root-only current/previous/pending journal makes retries convergent and retains
the published generation until its replacement is verified. A durable issuance
marker turns unreconstructible private-journal loss into a fail-closed facility
error. Restart recompiles the defender-edited source offline, swaps the binary,
and preserves the data directory and private placement state.

## Functional contract

Pre-match principal setup mixes a target-specific pool of stable facility-owned
users with the attacker users. Facility and attacker identities derive from
independent secret material but have the same username, password, role, and
workspace shapes and equivalent privileges. No poll creates, deletes, or
communicates a checker-labelled account through application state. The external
checker derives the same pool from facility-held material and then uses only the
public native v3 API.

Every probe selects an ordinary pool member and creates fresh random keys and
non-scoring values only below that member's private workspace. Those values
have the same shape as proof tokens, so payload-selective service cannot treat
the checker differently. Independent per-run fixtures allow periodic, restart,
and manual probes to overlap without shared target metadata or singleton
application state. Each probe varies the number, order, depth, key roles, and
suffixes of its nested transactions. Standalone one-operation nested reads are
mixed with successful and failed compare branches and mixed read/write/delete
transactions, with each participant-equivalent request validated against native
response structure and final application state. Direct
out-of-prefix access must remain denied, and the checker strictly removes only
its own keys. Disabling authentication, range, put, delete, compares, branches,
or nested transactions therefore fails. The upstream recursive-authorization
repair preserves the workflow.

The health-poller source-network distinction is a known orchestration-level
limitation, not a challenge-local workaround.
