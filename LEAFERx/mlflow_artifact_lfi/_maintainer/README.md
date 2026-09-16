# Maintainer evidence

The Stage 4 kernel is the accepted LOW-10 trace-authorization study, not the
older artifact-root package retained on this path. Its authoritative upstream
repository is <https://github.com/mlflow/mlflow>. The vulnerable source is
exact commit
[`5a73054b979c1927a2715bc58553f311cdbb7eeb`](https://github.com/mlflow/mlflow/commit/5a73054b979c1927a2715bc58553f311cdbb7eeb),
identified by
[`CVE-2026-8147`](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/8xxx/CVE-2026-8147.json).
The linked upstream repair
[`f9b1eb510478570609ef451984a255775aa4b937`](https://github.com/mlflow/mlflow/commit/f9b1eb510478570609ef451984a255775aa4b937)
adds the missing trace-route permission validators. The bundled primary archive has SHA-256
`7d2fd1b9aa0f54bd8924d4e8265496878d1bd0b3712185a35ade0f50165b8be7`.

The package preserves MLflow's own basic-auth users with `NO_PERMISSIONS`
defaults. The grouped round objectives are an owner-only trace metadata READ
and a protected trace-tag WRITE. All protected records are provisioned through
MLflow's HTTP API. The WRITE claim is bound to the exact trace and tag in a
trusted host-side snapshot of the tracking SQLite database.

The external checker exercises one facility-authenticated cohort containing every
arena-provisioned baseline principal, plus one equal-privilege peer only when a
two-team game would otherwise provide a single account. All are provisioned
through the same native API path with identical opaque credential and
experiment shapes. Issued principals and round-objective owners also use one
shared signed-username domain, so the service-visible signing secret cannot
identify one role without identifying the other. The flag service authenticates
the complete cohort with the shared facility secret, and the checker reads and
validates it through Orche's host-side authoritative-state interface, so prod
root cannot substitute health-only identities. Every run exercises every cohort
account with fresh trace experiment names and IDs, trace IDs, and broad
ordinary-looking field/value shapes without challenge-specific markers. One
randomly selected cohort member uses free-form values across MLflow's full safe
name syntax; the others use
semantic shapes. A different cohort member creates non-scoring noise with the
same combined experiment, trace, field, timestamp, and proof-value grammar as
round objectives. These values are fresh non-scoring noise, so a defense cannot
recognize and deny only that combination while keeping health green. Tag writes
use fresh standard-shaped `MARK{...}` values on checker-owned traces and read
them back without touching scoring state. Before sharing, every peer exercises
trace search, direct read, and tag mutation against another principal's trace;
the checker accepts either the uniformly vulnerable or uniformly denied route
family but rejects proof-shape-selective authorization. Each owner then grants
the peer native `EDIT` permission, and the same cross-owner operations must
succeed for both proof-shaped and ordinary noise. The checker also keeps direct
cross-account experiment access denied before the grant, so allowlisting the
manifest cannot keep health green while denying an issued participant. Cleanup
revokes each grant and targets only the exact traces and experiments created by
that checker run; it never deletes participant-created traces. The checker never
retrieves or uses the MLflow administrator credential.

The image uses the exact Stage 3 Python dependency lock and Python base image
digest. Its OS packages resolve only from the immutable Debian Trixie snapshot
`20260824T000000Z`, the timestamp recorded by that base image. The
behavior-critical packages are pinned to `openssh-server=1:10.0p1-7+deb13u4`,
`procps=2:4.0.4-9`, and `util-linux=2.41.5-0+deb13u1`; the TLS trust bundle is
also fixed at `ca-certificates=20250419`. Restoration of the advisory to the
global candidate manifest remains intentionally deferred by the migration
owner; the Stage 3 report records that separate provenance gap.
