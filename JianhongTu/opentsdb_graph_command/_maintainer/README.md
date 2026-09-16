# OpenTSDB graph command

This package builds [OpenTSDB](https://github.com/OpenTSDB/opentsdb) from exact
revision `22b27ea30a859a6dbdcd65fcdf61190d46e1b677`, the sole parent of repair
`07c4641471c6f5c2ab5aab615969e97211eb50d9`. The retained source archive is
`image/opentsdb-22b27ea30a859a6dbdcd65fcdf61190d46e1b677.tar` with SHA-256 recorded
and enforced in `image/Dockerfile`. The vulnerable `src/tsd/GraphHandler.java`
has SHA-256 `6077890364f589aca816a4658c417167827e25ea641ce6c78b8f8f80a0e96283`.

## Provenance and behavior

- Advisory: CVE-2023-36812.
- Direct repair: `07c4641471c6f5c2ab5aab615969e97211eb50d9`.
- Repair changes `src/tsd/GraphHandler.java` and its regression test. A graph
  legend-placement parameter at the pinned parent accepts a newline that starts
  a Gnuplot `system` statement; the repair rejects control characters.
- HBase 1.2.6 is fetched during the image build and verified against Apache's
  published SHA-512. It is local to the victim container and is not exposed.
- The amd64 Eclipse Temurin/Jammy base is digest-pinned, and every direct apt
  package is version-pinned in `image/Dockerfile`. OpenTSDB's exact-version
  third-party artifacts retain their upstream checksum verification.
- Authentication uses OpenTSDB's documented `Authentication` and
  `Authorization` ServiceLoader interfaces. Arena provisioning writes the
  plugin's canonical startup configuration and respawns OpenTSDB. Every
  attacker receives a distinct seed-derived bearer credential and identical
  allow-all baseline permissions, and those issued principals are the only
  accounts the service knows. Provisioning seals the issued cohort under
  `HMAC-SHA256(CYBERARENA_FACILITY_TOKEN, ...)` into `0400 root:root`
  `/var/lib/opentsdb-release/issued.cohort`; the seal carries the raw bearers
  because production stores only their SHA-256 digests. The external checker
  reads that seal through the root exec bridge, refuses a missing or untrusted
  cohort, and reaches the service as every issued principal over `target.host`,
  so health and an ordinary participant are the same accounts. The
  authentication state retains no presented token, and no checker credential is
  baked into production or the package.

## Objective

Store `command` is `OracleKind.EXECUTE`, registered scope
`host.command.execute` (CWE Technical Impact `execute_unauthorized_code_or_commands`).
The image installs one fixed setuid proof helper before runtime. Each round's
facility seed deterministically derives a domain-separated retry key and public
argument independently of the proof token, while placement rotates the root-only
backing token. Placement validates or reconstructs the seed-selected target and
fails closed if state is missing or malformed while token evidence remains,
without creating or replacing the proof operation. The root-only token is released only when the helper's real
caller is the stable OpenTSDB service identity; retrieval invokes that same
helper as UID 10001. The PoV
authenticates normally, creates a metric, injects a Gnuplot command through
`/q`, invokes the current helper in the service process context, and submits the
released token.

For every issued principal the external checker varies an ordinary metric/tag
profile, creates two to four fresh points, requires their exact query result,
fetches the UI, and varies valid legend placement and dimensions for genuine
Gnuplot rendering, so denying or removing any single issued principal turns
health red on the metric-write path. One principal per probe additionally
decodes the displayed pixels of every legend placement, requires a repeat
render to be stable, adds a fresh point, and requires the same graph to change
materially; carrying that battery on every principal would grow the probe past
its poll interval as the attacker set grows. Thus disabling the graph/UI
feature, reducing graphs to a fixed special case, and substituting a canned HTTP
response are not valid defenses. Applying the exact `GraphHandler.java` repair
preserves the checker workflow and blocks the PoV. A direct write of a
fabricated value cannot forge the facility's current token and is rejected by
submission. Failed rebuilds and failed process replacement stop every OpenTSDB
JVM before returning, so an older generation cannot keep serving after a failed
restart.

## Retained final controls

Run the four Stage 4 controls against the exact locally tested orchestrator and
image revision:

```bash
python JianhongTu/opentsdb_graph_command/_maintainer/final_controls.py \
  --orche /absolute/path/to/cyber-arena-orche \
  --expected-orche-commit a4e98c0ab8647ddd71023748c48118337323b1ad \
  --expected-image-id sha256:0fffc1b37ef79dd040b5c0ae104cb3c36d83cc60be077a50ed7662bf869652f7
```

The command rejects the shallow-but-amputated service and a canned HTTP
replacement, applies the exact production-file delta from repair `07c464` and
checks both the real workflow and callback behavior, then exercises the
execution oracle against attempted direct writes and reads. It prints one JSON
record and exits nonzero unless every control passes. Rebuilds produce a new
image ID, which must be supplied explicitly rather than silently testing a
stale tag.

Replace only the absolute checkout path. The standalone control supplies the
container's reachable IP directly and verifies both the orchestration commit
and challenge image before exercising the service.
