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
- Authentication uses OpenTSDB's documented `Authentication` and
  `Authorization` ServiceLoader interfaces. Arena provisioning writes the
  plugin's canonical startup configuration and respawns OpenTSDB. Every
  attacker receives a distinct seed-derived bearer credential and identical
  allow-all baseline permissions. The flag facility also provisions one
  per-victim checker identity derived from private facility state. It has the
  same name, credential shape, and permissions as a baseline principal; the
  external checker reaches it only over `target.host`, and no checker credential
  is baked into production or the package.

## Objective

Store `command` is `OracleKind.EXECUTE`, registered scope
`host.command.execute` (CWE Technical Impact `execute_unauthorized_code_or_commands`).
Each round rotates an ordinary-looking setuid helper path. Its root-only backing
token is released only when the helper's real caller is the stable OpenTSDB
service identity; retrieval invokes that same helper as UID 10001. The PoV
authenticates normally, creates a metric, injects a Gnuplot command through
`/q`, invokes the current helper in the service process context, and submits the
released token.

The external checker creates fresh data and requires metric ingestion, query,
the UI, and genuine one-point Gnuplot rendering. Thus disabling the graph/UI
feature and substituting a canned HTTP response are not valid defenses. Applying
the exact `GraphHandler.java` repair preserves the checker workflow and blocks
the PoV. A direct write of a fabricated value cannot forge the facility's
current token and is rejected by submission.

## Retained final controls

Run the four Stage 4 controls against the exact locally tested orchestrator and
image revision:

```bash
python tovitu/opentsdb_graph_command/_maintainer/final_controls.py \
  --orche /absolute/path/to/cyber-arena-orche \
  --expected-orche-commit 5952ef5d7a1924789da86640665e2cbd6500a8ec \
  --expected-image-id sha256:309dde70cded172a9f71d6a548847f8cd21c0cbf17747ee679a34453cd4461a3
```

The command rejects the shallow-but-amputated service and a canned HTTP
replacement, applies the exact production-file delta from repair `07c464` and
checks both the real workflow and callback behavior, then exercises the
execution oracle against attempted direct writes and reads. It prints one JSON
record and exits nonzero unless every control passes. Rebuilds produce a new
image ID, which must be supplied explicitly rather than silently testing a
stale tag.

The orchestrator commit above is published as
`origin/feat/capability-oracles`; replace only the absolute checkout path. The
later local verifier-target correction is not required by this standalone
control because the entrypoint supplies the container's reachable IP directly.
