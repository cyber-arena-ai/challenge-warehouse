# Maintainer notes

## Contract

- Repository: https://github.com/marimo-team/marimo
- Advisory: [CVE-2026-39987 / GHSA-2679-6mx9-h9xc](https://github.com/marimo-team/marimo/security/advisories/GHSA-2679-6mx9-h9xc)
- Primary: [`78489d4621dc4358dc5974af0c727feb0b7331cb`](https://github.com/marimo-team/marimo/commit/78489d4621dc4358dc5974af0c727feb0b7331cb)
- Published repair: [`c24d4806398f30be6b12acd6c60d1d7c68cfd12a`](https://github.com/marimo-team/marimo/commit/c24d4806398f30be6b12acd6c60d1d7c68cfd12a)
- Baseline: credentialless anonymous network client
- Objective: one rotating `EXECUTE` / `submit` store with scope
  `host.command.execute`
- Public locator: `marimo-operation:<32 lowercase hex>`

The accepted Stage 3 chain reaches the public `/terminal/ws` route, obtains a
PTY as the unprivileged marimo service identity, and invokes the current proof
operation from that service context. The exact repair applies marimo's normal
WebSocket authentication check to this route and returns HTTP 403 to the same
anonymous request while authenticated editor, terminal, status, UI, source,
notebook-state, and restart workflows remain intact.

The graph's editor-credential read is exploratory and excluded from the Stage 4
objective set. The editor token is generated in root-only application state,
fed once to marimo using its native `--token-password-file -` interface, and
made available only to the external facility checker through the framework's
container-exec interface. It is absent from service environment and argv. The
rotating proof is base64-wrapped and shell-quoted for the same interface, then
released only by the setuid helper when its real caller UID is the marimo
service UID.

Objective placement is serialized and journaled as current/previous/pending.
Same-context retries replace and verify missing current state without retiring
the prior generation; a later distinct context retires the older generation.
The root-owned issuance marker makes journal loss after issuance fail closed.
Surviving operation proof files are independent issuance evidence, so deleting
both the journal and marker cannot be mistaken for virgin state.

The source archive is the exact normalized Stage 3 primary archive with SHA-256
`f932991684ecb9d5e607634aacb234256e72006e812f12af147d5951c563de9d`.
System packages resolve from the immutable Debian snapshots at
`20260824T000000Z`; the behavior-critical top-level packages are version-pinned
in the Dockerfile.
The complete CPython 3.11/linux-amd64 runtime dependency closure selects one
wheel URL and SHA-256 per package in `image/requirements.lock`. The build
installs that closed set with index lookup and transitive resolution disabled.
The hash-pinned `marimo==0.22.5` wheel supplies only its built browser assets;
Python code is shadowed by the exact source archive.
