# Gogs command-execution challenge

This package pins the [gogs/gogs repository](https://github.com/gogs/gogs) at
[`e3bb4165dceb96b66053a067f9f3584302413a0e`](https://github.com/gogs/gogs/commit/e3bb4165dceb96b66053a067f9f3584302413a0e),
the vulnerable revision selected for
[CVE-2026-52806 / GHSA-qf6p-p7ww-cwr9](https://github.com/gogs/gogs/security/advisories/GHSA-qf6p-p7ww-cwr9)
and repaired by upstream commit
[`a9dbafbfd8e1020bacc626420238c01d75d03364`](https://github.com/gogs/gogs/commit/a9dbafbfd8e1020bacc626420238c01d75d03364). The accepted
Stage 3 study is `artifacts/projects/GOGS__GOGS/stage3/`; the corresponding
current attack graph is `artifacts/projects/GOGS__GOGS/graph/stage3/`.

## Challenge contract

- Baseline principal: an ordinary self-registered non-administrator repository
  owner using Gogs' native signup, token, repository, Git HTTP, pull-request,
  and merge capabilities.
- Objective: `victim_execution_witness`, EXECUTE,
  `host.command.execute`.
- Target: one fresh opaque execution operation derived with a domain-separated
  HMAC from the framework round-context seed. The public locator contains only
  that operation identifier.
- Boundary and oracle: a root-owned setuid helper admits only the Gogs service
  OS identity and the current or immediately previous operation. A successful
  helper invocation returns the exact proof; HTTP failure alone never counts.
- Facility transport: placement and observation send their base64-encoded
  private request through the framework's privileged container-command bridge
  and pipe it to the facility process on standard input.
- PoV: `_exploit.py` obtains the operation from attack-info, creates only
  ordinary application-owned assets, attempts both accepted Git integration
  routes, publishes the helper result back through Git HTTP, and submits it.

Gogs passes a stored attacker-controlled base ref to Git without separating
options from operands. Both the native rebase merge and the final push used by
create-merge-commit can therefore reach command execution. The upstream repair
adds operand separation and routes clone/push through hardened Git helpers.

The checker derives fresh ordinary owners, emails, tokens, repositories,
descriptions, Git authorship, commit messages, branches, filenames,
pull-request text, and file content from a private checker-side seed. It
validates exact content and history for both native merge routes, keeps that
seed in a root-only interruption journal, and decisively deletes all
checker-owned application data. It never resolves the target through Docker or
trusts defender-controlled state.

The full source and Go module cache are editable at `/srv/challenge/gogs`, and
restart recompiles offline before replacing the live binary. Source/dependency
closure beyond the exact immutable upstream commit remains deferred by the
migration contract.
