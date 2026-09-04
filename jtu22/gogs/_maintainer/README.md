# Gogs challenge

## Provenance and scenario

This package builds [Gogs](https://github.com/gogs/gogs) at immutable commit
`e3bb4165dceb96b66053a067f9f3584302413a0e`. The retained discovery snapshot
records an MIT-licensed self-hosted Git service with 47,692 GitHub stars.

The studied issue is CVE-2026-52806. An ordinary, non-site-admin repository
owner can push an option-like base ref, create the first pull request in a fresh
repository, and select rebase merge. `PullRequest.Merge` passes the attacker-
controlled base branch to `git rebase` before an end-of-options marker, so Git
interprets it as `--exec` and runs an attacker-selected command as the Gogs
service process. A later checkout can make the merge request return HTTP 500;
that status is not evidence of command execution.

Upstream repaired the path in
[`a9dbafbfd8e1020bacc626420238c01d75d03364`](https://github.com/gogs/gogs/commit/a9dbafbfd8e1020bacc626420238c01d75d03364).
The security-relevant `internal/database/pull.go` change is rebased onto the
locked source and retained as `upstream-fix.patch`: it moves clone/push through
Git helpers and adds
`--end-of-options` to merge, rebase, and checkout invocations. Applying that
patch blocks the in-band execution proof while preserving ordinary rebase merges.

## Flag and proof

There is one independently scored store:

- `host.command.execute` maps to CWE Technical Impact
  `execute_unauthorized_code_or_commands`. A rotating operation id and flag are
  stored in a root-only objective record. The setuid `/o` helper returns the
  current flag only to the real Gogs service UID and only for that operation id.
  The public proof must
  create fresh repositories and test both attacker-selected `--exec` and `-x`
  commands to invoke the helper, base64-transform its output, amend the rebased commit, and push it to
  a fresh proof branch through the victim's local repository. The attacker then
  retrieves that nonce-bound proof through the public raw route before
  submitting it. Observing HTTP 500 alone does not prove this scope.

Planting atomically replaces the root-only record out of band. Retrieval invokes
the same helper as the service UID and is an independent, exact, read-only
observation. The record lives outside the editable source tree and survives a
valid rebuild/restart. Other
genuine upstream vulnerabilities remain valid free-hunt routes if they realize
the declared command-execution scope without depending on arena-only fixtures.

## Checker and defense contract

The checker runs outside prod and creates ordinary identities, passwords,
repositories, branch names, and content markers from the same random generators
used by the exploit. It authenticates, creates the repository, enables rebase,
pushes a divergent history over Git HTTP, creates the first normal pull
request, and rebase-merges it. The final public branch must contain independent
fresh canaries from both the base and feature sides, and its tip must have one
parent whose ID is the exact pre-merge base tip. This rejects a regular merge as
well as a fake linear replacement that discards or rewrites the base history.
It never touches the scored key or
private flag state. Disabling registration, repository creation, Git HTTP
push, pull requests, rebase merge, or public result retrieval makes it fail,
and a fixed response cannot predict the fresh Git state.

The intended narrow defense is semantic argument separation at every Git
invocation that consumes attacker-controlled ref names. The exact upstream
patch must leave the checker green and stop the in-band proof. The first-local-copy
condition is intentional: exploit trials use a genuinely fresh repository and
the checker uses a separate repository, so health traffic cannot consume the
trigger.

## Build and restart

The source commit, Alpine, Node, and Go base images are immutable digest pins.
The behavior-relevant Git version and direct Alpine packages are exact version
pins; the health-poller installs Git `1:2.47.3-0+deb13u1` for its public push
workflow. Frontend dependencies use the upstream pnpm lockfile and Go modules
use the upstream `go.sum`. The initial binary, module cache, build cache,
source, and toolchain are baked into the image. Runtime startup is offline.
On the first boot, Gogs listens only on the container loopback address while
entrypoint creates the bootstrap administrator. It then stops Gogs, switches
the listener to `0.0.0.0`, and starts the public service. Public registration
therefore cannot race to claim the first-user admin role.

Defenders edit `/srv/challenge/gogs`. Restart builds a candidate binary with
network-disabled Go settings, exposes compilation failure, stops the recorded
old process only after compilation succeeds, atomically replaces the binary,
and exposes spawn/readiness failure. SQLite, repositories, bootstrap state, and
the flag remain under `/srv/gogs-data` across successful restarts.

The supplied exploit also implements the solo-defense verifier result contract:
it emits final structured raw facts, treats a reachable hardened target as a
clean zero-exit result, reports unreachable/runtime errors with a nonzero exit,
and correlates submissions with the verification attempt header.
