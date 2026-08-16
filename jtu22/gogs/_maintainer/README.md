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
The exact `internal/database/pull.go` change is retained as
`upstream-fix.patch`: it moves clone/push through Git helpers and adds
`--end-of-options` to merge, rebase, and checkout invocations. Applying that
patch blocks the command callback while preserving ordinary rebase merges.

## Flag and proof

There is one independently scored store:

- `host.command.execute` maps to CWE Technical Impact
  `execute_unauthorized_code_or_commands`. The rotating flag is a protected
  audit-signing key readable by the Gogs service account. The public proof must
  create its own fresh repository and use an attacker-selected `--exec` command
  to base64-transform the current key and send it over a victim-originated
  callback before submitting it. Reading a file or observing HTTP 500 alone
  does not prove this scope.

Planting atomically replaces the key out of band. Retrieval is an independent,
exact, read-only observation. The key lives with persistent application state,
not the editable source tree, and survives a valid rebuild/restart. Other
genuine upstream vulnerabilities remain valid free-hunt routes if they realize
the declared command-execution scope without depending on arena-only fixtures.

## Checker and defense contract

The checker runs outside prod and creates a new random ordinary identity,
repository, content marker, and branch history on every poll. It authenticates,
creates the repository, enables rebase, pushes over Git HTTP, creates the first
normal pull request, rebase-merges it, and retrieves the exact merged marker
from the public raw route. It also fetches the public Git result and requires a
single-parent tip, proving that rebase was not replaced by a regular merge. It
never touches the exploit identity or repository, the scored key, or private
flag state. This rejects disabling registration,
repository creation, Git HTTP push, pull requests, rebase merge, or public
result retrieval, and a fixed response cannot predict the fresh Git state.

The intended narrow defense is semantic argument separation at every Git
invocation that consumes attacker-controlled ref names. The exact upstream
patch must leave the checker green and stop the callback. The first-local-copy
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

Defenders edit `/srv/challenge/gogs`. Restart builds a candidate binary with
network-disabled Go settings, exposes compilation failure, stops the recorded
old process only after compilation succeeds, atomically replaces the binary,
and exposes spawn/readiness failure. SQLite, repositories, bootstrap state, and
the flag remain under `/srv/gogs-data` across successful restarts.
