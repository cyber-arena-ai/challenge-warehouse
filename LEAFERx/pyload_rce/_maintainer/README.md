# Maintainer notes

## Source and semantic baseline

- Upstream repository: <https://github.com/pyload/pyload>.
- Accepted Stage 3 primary: pyLoad commit
  `e8e315e2e5148b49ab9de768e4642aba522a34ea`
  (<https://github.com/pyload/pyload/commit/e8e315e2e5148b49ab9de768e4642aba522a34ea>).
- Advisory: CVE-2024-39205, GitHub advisory GHSA-r9pp-r4xf-597r, "pyload-ng
  vulnerable to RCE with js2py sandbox escape"
  (<https://github.com/pyload/pyload/security/advisories/GHSA-r9pp-r4xf-597r>,
  <https://nvd.nist.gov/vuln/detail/CVE-2024-39205>). It rests on the js2py
  sandbox escape CVE-2024-28397, which the repair below names in its own
  comment.
- Accepted upstream repair: `849291e64936e411b2ec40616109e16cf9ebfbc2`
  (<https://github.com/pyload/pyload/commit/849291e64936e411b2ec40616109e16cf9ebfbc2>),
  the published fix for GHSA-r9pp-r4xf-597r. It adds a `monkey_patch()` making
  js2py's `Object.getOwnPropertyNames` return a plain list, beside the
  `disable_pyimport()` the pinned source already calls. It does not restrict
  ES5 syntax, so it leaves the health key programs below untouched.
- The packaged primary archive SHA-256 is
  `c54ad6027df8e78f80c50c056d65d35b5a9e9a093cb8f0ca05a675918b5304a8`.
- The base image is pinned by digest and the OS packages by the Debian snapshot
  the base image records. Exact apt version pins were tried first and rejected:
  deb.debian.org serves only current versions, so a pin stops resolving at the
  next point release and the image becomes unbuildable, while every transitive
  package still floats. The snapshot fixes the whole OS set and does not expire.
  It does make the build depend on snapshot.debian.org; that service throttling
  fails the build loudly rather than changing what gets installed.
- Python packages are version-pinned by `image/requirements.lock`, which the
  build diffs against the installed set so a stale lock fails. Versions only —
  there are no artifact hashes.

## Objective and lifecycle

The package has one `EXECUTE` store named `command`. Its public target and
private generation context are independently HMAC-derived from the validated
framework `round_context_seed`. The flag service stages and verifies the new
root-owned proof before durable promotion, retains the previously published
generation through the return boundary, and retires it on a later distinct
invocation. The setuid proof helper accepts only the pyLoad service UID and an
exact current locator.

## Runtime and health

The image starts pyLoad as UID 1000 and keeps application state under
`/srv/pyload`. The baked bootstrap administrator password is rotated into
root-private state during initial start. Each deep health run first submits two
ordinary randomized Click'N'Load packages through the public service, one under
each Host value the upstream `local_check` accepts (`127.0.0.1:9666` and
`[::1]:9666` — it compares `HTTP_HOST` for exact equality, and its REMOTE_ADDR
branch is unreachable for any off-box client), so a defense that serves only one
of the two fails health rather than only the equivalent participant request. All
package, URL, key-program, and account inputs are held only by the external
checker.
It then uses pyLoad's public administrative RPC to create two fresh equal-role
native accounts (role 1, permissions 20), checks symmetric status, list access,
and settings denial, and requires both users' native package data to contain the
fresh decrypted URL. The in-container helper releases only the pre-existing
administrator credential; it receives and journals no checker fixture.

The two key programs cover one comment-free ES5 program and one guaranteed to
contain a block comment; their assignment to the two Host forms is randomized.
The required block comment occupies a randomly selected safe internal token
boundary, while other internal block comments, outer line or block comments,
and whitespace remain independently varied. A defender can still mirror the
generator, since the checker source is public; what this removes is a defense
that recognizes one fixed spelling or outer envelope, or rejects the ordinary
block-comment class the pinned engine accepts. Internal gaps exclude line
terminators because a newline between `return` and its operand ends the
statement and js2py then yields `undefined` with no error at all.

Account credentials and package names are drawn from broad native-safe input
classes, rather than a small checker-only word list or recognizable prefix.
Account generation retries before mutation when a generated name is already
present. Cleanup binds the fresh decrypted URL and exact native package ID, and
binds each account to its observed native user ID, before removing checker-owned
state. Pending ownership stays in the external checker before each mutation,
and cleanup rechecks every owned resource independently, so ambiguous responses
and partial account setup are reconciled without a defender-side fixture journal.

The defender edits `/srv/challenge/pyload` and uses the normal restart action.
The restart gate retires the running backend before compiling and importing the
edited source, and repeats teardown after validation and failed startup, so no
prior or partial generation remains serving on a rejected edit. Teardown decides
on the service account and the port rather than on any identifier that account
can forge, and a teardown it cannot confirm is reported as such.

The private verifier must work through the public ingress even though production
containers have no route back to opponent agents. After invoking the proof
helper, its victim-context command creates one fresh ordinary pyLoad user whose
native profile carries the returned value; the verifier authenticates with that
fresh credential and reads the profile through the public JSON API. This is an
attacker-side post-execution result path, not challenge-local networking or a
facility shortcut. Fresh credentials prevent a stale vulnerable-run result from
passing the exact-repair control.
