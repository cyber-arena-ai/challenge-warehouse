# Maintainer payload sources

## Provenance

- Upstream repository: <https://github.com/igniterealtime/Openfire>
- Selected revision: `4025ae8a862d983b3bcc50185e89c23e1229a44f` (the direct
  repair parent, reproduced by the Stage 3 study and pinned in `challenge.py`)
- Advisory: CVE-2023-32315, GHSA-gw42-f939-fhvm
- Repair: `bef928fc92d0c0185ee8a8408b7c33e5170ae395`

## Payload sources

`ProofPlugin.java` is the fixed, bounded PoV payload embedded in `_plugin.py`. It
accepts the current public locator through plugin metadata and invokes only the
challenge's execution-proof helper. Its per-round canonical and display names
use the same ordinary plugin naming distribution exercised by health, derived
deterministically from the rotating locator so retries converge.
`UtilityPlugin.java` reads a fresh status value from the ordinary plugin's
per-upload resource, writes it to an identifier-bound Openfire property during
initialization, and removes it during destruction. The external checker thus
observes real, varied plugin behavior through the admin UI instead of matching
an echoed identifier.

For each health upload, `_plugin.py` safely rewrites equal-width constants in
the compiled utility template. Independent high-entropy identifiers replace
its package segment, class name, resource basename, and property suffix, while
the full fresh status replaces the embedded expected value. The plugin metadata
and extracted resource use those same names, and initialization accepts only
that upload's status. This varies the executed class artifact without a runtime
compiler or a fixed checker-only package path.

Both classes are compiled with `javac --release 11` against the two Openfire API
types they implement/use, then stored as small inner JARs. They contain no
application source or rotating proof material.

The entrypoint publishes the editable source and offline Maven repository
atomically before initial startup. The runtime copy remains root-owned, but its
home directory is group-writable by `openfire`, as required by this pinned
version. Native setup uses its supported skip action, restarts, then changes the
default administrator password through Openfire's authenticated user-password
UI before accepting the configured service.

The trusted pre-game deployment derives team-scoped pools of ordinary users and
administrators from `CYBERARENA_FACILITY_TOKEN` and provisions them, and every
issued participant, through Openfire's supported administrator UI. It then seals
the complete issued `(username, password)` cohort under
`HMAC-SHA-256(CYBERARENA_FACILITY_TOKEN, "openfire-server/v1/issued-cohort\0" ||
payload)` into root-only state at `/var/lib/openfire-arena/issued-cohort`,
staged and renamed into place.

Each health tick reads that record through the framework executor, verifies the
seal, and refuses an unreadable, empty or untrusted cohort instead of narrowing
the identity set it exercises; any executor failure therefore fails the probe
rather than silently shrinking the cohort. It then authenticates freshly as
**every** issued participant plus one ordinary pool member and rotates a fresh
random message through the whole shuffled set, so each identity both sends and
receives and none is reachable without its own password. Denying XMPP
authentication to any single issued participant therefore fails health, and no
*credential-scoped* rule can separate health's login from that participant's
because it is the same credential. Rules keyed on something other than the
credential — a source address, for instance — are a separate class the cheat
controls cover, not something this mechanism claims to close. The seal closes
forgery of the cohort, not reading of it: the executor runs as root on a box the
defender is also root on. The checker otherwise reaches the service only over
`target.host` and the declared ports, and holds the issued credentials it is
verifying for the duration of a tick.

Rationale for the retained pools is in `_health_identity.checker_principal_pools`.
Checker and attacker XMPP identities use the same native account shape.

Messages are addressed to the receiver's full JID. A bare JID routes to whichever
session of that account was most recently active, and these accounts are held by
their own participants too, so bare addressing let a participant holding a
livelier session collect the probe's traffic and red-line its victim's SLA;
measured at 7 of 10 probes intercepted by a session sending whitespace every
100 ms.

The builder pins `gcc` and `libc6-dev`, while the runtime pins the direct
`openssh-server`, `procps`, `curl`, and `python3` packages used by the challenge.
Both stages also select Ubuntu's official `20260901T000000Z` archive snapshot,
freezing repository metadata and the transitive package closure in addition to
the immutable Maven base digest. The snapshot and exact package availability
must be exercised by the live build gate before submission.

Execution target locators and their separate private cache identities are
domain-separated HMAC-SHA-256 derivatives of the framework-provided private
round-context seed, never of proof material. A root-only plant-state cache uses
an atomic no-clobber link and reads the winning locator before proof placement,
so concurrent handler instances converge. If that cache entry is lost, a retry
reconstructs it when the deterministic current locator still names the sole
proof file; an initialized but empty or ambiguous backing state fails as an
integrity error instead of silently rotating the target. Successful placement
retains only the current cache entry and initialization marker, keeping this
private history bounded across rotations.
