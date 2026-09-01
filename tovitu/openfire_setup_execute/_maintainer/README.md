# Maintainer payload sources

`ProofPlugin.java` is the fixed, bounded PoV payload embedded in `_plugin.py`. It
accepts the current public locator through plugin metadata and invokes only the
challenge's execution-proof helper. `HealthPlugin.java` is a no-op plugin used by
the external checker to exercise supported plugin installation and removal.

Both classes are compiled with `javac --release 11` against the two Openfire API
types they implement/use, then stored as small inner JARs. They contain no
application source or rotating proof material.

The entrypoint publishes the editable source and offline Maven repository
atomically before initial startup. The runtime copy remains root-owned, but its
home directory is group-writable by `openfire`, as required by this pinned
version. Native setup uses its supported skip action, restarts, then changes the
default administrator password through Openfire's authenticated user-password
UI before accepting the configured service.

The trusted functionality phase derives a team-scoped checker administrator
from `CYBERARENA_FACILITY_TOKEN` and provisions it through a private runtime
helper that uses Openfire's local administrator UI. `checker.py` derives the
same identity in the health facility and then uses only `target.host` and the
declared ports for randomized XMPP, user administration, and plugin lifecycle
checks; it has no container exec, Docker lookup, or production-secret path.
