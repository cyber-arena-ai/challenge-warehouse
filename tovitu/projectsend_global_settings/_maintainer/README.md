# ProjectSend global-settings maintainer notes

This package pins ProjectSend at repair parent
`675d6d3f2124a4a25ef907b44ceb240003315e46`. The demonstrated direct-child
repair is `193367d937b1a59ed5b68dd4e60bd53317473744`.
The bundled vulnerable source archive has SHA-256
`c171f013a9ac84178d3bae23e324d3a0bae13084020411ef0618e01964bebdcd`.

The scored boundary is one `WRITE` store named `global_setting`, scoped as
`app.privileged.control`. Each attacker receives a distinct normal Client account;
the protected action is modification of the administrator-only global site title.
The known anonymous settings request demonstrates the reachable floor. An attempted
PHP upload was saved but denied by the upstream Apache policy, so this package does
not declare command execution.

The flag handler keeps its rotating integrity token in a root-only anchor. Claims
are adjudicated by scanning MariaDB's row-based transaction log for the
attempt-specific mark written to ProjectSend's protected options table. This gives
the trusted host snapshot a defender-independent record of an actual committed
application write without executing a reader in defender-controlled production;
all requests and mutations still go through ProjectSend's normal HTTP and database
paths.

Trusted principal setup uses ProjectSend's normal administrator forms to provision
target-specific checker accounts derived from facility state. The network-only
semantic checker uses those accounts to verify an authorized administrator title
change and restore, then checks Client authentication plus randomized upload,
listing, and public retrieval. Source replacement preserves MariaDB state, Client
principals, and uploaded files.

Run the focused tests from the orchestrator checkout with this warehouse selected,
then run the canonical static, build, and game gates. Admission controls must also
show that removing the settings workflow and returning canned responses fail the
semantic checker, while the exact upstream repair preserves normal behavior and
blocks the certified proof.
