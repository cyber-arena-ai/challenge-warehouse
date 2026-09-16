# pyLoad Download Manager

This package runs pyLoad from the accepted upstream commit
`e8e315e2e5148b49ab9de768e4642aba522a34ea`. It exposes the native web,
authenticated JSON API, and Click'N'Load companion-client surfaces on port
`8000`, with persistent application data and a complete editable source tree at
`/srv/challenge/pyload`.

The challenge publishes one rotating `host.command.execute` operation. The
functional checker uses two fresh equal-role ordinary pyLoad accounts to exercise status,
authorization denial, and a legitimate encrypted-package submission. Restarting
the service stops the current unprivileged pyLoad process before validating and
starting the edited source.

Build and validate through the orchestrator's canonical challenge checks using
the `pyload-download-manager` service name.
