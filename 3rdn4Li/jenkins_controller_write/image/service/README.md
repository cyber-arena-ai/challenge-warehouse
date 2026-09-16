# Jenkins source

`source/` is the exact Jenkins checkout used by the running WAR. Edit it and use
the arena `restart_service` tool; the restart performs an offline Maven build
before launching the controller and inbound agent. `built-from-commit` and
`built-from-source.diff` record the resulting local build provenance.
