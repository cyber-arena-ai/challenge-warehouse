"""FILE_AT_PATH flag handler for craft-cms.

CVE-2025-32432 gives the attacker command execution as www-data, so the
flag is a plain file at /flag (mode 644 — www-data must be able to read
it for the stolen-flag path to work). Planting and retrieval both run
inside the container over docker exec, independent of attack traffic.
"""

from __future__ import annotations

import shlex

from challenges.interface import (
    FlagObservation,
    SingleFlagHandler,
    VulboxTarget,
    exec_read_observe,
)

FLAG_PATH = "/flag"


class CraftCmsFlagHandler(SingleFlagHandler):
    @property
    def name(self) -> str:
        return "craft-cms-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        # plant/retrieve go via docker exec; the HTTP port isn't this
        # handler's concern (attack agents land RCE and read /flag themselves).
        return ()

    def plant_one(self, target: VulboxTarget, flag: str) -> str:
        """Write flag to /flag (mode 644). Returns /flag as the handle."""
        exec_in = target.meta["exec_in_container"]
        cmd = (
            f"sh -c 'printf %s {shlex.quote(flag)} > {shlex.quote(FLAG_PATH)}"
            f" && chmod 644 {shlex.quote(FLAG_PATH)}'"
        )
        rc, out = exec_in(target.host, cmd)
        if rc != 0:
            raise RuntimeError(
                f"craft-cms plant_flag failed on {target.host}: rc={rc}, out={out!r}"
            )
        return FLAG_PATH

    def retrieve(self, target: VulboxTarget, handle: str,
                expected: str | None = None) -> FlagObservation:
        """Read-only structured read of the flag file (privileged docker-exec
        cat): rc!=0 → the file is gone (NOT_FOUND); box unreachable → ERROR."""
        return exec_read_observe(target, f"cat {shlex.quote(handle)}", expected)
