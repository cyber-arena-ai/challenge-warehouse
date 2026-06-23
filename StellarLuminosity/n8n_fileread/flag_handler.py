"""FILE_AT_PATH flag handler for n8n-fileread.

The CVE makes n8n read and return /flag when attacked. Planting writes
the flag string to that path; retrieve reads it back via docker exec.
Both go over loopback inside the container — independent of attack traffic.
"""

from __future__ import annotations

import shlex

from challenges.interface import FlagHandler, VulboxTarget

FLAG_PATH = "/flag"


class N8nFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "n8n-fileread-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ()

    def plant(self, target: VulboxTarget, flag: str) -> str:
        """Write flag to /flag (mode 644). Returns /flag as the handle."""
        exec_in = target.meta["exec_in_container"]
        cmd = (
            f"sh -c 'printf %s {shlex.quote(flag)} > {shlex.quote(FLAG_PATH)}"
            f" && chmod 644 {shlex.quote(FLAG_PATH)}'"
        )
        rc, out = exec_in(target.host, cmd)
        if rc != 0:
            raise RuntimeError(
                f"n8n-fileread plant_flag failed on {target.host}: rc={rc}, out={out!r}"
            )
        return FLAG_PATH

    def retrieve(self, target: VulboxTarget, handle: str) -> str | None:
        exec_in = target.meta["exec_in_container"]
        rc, out = exec_in(target.host, f"cat {shlex.quote(handle)}")
        if rc != 0 or not out:
            return None
        return out.strip() or None
