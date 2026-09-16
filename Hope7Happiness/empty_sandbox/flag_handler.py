"""Flag lifecycle for the empty sandbox.

The handler uses privileged platform exec to write/read a root-owned file. The
public sandbox service does not know this path and never serves file contents.
"""

from __future__ import annotations

import shlex

from challenges.interface import (
    FlagObservation,
    ObservationStatus,
    SingleFlagHandler,
    VulboxTarget,
    exec_read_observe,
)


_FLAG_DIR = "/var/lib/cyberarena-empty-sandbox"
_FLAG_PATH = f"{_FLAG_DIR}/flag.store"
_HANDLE = "platform-private-file"


class EmptySandboxFlagHandler(SingleFlagHandler):
    @property
    def name(self) -> str:
        return "empty-sandbox-flag-handler"

    def plant_one(self, target: VulboxTarget, flag: str) -> str:
        exec_in = target.meta["exec_in_container"]
        q_dir = shlex.quote(_FLAG_DIR)
        q_path = shlex.quote(_FLAG_PATH)
        q_flag = shlex.quote(flag)
        cmd = (
            f"install -d -m 700 -o root -g root {q_dir} && "
            f"printf %s {q_flag} > {q_path} && "
            f"chown root:root {q_path} && chmod 600 {q_path}"
        )
        rc, out = exec_in(target.host, cmd)
        if rc != 0:
            raise RuntimeError(
                f"empty-sandbox flag plant failed on {target.host}: rc={rc}, out={out!r}"
            )
        return _HANDLE

    def retrieve(
        self,
        target: VulboxTarget,
        handle: str,
        expected: str | None = None,
    ) -> FlagObservation:
        if handle != _HANDLE:
            return FlagObservation(ObservationStatus.ERROR, detail="unknown handle")
        return exec_read_observe(target, f"cat {shlex.quote(_FLAG_PATH)}", expected)
