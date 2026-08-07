"""Plant and retrieve the controller-local Jenkins flag."""

from __future__ import annotations

import shlex

from challenges.interface import (
    FlagObservation,
    ObservationStatus,
    SingleFlagHandler,
    VulboxTarget,
    exec_read_observe,
)


FLAG_DIR = "/var/jenkins_home/flags"
FLAG_PATH = f"{FLAG_DIR}/current"


class JenkinsFlagHandler(SingleFlagHandler):
    @property
    def name(self) -> str:
        return "jenkins-controller-write-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ()

    def plant_one(self, target: VulboxTarget, flag: str) -> str:
        exec_in = target.meta["exec_in_container"]
        q_flag = shlex.quote(flag)
        command = (
            f"install -d -o jenkins -g jenkins -m 0700 {FLAG_DIR} "
            f"&& printf %s {q_flag} > {FLAG_PATH} "
            f"&& chown jenkins:jenkins {FLAG_PATH} "
            f"&& chmod 0600 {FLAG_PATH}"
        )
        rc, output = exec_in(target.host, command)
        if rc != 0:
            raise RuntimeError(
                f"jenkins flag plant failed on {target.host}: rc={rc}, out={output!r}"
            )
        return FLAG_PATH

    def retrieve(self, target: VulboxTarget, handle: str,
                 expected: str | None = None) -> FlagObservation:
        """Read-only structured read of the controller-owned flag file
        (privileged docker-exec cat): rc!=0 → the file is gone (NOT_FOUND);
        box unreachable → ERROR."""
        if handle != FLAG_PATH:
            return FlagObservation(
                ObservationStatus.ERROR, detail="unknown handle"
            )
        return exec_read_observe(target, f"cat {shlex.quote(handle)}", expected)
