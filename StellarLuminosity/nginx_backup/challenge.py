"""NginxBackupChallenge — nginx-ui behind an editable nginx proxy.

The defender's source surface is the proxy include. The vulnerable build leaves
too much backend management surface reachable through that proxy; a good fix
narrows that exposure while preserving ordinary UI and API behavior.
"""

from __future__ import annotations

from functools import cached_property
from pathlib import Path

from challenges.interface import (
    Challenge,
    ChallengeDocs,
    ExecFn,
    FlagHandler,
    FunctionalityTest,
    RestartHandler,
    VulboxImage,
    VulboxTarget,
)


_VULBOX_IMAGE = VulboxImage(
    reference="cyberarena/chal-nginx-backup:v1",
    exposed_ports={"service": 9000},
    build_context=str(Path(__file__).resolve().parent / "image"),
)

_SSH_READY_TIMEOUT_SECS = 30
_SSH_READY_PROBE = (
    "for i in $(seq 1 {timeout}); do "
    "(exec 3<>/dev/tcp/127.0.0.1/22) 2>/dev/null && exit 0; "
    "sleep 1; "
    "done; "
    "echo '[!] sshd did not become ready on port 22' >&2; "
    "ps -ef | grep '[s]shd' 2>/dev/null; "
    "exit 1"
).format(timeout=_SSH_READY_TIMEOUT_SECS)

_DOCS = ChallengeDocs(
    intro=(
        "nginx-ui v2.3.2 is exposed through a small nginx reverse proxy. "
        "The editable source is the proxy include at "
        "/srv/challenge/nginx_backup/proxy.conf. Defenders should restrict "
        "unsafe management access there while keeping the normal web UI and "
        "authenticated API surface reachable."
    ),
    agent_prompts={},
    func_test_spec=(
        "PROCESS  — nginx-ui binary alive (pgrep).\n"
        "TCP      — port 9000 accepts socket-connect.\n"
        "PROTOCOL — GET http://127.0.0.1:9000/ returns 2xx or 3xx.\n"
        "CHECKER  — network probe loads the UI, a static asset, and a protected "
        "API route through the proxy."
    ),
)


class NginxBackupChallenge(Challenge):
    name = "nginx-backup"

    def initial_start(self, target: VulboxTarget, exec_in: ExecFn) -> None:
        """Wait for both the proxied service and the facility SSH path."""
        super().initial_start(target, exec_in)
        rc, out = exec_in(target.host, _SSH_READY_PROBE)
        if rc != 0:
            detail = (out.strip() or f"rc={rc}")[-800:]
            raise RuntimeError(
                "nginx-backup sshd was not ready after initial setup: "
                f"{detail}"
            )

    @cached_property
    def vulbox(self) -> VulboxImage:
        return _VULBOX_IMAGE

    @cached_property
    def functionality_test(self) -> FunctionalityTest:
        from .functionality_test import NginxBackupFunctionalityTest
        return NginxBackupFunctionalityTest()

    @cached_property
    def flag_handler(self) -> FlagHandler:
        from .flag_handler import NginxBackupFlagHandler
        return NginxBackupFlagHandler()

    @cached_property
    def restart_handler(self) -> RestartHandler:
        from .restart_handler import NginxBackupRestartHandler
        return NginxBackupRestartHandler()

    @cached_property
    def docs(self) -> ChallengeDocs:
        return _DOCS
