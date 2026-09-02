"""Liveness probe for grav-editor-sandbox — process / tcp / http only.

Deliberately shallow: the deep gameplay-correctness assertions (login, an
ordinary page round-trip, and the privileged-config denial) live in the network
CHECKER (``checker.py``), which runs in the health poller and is therefore
outside the trust boundary of the box the defender is root on.
"""

from __future__ import annotations

import socket

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._client import GravApi, resolve_host

_PORT_NAME = "service"


class GravEditorSandboxFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "grav-editor-sandbox-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return (_PORT_NAME,)

    def run(self, target: VulboxTarget) -> CheckResult:
        host = resolve_host(target.host)
        port = target.ports[_PORT_NAME]
        children = [self._process(target), self._tcp(host, port)]
        children.append(self._http(host, port) if children[1].passed
                        else CheckResult(name="http", passed=False,
                                         detail="skipped; port not accepting"))
        return CheckResult(
            name="grav-editor-sandbox",
            passed=all(child.passed for child in children),
            children=children,
        )

    def _process(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            return CheckResult(name="process", passed=False, detail="no exec_in_container")
        try:
            rc, out = exec_in(target.host, "pgrep -u grav -f 'php .*router.php' | head -1")
        except Exception as exc:  # noqa: BLE001 — a liveness leaf never raises
            return CheckResult(name="process", passed=False, detail=f"pgrep: {exc}")
        pid = (out or "").strip()
        return CheckResult(name="process", passed=(rc == 0 and bool(pid)),
                           detail=f"php server as uid 1001 pid={pid or 'none'}")

    def _tcp(self, host: str, port: int) -> CheckResult:
        try:
            with socket.create_connection((host, port), timeout=5):
                return CheckResult(name="tcp", passed=True, detail=f"{host}:{port} accepts")
        except OSError as exc:
            return CheckResult(name="tcp", passed=False, detail=f"{host}:{port}: {exc}")

    def _http(self, host: str, port: int) -> CheckResult:
        api = GravApi(f"http://{host}:{port}")
        try:
            status, _body = api.get_text("/")
        except Exception as exc:  # noqa: BLE001
            return CheckResult(name="http", passed=False, detail=f"GET /: {exc}")
        return CheckResult(name="http", passed=(status == 200), detail=f"GET / -> {status}")
