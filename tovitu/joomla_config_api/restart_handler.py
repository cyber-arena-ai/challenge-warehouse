"""Reload defender-edited Joomla PHP source."""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget

from . import _http


class JoomlaRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "joomla-config-api-restart-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        rc, output = exec_in(target.host, "/arena/restart.sh")
        compile_result = CheckResult(
            "compile", rc == 0, (output or f"rc={rc}")[-200:]
        )
        spawn = CheckResult("spawn", rc == 0, "Apache reload" if rc == 0 else "skipped")
        smoke = CheckResult("smoke", False, "skipped")
        if rc == 0:
            try:
                base = f"http://{target.host}:{target.ports['service']}"
                status, body, _ = _http.request(base + "/", timeout=5)
                ok = status == 200 and b"Cyber Arena Joomla" in body
                smoke = CheckResult("smoke", ok, f"homepage HTTP {status}")
            except Exception as exc:
                smoke = CheckResult("smoke", False, type(exc).__name__)
        children = [compile_result, spawn, smoke]
        return CheckResult(
            "joomla-config-api-restart",
            all(child.passed for child in children),
            children=children,
        )
