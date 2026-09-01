"""Offline source rebuild and NATS service replacement."""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget


class NatsRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "nats-mqtt-acl-restart-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service", "nats")

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        rc, out = exec_in(target.host, "/arena/restart.sh")
        detail = ((out or "").strip() or f"rc={rc}")[-600:]
        return CheckResult("nats-mqtt-acl-restart", rc == 0, detail)
