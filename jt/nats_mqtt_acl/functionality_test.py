"""Shallow NATS process, TCP, and protocol liveness."""

from __future__ import annotations

import socket

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._mqtt import resolve_host


class NatsFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "nats-mqtt-acl-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service", "nats")

    def run(self, target: VulboxTarget) -> CheckResult:
        host = resolve_host(target.host)
        children = [self._process(target), self._tcp(host, target.ports["service"]),
                    self._info(host, target.ports["nats"])]
        return CheckResult("nats-mqtt-acl", all(c.passed for c in children),
                           children=children)

    @staticmethod
    def _process(target: VulboxTarget) -> CheckResult:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            return CheckResult("process", False, "no exec bridge")
        rc, out = exec_in(
            target.host,
            "pid=$(cat /run/nats-server.pid 2>/dev/null) && "
            "test -n \"$pid\" && awk '/^Uid:/{print $2}' /proc/$pid/status",
        )
        uid = (out or "").strip()
        return CheckResult("process", rc == 0 and uid == "1000",
                           f"service uid={uid or 'none'}")

    @staticmethod
    def _tcp(host: str, port: int) -> CheckResult:
        try:
            with socket.create_connection((host, port), timeout=5):
                return CheckResult("mqtt_tcp", True, f"{host}:{port} accepts")
        except OSError as error:
            return CheckResult("mqtt_tcp", False, str(error))

    @staticmethod
    def _info(host: str, port: int) -> CheckResult:
        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                raw = sock.recv(4096)
            text = raw.decode(errors="replace")
            ok = text.startswith("INFO ") and '"version":"2.12.5"' in text
            return CheckResult("nats_info", ok, text[:180])
        except OSError as error:
            return CheckResult("nats_info", False, str(error))
