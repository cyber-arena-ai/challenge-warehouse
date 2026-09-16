"""Shallow NATS process and public MQTT liveness."""

from __future__ import annotations

import socket

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

class NatsFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "nats-mqtt-acl-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        children = [
            self._process(target),
            self._tcp(target.host, target.ports["service"]),
            self._internal_core(target),
        ]
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
    def _internal_core(target: VulboxTarget) -> CheckResult:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            return CheckResult("core_loopback", False, "no exec bridge")
        rc, output = exec_in(
            target.host,
            "exec 3<>/dev/tcp/127.0.0.1/4222 && "
            "IFS= read -r -t 3 line <&3 && case \"$line\" in INFO*) exit 0;; esac; exit 1",
        )
        return CheckResult(
            "core_loopback", rc == 0, (output or "loopback INFO checked")[-180:]
        )
