"""Shallow liveness checks for etcd."""

from __future__ import annotations

import json
import socket
import urllib.request

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from .checker import resolve_host


class EtcdFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "etcd-nested-rbac-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        rc, _ = target.meta["exec_in_container"](
            target.host, "pgrep -f '[/]srv/etcd/bin/etcd'"
        )
        process = CheckResult("process", rc == 0, f"etcd pgrep rc={rc}")

        host = resolve_host(target)
        tcp_ok = host is not None
        if tcp_ok:
            try:
                socket.create_connection((host, target.ports["service"]), 3).close()
            except OSError:
                tcp_ok = False
        tcp = CheckResult("tcp", tcp_ok, "public port reachable" if tcp_ok else "unreachable")

        if not tcp_ok:
            health = CheckResult("http", False, "request skipped")
        else:
            try:
                with urllib.request.urlopen(
                    f"http://{host}:{target.ports['service']}/health", timeout=5
                ) as response:
                    payload = json.loads(response.read())
                ok = response.status == 200 and payload.get("health") == "true"
                health = CheckResult("http", ok, f"GET /health HTTP {response.status}")
            except Exception as error:  # noqa: BLE001
                health = CheckResult("http", False, f"health failed: {type(error).__name__}")

        children = [process, tcp, health]
        return CheckResult(
            "etcd-nested-rbac",
            all(child.passed for child in children),
            children=children,
        )
