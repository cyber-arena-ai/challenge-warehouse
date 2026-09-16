"""Shallow process and public-health checks for etcd."""

from __future__ import annotations

import json
import socket
import urllib.request

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._client import target_base


class EtcdFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "etcd-configuration-store-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta.get("exec_in_container")
        rc = 1
        if exec_in is not None:
            rc, _ = exec_in(target.host, "pgrep -f '[/]srv/etcd/bin/etcd'")
        process = CheckResult("process", rc == 0, f"etcd pgrep rc={rc}")

        try:
            socket.create_connection(
                (target.host, target.ports["service"]), timeout=3
            ).close()
            tcp = CheckResult("tcp", True, "public port reachable")
        except OSError:
            tcp = CheckResult("tcp", False, "public port unreachable")

        try:
            with urllib.request.urlopen(target_base(target) + "/health", timeout=5) as response:
                payload = json.loads(response.read())
            ok = response.status == 200 and payload.get("health") == "true"
            health = CheckResult("http", ok, f"GET /health HTTP {response.status}")
        except Exception as error:  # noqa: BLE001 — liveness failures are data
            health = CheckResult(
                "http", False, f"health failed: {type(error).__name__}"
            )

        children = [process, tcp, health]
        return CheckResult(
            "etcd-configuration-store",
            all(child.passed for child in children),
            children=children,
        )
