"""Shallow process and public HTTP liveness checks."""

from __future__ import annotations

import socket
import urllib.error
import urllib.request

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget


class ChangedetectionIoFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "changedetection-io-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            process = CheckResult("process", False, "no exec bridge")
        else:
            rc, output = exec_in(
                target.host,
                "pid=$(cat /run/changedetection.pid 2>/dev/null) && "
                "test -n \"$pid\" && awk '/^Uid:/{print $2}' /proc/$pid/status",
            )
            uid = (output or "").strip()
            process = CheckResult("process", rc == 0 and uid == "1000", f"uid={uid or 'none'}")

        try:
            socket.create_connection((target.host, target.ports["service"]), 4).close()
            tcp = CheckResult("tcp", True, "public port accepts")
        except OSError as error:
            tcp = CheckResult("tcp", False, str(error))

        try:
            url = f"http://{target.host}:{target.ports['service']}/"
            with urllib.request.urlopen(url, timeout=8) as response:
                status = response.status
                body = response.read(512)
            http = CheckResult(
                "http",
                status == 200 and b"changedetection" in body.lower(),
                f"GET / HTTP {status}",
            )
        except (OSError, urllib.error.URLError) as error:
            http = CheckResult("http", False, type(error).__name__)
        children = [process, tcp, http]
        return CheckResult(
            "changedetection-io", all(child.passed for child in children), children=children
        )
