"""Shallow liveness probe for the authenticated Gradio service."""

from __future__ import annotations

import socket
import urllib.error
import urllib.request

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget


class GradioFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "gradio-component-workspace-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("web",)

    def run(self, target: VulboxTarget) -> CheckResult:
        children = [self._process(target), self._tcp(target), self._http(target)]
        return CheckResult(
            "gradio-component-workspace",
            all(child.passed for child in children),
            children=children,
        )

    @staticmethod
    def _process(target: VulboxTarget) -> CheckResult:
        exec_in = target.meta.get("exec_in_container")
        if not callable(exec_in):
            return CheckResult("process", False, "no exec bridge")
        rc, output = exec_in(
            target.host,
            "found=0; for pid in $(pgrep -f '[s]rv/challenge/app.py'); do "
            "uid=$(awk '/^Uid:/{print $2}' /proc/$pid/status 2>/dev/null || true); "
            "if [ \"$uid\" = 10001 ]; then found=1; "
            "tr '\\0' ' ' </proc/$pid/cmdline | "
            "grep -Eq 'FLAG\\{|password|report-' && exit 1; fi; done; "
            "[ \"$found\" = 1 ] && printf 10001",
        )
        uid = (output or "").strip().splitlines()[:1]
        passed = rc == 0 and uid == ["10001"]
        return CheckResult("process", passed, f"runtime uid={uid[0] if uid else 'unknown'}")

    @staticmethod
    def _tcp(target: VulboxTarget) -> CheckResult:
        try:
            socket.create_connection((target.host, target.ports["web"]), timeout=4).close()
            return CheckResult("tcp", True, "public port reachable")
        except OSError as error:
            return CheckResult("tcp", False, type(error).__name__)

    @staticmethod
    def _http(target: VulboxTarget) -> CheckResult:
        url = f"http://{target.host}:{target.ports['web']}/"
        try:
            with urllib.request.urlopen(url, timeout=8) as response:
                body = response.read(8192).lower()
            passed = response.status == 200 and b"gradio" in body
            return CheckResult("http", passed, f"public root HTTP {response.status}")
        except (OSError, urllib.error.URLError) as error:
            return CheckResult("http", False, type(error).__name__)
