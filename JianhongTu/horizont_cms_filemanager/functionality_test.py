"""Cheap liveness checks for the HorizontCMS process and HTTP endpoint."""

from __future__ import annotations

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget


class HorizontCmsFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "horizont-cms-filemanager-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        port = target.ports["service"]

        process_rc, _ = exec_in(
            target.host,
            "test -s /run/horizont.pid && kill -0 $(cat /run/horizont.pid)",
        )
        process = CheckResult(
            name="process", passed=process_rc == 0, detail=f"php pid rc={process_rc}"
        )

        tcp_rc, _ = exec_in(
            target.host,
            f"bash -c 'exec 3<>/dev/tcp/127.0.0.1/{port}; exec 3>&-'",
        )
        tcp = CheckResult(name="tcp", passed=tcp_rc == 0, detail=f"connect rc={tcp_rc}")

        protocol_cmd = (
            "php -r '$b=@file_get_contents(\"http://127.0.0.1:"
            f"{port}/admin/login\"); exit($b!==false && strpos($b,\"csrf-token\")!==false ? 0 : 1);'"
        )
        protocol_rc, _ = exec_in(target.host, protocol_cmd)
        protocol = CheckResult(
            name="protocol",
            passed=protocol_rc == 0,
            detail=f"login page rc={protocol_rc}",
        )
        children = [process, tcp, protocol]
        return CheckResult(
            name="horizont-cms-filemanager",
            passed=all(child.passed for child in children),
            children=children,
        )
