"""Cheap liveness checks for MiniServ and the Webmin login surface."""

from __future__ import annotations

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget


class WebminFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "webmin-filemanager-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        port = target.ports["service"]

        process_rc, _ = exec_in(
            target.host,
            "test -s /var/webmin/miniserv.pid && kill -0 $(cat /var/webmin/miniserv.pid)",
        )
        process = CheckResult(
            name="process", passed=process_rc == 0, detail=f"miniserv pid rc={process_rc}"
        )

        tcp_rc, _ = exec_in(
            target.host,
            f"bash -c 'exec 3<>/dev/tcp/127.0.0.1/{port}; exec 3>&-'",
        )
        tcp = CheckResult(name="tcp", passed=tcp_rc == 0, detail=f"connect rc={tcp_rc}")

        protocol_cmd = (
            "perl -MIO::Socket::INET -e '$s=IO::Socket::INET->new("
            f"PeerAddr=>\"127.0.0.1\",PeerPort=>{port},Proto=>\"tcp\",Timeout=>5) "
            "or exit 1; print $s \"GET / HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n\"; "
            "local $/; $b=<$s>; exit(index($b,\"session_login\") >= 0 ? 0 : 1)'"
        )
        protocol_rc, _ = exec_in(target.host, protocol_cmd)
        protocol = CheckResult(
            name="protocol",
            passed=protocol_rc == 0,
            detail=f"login page rc={protocol_rc}",
        )
        children = [process, tcp, protocol]
        return CheckResult(
            name="webmin-filemanager-execute",
            passed=all(child.passed for child in children),
            children=children,
        )
