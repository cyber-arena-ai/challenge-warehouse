"""4-level health probe for gradio-lfi."""

from __future__ import annotations

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

PROCESS_PATTERN = "/srv/challenge/app.py"
CHECKER_COMMAND = "/arena/checker.sh"


def _http_probe(port: int, path: str) -> str:
    return (
        "python3 -c \"import urllib.request,sys; "
        f"r=urllib.request.urlopen('http://127.0.0.1:{port}{path}', timeout=4); "
        "sys.exit(0 if r.status==200 else 1)\""
    )


def _tcp_probe(port: int) -> str:
    return (
        "python3 -c \"import socket; s=socket.socket(); s.settimeout(2); "
        f"s.connect(('127.0.0.1', {port})); s.close()\""
    )


class GradioFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "gradio-lfi-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("web",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        port = target.ports["web"]

        rc, _ = exec_in(target.host, f"pgrep -f {PROCESS_PATTERN!r}")
        process = CheckResult(name="process", passed=(rc == 0), detail=f"pgrep rc={rc}")

        rc, _ = exec_in(target.host, _tcp_probe(port))
        tcp = CheckResult(name="tcp", passed=(rc == 0), detail=f"socket-connect rc={rc}")

        rc, _ = exec_in(target.host, _http_probe(port, "/config"))
        http = CheckResult(name="http", passed=(rc == 0), detail=f"GET /config rc={rc}")

        rc, out = exec_in(target.host, CHECKER_COMMAND)
        checker = CheckResult(name="checker", passed=(rc == 0), detail=(out.strip() or f"rc={rc}")[-200:])

        return CheckResult(
            name="gradio-lfi",
            passed=all(c.passed for c in (process, tcp, http, checker)),
            children=[process, tcp, http, checker],
        )
