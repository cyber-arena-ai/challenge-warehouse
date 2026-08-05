"""Liveness probe for mlflow-lfi: process + tcp + http.

  process — a gunicorn worker serving `mlflow.server:app` is alive.
  tcp     — port 5000 accepts a socket connect.
  http    — GET /health returns 200.

The CHECKER is the framework-run `image/checker.sh` (shipped over stdin), no
longer invoked here.
"""

from __future__ import annotations

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

# gunicorn worker cmdline contains the app spec verbatim.
PROCESS_PATTERN = "mlflow.server:app"


def _http_probe(port: int) -> str:
    return (
        "python3 -c \"import urllib.request,sys; "
        f"r=urllib.request.urlopen('http://127.0.0.1:{port}/health', timeout=3); "
        "sys.exit(0 if r.status==200 else 1)\""
    )


def _tcp_probe(port: int) -> str:
    return (
        "python3 -c \"import socket; s=socket.socket(); s.settimeout(2); "
        f"s.connect(('127.0.0.1', {port})); s.close()\""
    )


class MlflowFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "mlflow-lfi-functionality"

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

        rc, _ = exec_in(target.host, _http_probe(port))
        http = CheckResult(name="http", passed=(rc == 0), detail=f"GET /health rc={rc}")

        return CheckResult(
            name="mlflow-lfi",
            passed=all(c.passed for c in (process, tcp, http)),
            children=[process, tcp, http],
        )
