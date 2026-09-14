"""Shallow pyLoad liveness."""

from __future__ import annotations

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget


def _tcp_probe(port: int) -> str:
    return (
        "python3 -c 'import socket;"
        f"s=socket.create_connection((\"127.0.0.1\",{port}),3);"
        "s.close()'"
    )


def _http_probe(port: int) -> str:
    return (
        "python3 -c 'import sys,urllib.request;"
        f"r=urllib.request.urlopen(\"http://127.0.0.1:{port}/\",timeout=5);"
        "b=r.read(4096).lower();"
        "sys.exit(0 if r.status<400 and b\"pyload\" in b else 1)'"
    )


class PyloadFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "pyload-download-manager-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("web",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta.get("exec_in_container")
        rc = 1
        uid = "none"
        if exec_in is not None:
            # Liveness, not identity: the service account can forge this argv.
            rc, output = exec_in(
                target.host,
                "pid=$(pgrep -u pyload -f 'pyload --userdir /srv/pyload/u' | head -1) && "
                "awk '/^Uid:/{print $2}' /proc/$pid/status",
            )
            uid = (output or "").strip()
        process = CheckResult("process", rc == 0 and uid == "1000", f"uid={uid}")

        tcp_rc = http_rc = 1
        if exec_in is not None:
            tcp_rc, _ = exec_in(target.host, _tcp_probe(target.ports["web"]))
            http_rc, _ = exec_in(target.host, _http_probe(target.ports["web"]))
        tcp = CheckResult("tcp", tcp_rc == 0, f"connect rc={tcp_rc}")
        http = CheckResult("http", http_rc == 0, f"GET / rc={http_rc}")

        children = [process, tcp, http]
        return CheckResult(
            "pyload-download-manager",
            all(child.passed for child in children),
            children=children,
        )
