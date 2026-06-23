"""Respawn certified-transparency via /arena/restart.sh.

The service is two compiled Go binaries (log :3000 + monitor :3001), so "rebuild"
is `go build` of both (a broken edit fails the build, SOP §7) plus a kill/relaunch
of both daemons. The smoke leaf HTTP-probes get-sth (log) and get-pubkey (monitor).
"""
from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget

RESTART_COMMAND = "/arena/restart.sh"


class CertifiedTransparencyRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "certified-transparency-restart-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service", "monitor")

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        port = target.ports.get("service", 3000)
        mon_port = target.ports.get("monitor", 3001)

        rc, out = exec_in(target.host, RESTART_COMMAND)
        ok = (rc == 0)
        compile_ = CheckResult(name="compile", passed=ok,
                               detail=(out.strip() or f"rc={rc}")[-200:])
        spawn = CheckResult(name="spawn", passed=ok,
                            detail="ok" if ok else "see compile detail")
        if ok:
            probe = (
                "python3 - <<'PY'\n"
                "import socket,sys\n"
                "def alive(port, path, needle):\n"
                "    try:\n"
                "        s=socket.socket(); s.settimeout(3); s.connect(('127.0.0.1',port))\n"
                "        s.sendall(('GET %s HTTP/1.0\\r\\nHost: x\\r\\n\\r\\n' % path).encode())\n"
                "        data=b''\n"
                "        while True:\n"
                "            c=s.recv(4096)\n"
                "            if not c: break\n"
                "            data+=c\n"
                "        s.close()\n"
                "        return needle in data\n"
                "    except Exception:\n"
                "        return False\n"
                f"ok = alive({port}, '/api/v1/get-sth', b'\"sth\"') and alive({mon_port}, '/api/v1/get-pubkey', b'\"pubkey\"')\n"
                "sys.exit(0 if ok else 1)\n"
                "PY"
            )
            srv_rc, _ = exec_in(target.host, probe)
            smoke = CheckResult(name="smoke", passed=(srv_rc == 0),
                                detail=f"log+monitor probe rc={srv_rc}")
        else:
            smoke = CheckResult(name="smoke", passed=False, detail="skipped; build failed")
        return CheckResult(name="certified-transparency-restart",
                           passed=all(x.passed for x in (compile_, spawn, smoke)),
                           children=[compile_, spawn, smoke])
