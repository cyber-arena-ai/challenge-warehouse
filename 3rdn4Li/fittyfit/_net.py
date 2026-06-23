"""Service-URL helper for faust-fittyfit.

Returns the base URL WITH a trailing slash to match the upstream checker's
`self._baseurl = http://[ip]:5001/` (the inlined `_client` helpers replicate
its exact URL concatenations). Resolves the prod container name to a routable
IP via `docker inspect`; an IP / resolve failure is used as-is.
"""
from __future__ import annotations

import ipaddress
import subprocess

from challenges.interface import VulboxTarget

_DEFAULT_PORT = 5001


def base_url(target: VulboxTarget) -> str:
    host = _resolve(target.host)
    port = target.ports.get("service", _DEFAULT_PORT)
    return f"http://{host}:{port}/"


def _resolve(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        out = subprocess.run(
            ["docker", "inspect", "-f",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", host],
            capture_output=True, text=True, timeout=5,
        ).stdout.split()
        if out:
            return out[0]
    except Exception:
        pass
    return host
