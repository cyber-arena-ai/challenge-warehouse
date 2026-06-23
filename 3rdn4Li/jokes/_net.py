"""Service-URL helper for faust-jokes.

`target.host` is the prod CONTAINER NAME; resolve it to a routable IP via
`docker inspect` so the in-process HTTP handler can reach the service. An IP
(e2e harness) or a resolve failure is used as-is.
"""
from __future__ import annotations

import ipaddress
import subprocess

from challenges.interface import VulboxTarget

_DEFAULT_PORT = 5000


def base_url(target: VulboxTarget) -> str:
    host = _resolve(target.host)
    port = target.ports.get("service", _DEFAULT_PORT)
    return f"http://{host}:{port}"


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
