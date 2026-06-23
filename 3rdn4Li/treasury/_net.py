"""Host resolver for faust-treasury.

The handlers speak the raw pwntools menu protocol on port 6789; they just
need a routable IP. Resolves the prod container name via `docker inspect`; an
IP / resolve failure is used as-is.
"""
from __future__ import annotations

import ipaddress
import subprocess

from challenges.interface import VulboxTarget


def resolve(target: VulboxTarget) -> str:
    host = target.host
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
