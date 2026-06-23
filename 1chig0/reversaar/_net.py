"""Host resolver for reversaar.

The handlers speak HTTP on port 7331, so they need a routable IP. The framework
passes `target.host` = prod container name; `docker inspect` turns it into a
bridge IP. An IP / resolve failure is returned as-is.
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
