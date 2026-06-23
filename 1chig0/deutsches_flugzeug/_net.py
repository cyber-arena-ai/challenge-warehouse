"""Host resolver for deutsches-flugzeug.

The HTTP handlers just need a routable IP. The framework passes
`target.host` = prod container name, which `docker inspect` turns into a
bridge IP. An IP / resolve failure is used as-is.
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
