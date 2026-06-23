"""Host helper for faust-birthdaygram.

The vendored `_checker/utils.py` builds URLs as `http://{self.ip}:3000/...`, so
the handlers reuse it UNMODIFIED and just hand it a tiny object whose
`.ip` is the prod container's routable IP (resolved from the container name via
`docker inspect`; an IP / resolve failure is used as-is).
"""
from __future__ import annotations

import ipaddress
import os
import subprocess

from challenges.interface import VulboxTarget


class _CheckerLike:
    """Minimal stand-in for the upstream checker — utils.py only reads `.ip`."""

    def __init__(self, ip: str):
        self.ip = ip


def make_checker(target: VulboxTarget) -> _CheckerLike:
    # utils.py reads/writes PNG scratch files under /tmp/{images,flags}/ (the
    # upstream checker's __main__ created these; we must too since we don't run it).
    os.makedirs("/tmp/images", exist_ok=True)
    os.makedirs("/tmp/flags", exist_ok=True)
    return _CheckerLike(_resolve(target.host))


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
