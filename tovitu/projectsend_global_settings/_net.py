"""Resolve a vulbox container name for host-side HTTP handlers."""

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
        output = subprocess.run(
            [
                "docker",
                "inspect",
                "-f",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
                host,
            ],
            capture_output=True,
            check=False,
            text=True,
            timeout=5,
        ).stdout.split()
        if output:
            return output[0]
    except Exception:  # noqa: BLE001, S110 — DNS runtimes may not have Docker
        pass
    return host
