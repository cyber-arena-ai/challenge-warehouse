"""Build the pinned NATS challenge image."""

from __future__ import annotations

import subprocess
from pathlib import Path

from .challenge import NatsMqttAclChallenge

_BUILD_CONTEXT = Path(__file__).resolve().parent / "image"


def build_image() -> str:
    tag = NatsMqttAclChallenge().vulbox.reference
    try:
        subprocess.run(
            ["docker", "build", "--platform=linux/amd64", "-t", tag,
             str(_BUILD_CONTEXT)],
            check=True, capture_output=True, text=True,
        )
    except subprocess.CalledProcessError as error:
        raise RuntimeError(
            f"docker build failed for {tag}\nstdout:\n{error.stdout}\nstderr:\n{error.stderr}"
        ) from error
    return tag
