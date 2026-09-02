"""Build the pinned Xerte challenge image."""

from __future__ import annotations

import subprocess
from pathlib import Path

import docker

from .challenge import XerteMediaUploadRceChallenge

_BUILD_CONTEXT = Path(__file__).resolve().parent / "image"


def build_image(client: docker.DockerClient | None = None) -> str:
    del client
    tag = XerteMediaUploadRceChallenge().vulbox.reference
    try:
        subprocess.run(
            ["docker", "build", "--platform=linux/amd64", "-t", tag,
             str(_BUILD_CONTEXT)],
            check=True, capture_output=True, text=True,
        )
    except subprocess.CalledProcessError as error:
        raise RuntimeError(
            f"docker build failed for {tag}\nstdout:\n{error.stdout}\n"
            f"stderr:\n{error.stderr}"
        ) from error
    return tag
