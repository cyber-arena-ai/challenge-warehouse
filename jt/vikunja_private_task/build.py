"""Build the pinned Vikunja challenge image."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

import docker

from .challenge import VikunjaPrivateTaskChallenge

log = logging.getLogger(__name__)
_BUILD_CONTEXT = Path(__file__).resolve().parent / "image"


def build_image(client: docker.DockerClient | None = None) -> str:
    tag = VikunjaPrivateTaskChallenge().vulbox.reference
    client = client or docker.from_env()
    try:
        client.images.get(tag)
        log.info("vikunja-private-task: image %s present; skipping build", tag)
        return tag
    except docker.errors.ImageNotFound:
        pass
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
