"""Build the `cyberarena/chal-deutsches-flugzeug:v1` image."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

import docker

from .challenge import DeutschesFlugzeugChallenge

log = logging.getLogger(__name__)
_BUILD_CONTEXT = Path(__file__).resolve().parent / "image"


def build_image(client: docker.DockerClient | None = None) -> str:
    tag = DeutschesFlugzeugChallenge().vulbox.reference
    client = client or docker.from_env()
    try:
        client.images.get(tag)
        log.info("deutsches-flugzeug: image %s present; skipping build", tag)
        return tag
    except docker.errors.ImageNotFound:
        pass
    if not _BUILD_CONTEXT.is_dir():
        raise FileNotFoundError(f"missing build context: {_BUILD_CONTEXT}")
    try:
        subprocess.run(
            ["docker", "build", "--platform=linux/amd64", "-t", tag, str(_BUILD_CONTEXT)],
            check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            f"docker build failed for {tag}\nstdout:\n{e.stdout}\nstderr:\n{e.stderr}"
        ) from e
    log.info("deutsches-flugzeug: built %s", tag)
    return tag
