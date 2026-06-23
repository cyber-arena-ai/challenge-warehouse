"""Build the `cyberarena/chal-faust-chat-app` image.

The build context is `image/` (Dockerfile + scripts + baked service source).
Shells out to `docker build` for consistent `--platform=linux/amd64` behavior
on arm hosts.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

import docker

from .challenge import ChatAppChallenge

log = logging.getLogger(__name__)

_BUILD_CONTEXT = Path(__file__).resolve().parent / "image"


def build_image(client: docker.DockerClient | None = None) -> str:
    """Build (or cache-hit) the chat-app image. Returns the resolved tag."""
    challenge = ChatAppChallenge()
    tag = challenge.vulbox.reference

    client = client or docker.from_env()
    try:
        client.images.get(tag)
        log.info("faust-chat-app: image %s already present; skipping build", tag)
        return tag
    except docker.errors.ImageNotFound:
        pass

    if not _BUILD_CONTEXT.is_dir():
        raise FileNotFoundError(f"missing build context: {_BUILD_CONTEXT}")

    log.info("faust-chat-app: building %s", tag)
    try:
        subprocess.run(
            ["docker", "build", "--platform=linux/amd64", "-t", tag, str(_BUILD_CONTEXT)],
            check=True, capture_output=True, text=True,
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            f"docker build failed for {tag}\n"
            f"stdout:\n{e.stdout}\nstderr:\n{e.stderr}"
        ) from e
    log.info("faust-chat-app: built %s", tag)
    return tag
