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
    # Build only when the tag is absent (the convention the other packages
    # follow). Without this the build re-ran on every game and depended on
    # Docker's layer cache to satisfy the `apk add` step: a box with no cache
    # (batch-workers-3, 2026-09-19) re-ran apk against a rotated version pin
    # and failed the game, and any cache prune would do the same elsewhere.
    try:
        client.images.get(tag)
        log.info("vikunja-private-task: image %s present; skipping build", tag)
        return tag
    except docker.errors.ImageNotFound:
        pass
    if not _BUILD_CONTEXT.is_dir():
        raise FileNotFoundError(f"missing build context: {_BUILD_CONTEXT}")
    log.info("vikunja-private-task: building current context as %s", tag)
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
