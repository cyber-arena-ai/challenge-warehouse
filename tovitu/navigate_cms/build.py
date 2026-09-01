"""Build the pinned Navigate CMS image."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

import docker

from .challenge import NavigateCmsChallenge

log = logging.getLogger(__name__)
_BUILD_CONTEXT = Path(__file__).resolve().parent / "image"


def build_image(client: docker.DockerClient | None = None) -> str:
    tag = NavigateCmsChallenge().vulbox.reference
    client = client or docker.from_env()
    try:
        client.images.get(tag)
        return tag
    except docker.errors.ImageNotFound:
        pass
    subprocess.run(
        [
            "docker",
            "build",
            "--platform=linux/amd64",
            "--pull=false",
            "-t",
            tag,
            str(_BUILD_CONTEXT),
        ],
        check=True,
    )
    log.info("built %s", tag)
    return tag
