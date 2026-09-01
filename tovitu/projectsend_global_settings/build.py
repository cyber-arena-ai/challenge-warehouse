"""Build the pinned ProjectSend challenge image."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

import docker

from .challenge import IMAGE_REFERENCE


log = logging.getLogger(__name__)
_CONTEXT = Path(__file__).resolve().parent / "image"


def build_image(client: docker.DockerClient | None = None) -> str:
    client = client or docker.from_env()
    try:
        client.images.get(IMAGE_REFERENCE)
        return IMAGE_REFERENCE
    except docker.errors.ImageNotFound:
        pass
    completed = subprocess.run(
        [
            "docker",
            "build",
            "--platform=linux/amd64",
            "-t",
            IMAGE_REFERENCE,
            str(_CONTEXT),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "ProjectSend image build failed\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    log.info("built %s", IMAGE_REFERENCE)
    return IMAGE_REFERENCE
