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
    del client
    tag = NavigateCmsChallenge().vulbox.reference
    completed = subprocess.run(
        [
            "docker",
            "build",
            "--platform=linux/amd64",
            "--pull=false",
            "-t",
            tag,
            str(_BUILD_CONTEXT),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "Navigate CMS image build failed\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    log.info("built %s", tag)
    return tag
