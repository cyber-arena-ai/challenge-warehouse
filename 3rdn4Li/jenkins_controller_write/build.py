"""Build the pinned Jenkins challenge image."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

import docker

from .challenge import JenkinsControllerWriteChallenge


log = logging.getLogger(__name__)
_CONTEXT_DIR = Path(__file__).resolve().parent / "image"


def build_image(client: docker.DockerClient | None = None) -> str:
    challenge = JenkinsControllerWriteChallenge()
    tag = challenge.vulbox.reference
    client = client or docker.from_env()
    try:
        client.images.get(tag)
        log.info("jenkins-controller-write: image %s already present; skipping build", tag)
        return tag
    except docker.errors.ImageNotFound:
        pass

    cmd = [
        "docker",
        "build",
        "--platform=linux/amd64",
        "-t",
        tag,
        str(_CONTEXT_DIR),
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as error:
        raise RuntimeError(
            f"docker build failed for {tag}\n"
            f"stdout:\n{error.stdout}\nstderr:\n{error.stderr}"
        ) from error
    return tag


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    print(build_image())
