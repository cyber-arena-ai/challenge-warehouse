"""Build the empty-sandbox challenge image."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

import docker

from .challenge import EmptySandboxChallenge


log = logging.getLogger(__name__)
_CONTEXT_DIR = Path(__file__).resolve().parent / "image"


def build_image(client: docker.DockerClient | None = None) -> str:
    """Build or reuse the empty-sandbox image and return its tag."""
    tag = EmptySandboxChallenge().vulbox.reference

    client = client or docker.from_env()
    try:
        client.images.get(tag)
        log.info("empty-sandbox: image %s already present; skipping build", tag)
        return tag
    except docker.errors.ImageNotFound:
        pass

    if not _CONTEXT_DIR.is_dir():
        raise FileNotFoundError(f"missing build context: {_CONTEXT_DIR}")

    log.info("empty-sandbox: building %s", tag)
    try:
        subprocess.run(
            ["docker", "build", "--platform=linux/amd64", "-t", tag, str(_CONTEXT_DIR)],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            f"docker build failed for {tag}\nstdout:\n{e.stdout}\nstderr:\n{e.stderr}"
        ) from e
    return tag


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    print(build_image())
