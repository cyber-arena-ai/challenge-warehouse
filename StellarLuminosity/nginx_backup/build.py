"""Build the `cyberarena/chal-nginx-backup` image from `image/`.

Shells out to `docker build` (not the python SDK) because the SDK's
legacy builder misroutes `--platform=linux/amd64` on arm hosts.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

import docker

from .challenge import NginxBackupChallenge

log = logging.getLogger(__name__)

_CONTEXT_DIR = Path(__file__).resolve().parent / "image"


def build_image(client: docker.DockerClient | None = None) -> str:
    """Build (or cache-hit) the nginx-backup image. Returns the resolved tag."""
    challenge = NginxBackupChallenge()
    tag = challenge.vulbox.reference

    client = client or docker.from_env()
    try:
        client.images.get(tag)
        log.info("nginx-backup: image %s already present; skipping build", tag)
        return tag
    except docker.errors.ImageNotFound:
        pass

    if not _CONTEXT_DIR.is_dir():
        raise FileNotFoundError(f"missing build context: {_CONTEXT_DIR}")

    log.info("nginx-backup: building %s", tag)
    try:
        subprocess.run(
            ["docker", "build", "--platform=linux/amd64", "-t", tag, str(_CONTEXT_DIR)],
            check=True, capture_output=True, text=True,
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            f"docker build failed for {tag}\n"
            f"stdout:\n{e.stdout}\nstderr:\n{e.stderr}"
        ) from e
    log.info("nginx-backup: built %s", tag)
    return tag
