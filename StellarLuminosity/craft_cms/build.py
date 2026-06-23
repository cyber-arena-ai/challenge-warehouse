"""Build the `cyberarena/chal-craft-cms` image from `image/`.

Shells out to `docker build` (not the python SDK) because the SDK's
legacy builder misroutes `--platform=linux/amd64` on arm hosts.

The build is heavy: it composer-installs Craft 5.6.16, boots a build-time
MariaDB, runs a headless `craft install`, then bakes the installed DB into
the image so containers start fast. Expect several minutes on a cold build.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

import docker

from .challenge import CraftCmsChallenge

log = logging.getLogger(__name__)

_CONTEXT_DIR = Path(__file__).resolve().parent / "image"


def build_image(client: docker.DockerClient | None = None) -> str:
    """Build (or cache-hit) the craft-cms image. Returns the resolved tag."""
    challenge = CraftCmsChallenge()
    tag = challenge.vulbox.reference

    client = client or docker.from_env()
    try:
        client.images.get(tag)
        log.info("craft-cms: image %s already present; skipping build", tag)
        return tag
    except docker.errors.ImageNotFound:
        pass

    if not _CONTEXT_DIR.is_dir():
        raise FileNotFoundError(f"missing build context: {_CONTEXT_DIR}")

    log.info("craft-cms: building %s", tag)
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
    log.info("craft-cms: built %s", tag)
    return tag
