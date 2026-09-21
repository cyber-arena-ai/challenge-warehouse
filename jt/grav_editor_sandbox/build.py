"""Build the `cyberarena/chal-grav-editor-sandbox:v1` image.

The build downloads and hash-verifies the official grav-admin 2.0.0-beta.1
release archive, so it needs network at BUILD time and none at run time.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

import docker

from .challenge import GravEditorSandboxChallenge

log = logging.getLogger(__name__)

_BUILD_CONTEXT = Path(__file__).resolve().parent / "image"


def build_image(client: docker.DockerClient | None = None) -> str:
    tag = GravEditorSandboxChallenge().vulbox.reference
    client = client or docker.from_env()
    try:
        client.images.get(tag)
        log.info("grav-editor-sandbox: image %s present; skipping build", tag)
        return tag
    except docker.errors.ImageNotFound:
        pass
    if not _BUILD_CONTEXT.is_dir():
        raise FileNotFoundError(f"missing build context: {_BUILD_CONTEXT}")
    try:
        subprocess.run(
            ["docker", "build", "--platform=linux/amd64", "-t", tag, str(_BUILD_CONTEXT)],
            check=True, capture_output=True, text=True,
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            f"docker build failed for {tag}\nstdout:\n{e.stdout}\nstderr:\n{e.stderr}"
        ) from e
    log.info("grav-editor-sandbox: built %s", tag)
    return tag
