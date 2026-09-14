"""Build the pinned Jenkins challenge image."""

from __future__ import annotations

import hashlib
import logging
import subprocess
from pathlib import Path

import docker

from .challenge import JenkinsControllerWriteChallenge


log = logging.getLogger(__name__)
_CONTEXT_DIR = Path(__file__).resolve().parent / "image"
_CONTEXT_LABEL = "org.cyberarena.build-context-sha256"


def _context_sha256() -> str:
    digest = hashlib.sha256()
    for path in sorted(_CONTEXT_DIR.rglob("*")):
        relative = path.relative_to(_CONTEXT_DIR)
        if "__pycache__" in relative.parts or path.suffix == ".pyc":
            continue
        if not path.is_file():
            continue
        name = relative.as_posix().encode()
        digest.update(len(name).to_bytes(4, "big"))
        digest.update(name)
        digest.update(path.read_bytes())
    return digest.hexdigest()


def build_image(client: docker.DockerClient | None = None) -> str:
    challenge = JenkinsControllerWriteChallenge()
    tag = challenge.vulbox.reference
    client = client or docker.from_env()
    context_sha256 = _context_sha256()
    try:
        image = client.images.get(tag)
        labels = image.attrs.get("Config", {}).get("Labels") or {}
        if labels.get(_CONTEXT_LABEL) == context_sha256:
            log.info(
                "jenkins-controller-write: image %s matches build context; "
                "skipping build",
                tag,
            )
            return tag
    except docker.errors.ImageNotFound:
        pass

    cmd = [
        "docker",
        "build",
        "--platform=linux/amd64",
        "--label",
        f"{_CONTEXT_LABEL}={context_sha256}",
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
