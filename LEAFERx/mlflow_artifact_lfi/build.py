"""Build the exact pinned MLflow challenge image."""

from __future__ import annotations

import logging
from pathlib import Path

import docker

from .challenge import MlflowTrackingChallenge


log = logging.getLogger(__name__)
_CONTEXT = Path(__file__).resolve().parent / "image"


def build_image(client: docker.DockerClient | None = None) -> str:
    client = client or docker.from_env()
    tag = MlflowTrackingChallenge().vulbox.reference
    if not _CONTEXT.is_dir():
        raise FileNotFoundError(f"missing build context: {_CONTEXT}")
    log.info("building %s", tag)
    client.images.build(
        path=str(_CONTEXT),
        tag=tag,
        platform="linux/amd64",
        rm=True,
    )
    return tag


if __name__ == "__main__":
    print(build_image())
