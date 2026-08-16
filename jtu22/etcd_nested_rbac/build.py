"""Build the etcd nested-transaction RBAC challenge image."""

from __future__ import annotations

import subprocess
from pathlib import Path

import docker

from .challenge import EtcdNestedRbacChallenge

_CONTEXT_DIR = Path(__file__).resolve().parent / "image"


def build_image(client: docker.DockerClient | None = None) -> str:
    tag = EtcdNestedRbacChallenge().vulbox.reference
    command = [
        "docker",
        "build",
        "--platform=linux/amd64",
        "-t",
        tag,
        str(_CONTEXT_DIR),
    ]
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as error:
        raise RuntimeError(
            f"docker build failed for {tag}\n"
            f"stdout:\n{error.stdout}\nstderr:\n{error.stderr}"
        ) from error
    return tag


if __name__ == "__main__":
    print(build_image())
