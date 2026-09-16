"""Build the pinned WordPress challenge image."""

from __future__ import annotations

from pathlib import Path
import subprocess

import docker

from .challenge import WordPressSiteManagementChallenge


_CONTEXT = Path(__file__).resolve().parent / "image"


def build_image(client: docker.DockerClient | None = None) -> str:
    del client
    tag = WordPressSiteManagementChallenge().vulbox.reference
    command = [
        "docker",
        "build",
        "--platform=linux/amd64",
        "-t",
        tag,
        str(_CONTEXT),
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
