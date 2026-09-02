"""Build the pinned Grafana challenge image."""

from __future__ import annotations

import subprocess

from .challenge import GrafanaProtectedContactPointChallenge


def build_image() -> str:
    image = GrafanaProtectedContactPointChallenge().vulbox
    try:
        subprocess.run(
            [
                "docker", "build", "--platform=linux/amd64",
                "-t", image.reference, image.build_context,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as error:
        raise RuntimeError(
            f"docker build failed for {image.reference}\n"
            f"stdout:\n{error.stdout}\nstderr:\n{error.stderr}"
        ) from error
    return image.reference
