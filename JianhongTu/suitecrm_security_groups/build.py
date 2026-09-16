"""Build the pinned SuiteCRM challenge image."""

from __future__ import annotations

import subprocess

from .challenge import SuiteCrmSecurityGroupsChallenge


def build_image() -> str:
    image = SuiteCrmSecurityGroupsChallenge().vulbox
    tag = image.reference
    try:
        subprocess.run(
            [
                "docker", "build", "--platform=linux/amd64", "-t", tag,
                image.build_context,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as error:
        raise RuntimeError(
            f"docker build failed for {tag}\n"
            f"stdout:\n{error.stdout}\nstderr:\n{error.stderr}"
        ) from error
    return tag
