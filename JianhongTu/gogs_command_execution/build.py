"""Build the pinned Gogs challenge image."""

from __future__ import annotations

import subprocess
from pathlib import Path

from .challenge import GogsCodeCollaborationChallenge


_CONTEXT = Path(__file__).resolve().parent / "image"


def build_image() -> str:
    challenge = GogsCodeCollaborationChallenge()
    tag = challenge.vulbox.reference
    command = ["docker", "build", "--platform=linux/amd64", "-t", tag, str(_CONTEXT)]
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as error:
        raise RuntimeError(
            f"docker build failed for {tag}\nstdout:\n{error.stdout}\nstderr:\n{error.stderr}"
        ) from error
    return tag


if __name__ == "__main__":
    print(build_image())
