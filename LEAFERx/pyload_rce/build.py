"""Build the pinned pyLoad image."""

from __future__ import annotations

import subprocess
from pathlib import Path

from .challenge import PyloadDownloadManagerChallenge

_CONTEXT = Path(__file__).resolve().parent / "image"


def build_image() -> str:
    tag = PyloadDownloadManagerChallenge().vulbox.reference
    try:
        subprocess.run(
            ["docker", "build", "--platform=linux/amd64", "-t", tag, str(_CONTEXT)],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as error:
        raise RuntimeError(
            f"docker build failed for {tag}\nstdout:\n{error.stdout}\nstderr:\n{error.stderr}"
        ) from error
    return tag
