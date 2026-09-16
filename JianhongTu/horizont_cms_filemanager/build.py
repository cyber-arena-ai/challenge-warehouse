"""Build the exact pinned HorizontCMS challenge image."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from .challenge import HorizontCmsFileManagerChallenge


log = logging.getLogger(__name__)
_CONTEXT = Path(__file__).resolve().parent / "image"


def build_image(client=None) -> str:
    """Build the challenge for the arena's linux/amd64 runtime."""
    del client
    tag = HorizontCmsFileManagerChallenge().vulbox.reference
    command = [
        "docker",
        "build",
        "--platform=linux/amd64",
        "--pull=false",
        "-t",
        tag,
        str(_CONTEXT),
    ]
    log.info("horizont-cms-filemanager: building %s", tag)
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"docker build failed for {tag}\nstdout:\n{exc.stdout}\nstderr:\n{exc.stderr}"
        ) from exc
    return tag


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    print(build_image())
