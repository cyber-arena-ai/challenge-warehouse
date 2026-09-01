"""Build the exact vulnerable ownCloud challenge image."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from .challenge import OwnCloudSignedUrlChallenge


log = logging.getLogger(__name__)
_CONTEXT_DIR = Path(__file__).resolve().parent / "image"


def build_image(client=None) -> str:
    del client
    challenge = OwnCloudSignedUrlChallenge()
    tag = challenge.vulbox.reference
    if not _CONTEXT_DIR.is_dir():
        raise FileNotFoundError(f"missing build context: {_CONTEXT_DIR}")
    command = [
        "docker",
        "build",
        "--platform=linux/amd64",
        "--pull=false",
        "-t",
        tag,
        str(_CONTEXT_DIR),
    ]
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as error:
        raise RuntimeError(
            f"docker build failed for {tag}\nstdout:\n{error.stdout}\nstderr:\n{error.stderr}"
        ) from error
    return tag


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    print(build_image())
