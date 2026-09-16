"""Build the pinned Dolibarr challenge image."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from .challenge import IMAGE_REFERENCE


log = logging.getLogger(__name__)
_CONTEXT = Path(__file__).resolve().parent / "image"


def build_image(client: object | None = None) -> str:
    """Build the current linux/amd64 package context and return its tag."""

    del client

    completed = subprocess.run(
        [
            "docker",
            "build",
            "--platform=linux/amd64",
            "--pull=false",
            "-t",
            IMAGE_REFERENCE,
            str(_CONTEXT),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "Dolibarr image build failed\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    log.info("built %s", IMAGE_REFERENCE)
    return IMAGE_REFERENCE
