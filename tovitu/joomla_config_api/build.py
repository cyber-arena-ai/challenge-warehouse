"""Build the pinned Joomla challenge image."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from .challenge import JoomlaConfigApiChallenge

log = logging.getLogger(__name__)
_BUILD_CONTEXT = Path(__file__).resolve().parent / "image"


def build_image(client: object | None = None) -> str:
    del client
    tag = JoomlaConfigApiChallenge().vulbox.reference
    subprocess.run(
        [
            "docker",
            "build",
            "--platform=linux/amd64",
            "--pull=false",
            "-t",
            tag,
            str(_BUILD_CONTEXT),
        ],
        check=True,
    )
    log.info("built %s", tag)
    return tag
