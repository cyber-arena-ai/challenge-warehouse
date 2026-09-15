"""Build the exact Nginx UI source package."""

from __future__ import annotations

import subprocess
from pathlib import Path

from .challenge import NginxUiManagementChallenge


_CONTEXT = Path(__file__).resolve().parent / "image"


def build_image(client=None) -> str:
    tag = NginxUiManagementChallenge().vulbox.reference
    subprocess.run(
        [
            "docker",
            "build",
            "--platform=linux/amd64",
            "--tag",
            tag,
            str(_CONTEXT),
        ],
        check=True,
    )
    return tag
