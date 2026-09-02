"""Build the pinned OpenTSDB challenge image."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from .challenge import OpenTSDBGraphCommandChallenge


log = logging.getLogger(__name__)
_BUILD_CONTEXT = Path(__file__).resolve().parent / "image"


def build_image(client=None) -> str:
    """Build the current package context for the arena's linux/amd64 runtime."""
    del client
    tag = OpenTSDBGraphCommandChallenge().vulbox.reference
    if not _BUILD_CONTEXT.is_dir():
        raise FileNotFoundError(f"missing build context: {_BUILD_CONTEXT}")
    try:
        subprocess.run(
            [
                "docker",
                "build",
                "--platform=linux/amd64",
                "--pull=false",
                "--tag",
                tag,
                str(_BUILD_CONTEXT),
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
    log.info("opentsdb-graph-command: built %s", tag)
    return tag
