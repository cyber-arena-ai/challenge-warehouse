"""Build the pinned Apache Airflow challenge image."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from .challenge import AirflowChallenge

log = logging.getLogger(__name__)
_BUILD_CONTEXT = Path(__file__).resolve().parent / "image"


def build_image(client: object | None = None) -> str:
    tag = AirflowChallenge().vulbox.reference
    if not _BUILD_CONTEXT.is_dir():
        raise FileNotFoundError(f"missing build context: {_BUILD_CONTEXT}")
    try:
        subprocess.run(
            [
                "docker",
                "build",
                "--platform=linux/amd64",
                "-t",
                tag,
                str(_BUILD_CONTEXT),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            f"docker build failed for {tag}\nstdout:\n{e.stdout}\nstderr:\n{e.stderr}"
        ) from e
    log.info("airflow: built %s", tag)
    return tag
