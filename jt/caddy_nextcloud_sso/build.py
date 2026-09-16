"""Build the pinned Caddy and Nextcloud challenge image."""

from __future__ import annotations

import subprocess

from .challenge import CaddyNextcloudSsoChallenge


def build_image() -> str:
    image = CaddyNextcloudSsoChallenge().vulbox
    tag = image.reference
    try:
        subprocess.run(
            ["docker", "build", "--platform=linux/amd64", "-t", tag,
             image.build_context],
            check=True, capture_output=True, text=True,
        )
    except subprocess.CalledProcessError as error:
        raise RuntimeError(
            f"docker build failed for {tag}\nstdout:\n{error.stdout}\nstderr:\n{error.stderr}"
        ) from error
    return tag
