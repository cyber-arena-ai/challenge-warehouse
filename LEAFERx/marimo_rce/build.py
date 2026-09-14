"""Build the exact pinned marimo notebook image."""

from __future__ import annotations

import hashlib
import logging
import subprocess
from pathlib import Path

from .challenge import IMAGE_TAG, MarimoNotebookChallenge


log = logging.getLogger(__name__)
_CONTEXT = Path(__file__).resolve().parent / "image"


def _context_tag() -> str:
    digest = hashlib.sha256()
    for path in sorted(_CONTEXT.rglob("*")):
        relative = path.relative_to(_CONTEXT)
        if (
            not path.is_file()
            or "__pycache__" in relative.parts
            or path.suffix == ".pyc"
        ):
            continue
        digest.update(relative.as_posix().encode())
        digest.update(b"\0")
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        digest.update(b"\0")
    return "ctx-" + digest.hexdigest()


def build_image(client: object | None = None) -> str:
    del client
    actual_tag = _context_tag()
    if actual_tag != IMAGE_TAG:
        raise RuntimeError(
            f"build context tag drifted: declared {IMAGE_TAG}, actual {actual_tag}"
        )
    tag = MarimoNotebookChallenge().vulbox.reference
    command = ["docker", "build", "--platform=linux/amd64", "-t", tag, str(_CONTEXT)]
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
