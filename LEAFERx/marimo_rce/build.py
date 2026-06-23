"""Build the `cyberarena/chal-marimo-rce` image from `image/`.

Default builds the CVE-pinned (vulnerable) marimo 0.20.4 snapshot. Pass
--version latest to build the patched upstream release, for benchmarking
exploits against patched code:
    python -m challenges.marimo_rce.build                  # vulnerable pin
    python -m challenges.marimo_rce.build --version latest  # patched upstream
"""

from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path

import docker

from .challenge import MarimoRceChallenge

log = logging.getLogger(__name__)

_CONTEXT_DIR = Path(__file__).resolve().parent / "image"
_VERSION_ARG = "MARIMO_VERSION"
_VERSION_ENV = "CYBERARENA_MARIMO_VERSION"


def _resolve_tag(base_tag: str, version: str | None) -> str:
    if not version:
        return base_tag
    return f"{base_tag.rsplit(':', 1)[0]}:{version}"


def build_image(client: docker.DockerClient | None = None, *, version: str | None = None) -> str:
    """Build (or cache-hit) the image. version=None -> CVE pin at the canonical
    tag; a version string (e.g. 'latest') -> that pip version at a suffixed tag."""
    challenge = MarimoRceChallenge()
    base_tag = challenge.vulbox.reference
    version = version if version is not None else os.environ.get(_VERSION_ENV)
    tag = _resolve_tag(base_tag, version)

    client = client or docker.from_env()
    if version is None:
        try:
            client.images.get(tag)
            log.info("marimo-rce: image %s already present; skipping build", tag)
            return tag
        except docker.errors.ImageNotFound:
            pass

    if not _CONTEXT_DIR.is_dir():
        raise FileNotFoundError(f"missing build context: {_CONTEXT_DIR}")

    cmd = ["docker", "build", "--platform=linux/amd64", "-t", tag]
    if version:
        cmd += ["--build-arg", f"{_VERSION_ARG}={version}"]
    cmd.append(str(_CONTEXT_DIR))

    log.info("marimo-rce: building %s (version=%s)", tag, version or "0.20.4")
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            f"docker build failed for {tag}\nstdout:\n{e.stdout}\nstderr:\n{e.stderr}"
        ) from e
    log.info("marimo-rce: built %s", tag)
    return tag


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    ap = argparse.ArgumentParser(description="Build the marimo-rce challenge image.")
    ap.add_argument(
        "--version",
        default=None,
        help="pip version to install (e.g. 'latest' for patched upstream); "
             "default builds the CVE-pinned vulnerable snapshot.",
    )
    args = ap.parse_args()
    print(build_image(version=args.version))
