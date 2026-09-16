#!/usr/bin/env python3
"""Trusted adapter for rotating the existing native Flask secret object."""

from __future__ import annotations

import base64
import fcntl
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Callable

SECRET_PATH = "/datastore/secret.txt"
DATASTORE_PATH = "/datastore"
TARGET_RE = re.compile(r"/datastore/secret-[0-9a-f]{24}\.txt")
TARGET_NAME_RE = re.compile(r"secret-[0-9a-f]{24}\.txt")


def _metadata(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
        stat.S_IMODE(info.st_mode),
        info.st_uid,
        info.st_gid,
    )


def _write(fd: int, value: bytes) -> None:
    os.lseek(fd, 0, os.SEEK_SET)
    offset = 0
    while offset < len(value):
        offset += os.write(fd, value[offset:])
    os.ftruncate(fd, len(value))
    os.fsync(fd)


def _restart() -> bool:
    result = subprocess.run(
        ["/arena/start.sh"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=150,
    )
    return result.returncode == 0


def _replace_link(target: str) -> None:
    name = os.path.basename(target)
    temporary = os.path.join(DATASTORE_PATH, f".secret-link-{os.getpid()}")
    try:
        os.symlink(name, temporary)
        os.replace(temporary, SECRET_PATH)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _current_object() -> tuple[str, bool]:
    info = os.lstat(SECRET_PATH)
    if stat.S_ISREG(info.st_mode):
        return SECRET_PATH, True
    if not stat.S_ISLNK(info.st_mode):
        raise ValueError("credential object has an invalid type")
    name = os.readlink(SECRET_PATH)
    if os.path.basename(name) != name or TARGET_NAME_RE.fullmatch(name) is None:
        raise ValueError("credential link has an invalid target")
    target = os.path.join(DATASTORE_PATH, name)
    if not stat.S_ISREG(os.lstat(target).st_mode):
        raise ValueError("credential target is not a regular file")
    return target, False


def _cleanup_old_targets(current: str) -> None:
    for entry in os.scandir(DATASTORE_PATH):
        if TARGET_NAME_RE.fullmatch(entry.name) is None or entry.path == current:
            continue
        if entry.is_dir(follow_symlinks=False):
            raise ValueError("stale credential target is a directory")
        os.unlink(entry.path)


def rotate_existing_secret(
    value: str,
    target: str,
    *,
    restart: Callable[[], bool] = _restart,
) -> None:
    encoded = value.encode()
    if not encoded or len(encoded) > 256 or b"\n" in encoded:
        raise ValueError("invalid credential shape")
    if TARGET_RE.fullmatch(target) is None:
        raise ValueError("invalid credential target")
    current, native_layout = _current_object()
    fd = os.open(current, os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("credential object is not a regular file")
        old = os.read(fd, 4097)
        if not old or len(old) > 4096:
            raise ValueError("credential object has invalid prior content")
        before_metadata = _metadata(before)
        _write(fd, encoded)
        if _metadata(os.fstat(fd)) != before_metadata:
            _write(fd, old)
            raise RuntimeError("credential metadata changed")
        moved = False
        restart_error: Exception | None = None
        try:
            if current != target:
                try:
                    target_info = os.lstat(target)
                except FileNotFoundError:
                    target_info = None
                if target_info is not None:
                    if stat.S_ISDIR(target_info.st_mode):
                        raise ValueError("credential target is a directory")
                    os.unlink(target)
                os.replace(current, target)
                moved = True
                _replace_link(target)
            _cleanup_old_targets(target)
            restarted = restart()
        except Exception as error:
            restarted = False
            restart_error = error
        if restarted:
            return
        _write(fd, old)
        if _metadata(os.fstat(fd)) != before_metadata:
            raise RuntimeError("credential metadata changed during rollback")
        if moved:
            try:
                os.unlink(SECRET_PATH)
            except FileNotFoundError:
                pass
            os.replace(target, current)
            if not native_layout:
                _replace_link(current)
        try:
            rollback_restarted = restart()
        except Exception as error:
            raise RuntimeError(
                "credential rotation and rollback restart failed"
            ) from error
        if not rollback_restarted:
            raise RuntimeError("credential rotation and rollback restart failed")
        error = RuntimeError("credential rotation restart failed; prior value restored")
        if restart_error is not None:
            raise error from restart_error
        raise error
    finally:
        os.close(fd)


def _decode(raw: str) -> tuple[str, str]:
    request = json.loads(base64.b64decode(raw, validate=True))
    if not isinstance(request, dict) or set(request) != {"flag", "target"}:
        raise ValueError("invalid request")
    flag = request["flag"]
    target = request["target"]
    if not isinstance(flag, str) or not isinstance(target, str):
        raise ValueError("invalid request")
    return flag, target


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] != "plant":
        return 2
    try:
        flag, target = _decode(argv[2])
        rotate_existing_secret(flag, target)
    except Exception as error:
        print(f"facility placement failed: {type(error).__name__}", file=sys.stderr)
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
