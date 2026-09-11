#!/usr/bin/env python3
"""Root-only etcd flag/checker store helper."""

from __future__ import annotations

import base64
import os
import subprocess
import sys

PASSWORD_FILE = "/srv/etcd/root-password"


def _command(*args: str) -> subprocess.CompletedProcess[str]:
    password = open(PASSWORD_FILE).read().strip()
    env = dict(os.environ, ETCDCTL_API="3")
    return subprocess.run(
        [
            "/usr/local/bin/etcdctl",
            "--endpoints=http://127.0.0.1:2379",
            "--user",
            f"root:{password}",
            *args,
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )


def main() -> int:
    if len(sys.argv) < 3:
        return 2
    action, key = sys.argv[1:3]
    if not key.startswith("/"):
        return 2
    if action == "replace-prefix" and len(sys.argv) == 5:
        prefix, replacement_key, encoded = sys.argv[2:5]
        if not prefix.startswith("/") or not replacement_key.startswith(prefix):
            return 2
        try:
            value = base64.urlsafe_b64decode(encoded.encode()).decode()
        except Exception:
            return 2
        result = _command("del", prefix, "--prefix")
        if result.returncode == 0:
            result = _command("put", replacement_key, value)
    elif action == "plant" and len(sys.argv) == 4:
        try:
            value = base64.urlsafe_b64decode(sys.argv[3].encode()).decode()
        except Exception:
            return 2
        result = _command("put", key, value)
    elif action == "retrieve" and len(sys.argv) == 3:
        result = _command("get", key, "--print-value-only")
    elif action == "delete" and len(sys.argv) == 3:
        result = _command("del", key)
    else:
        return 2
    if result.returncode != 0:
        print((result.stderr or result.stdout)[-300:], file=sys.stderr)
        return result.returncode
    if action == "retrieve":
        print(result.stdout.strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
