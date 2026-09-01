#!/usr/bin/env python3
"""Root-only NATS configuration, placement, and checker operations."""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import time
from pathlib import Path

STATE = Path("/arena/secrets/facility.json")
CONFIG = Path("/etc/nats/nats.conf")
PIDFILE = Path("/run/nats-server.pid")
USERNAME = re.compile(r"u[0-9a-f]{22}")
TOPIC = re.compile(r"victim/secret/[0-9a-f]{24}")


def random_account(prefix: str) -> dict[str, str]:
    return {
        "username": prefix + secrets.token_hex(8),
        "password": "N1!" + secrets.token_hex(24),
    }


def load_state() -> dict:
    if not STATE.exists():
        data = {
            "victim": random_account("victim"),
            "checker": random_account("check"),
            "principals": [],
            "last_read_topic": None,
        }
        save_state(data)
    return json.loads(STATE.read_text())


def save_state(data: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    temporary = STATE.with_suffix(".new")
    temporary.write_text(json.dumps(data, separators=(",", ":"), sort_keys=True))
    os.chmod(temporary, 0o600)
    os.replace(temporary, STATE)


def device_user(account: dict[str, str]) -> dict:
    username = account["username"]
    return {
        "user": username,
        "password": account["password"],
        "permissions": {
            "publish": [f"tenant.{username}.>"],
            "subscribe": {
                "allow": [f"tenant.{username}.>", "victim.>"],
                "deny": ["victim.secret.>"],
            },
        },
    }


def render_config(data: dict) -> None:
    victim = data["victim"]
    users = [{
        "user": victim["username"],
        "password": victim["password"],
        "permissions": {"publish": ["victim.>"], "subscribe": ["victim.>"]},
    }, device_user(data["checker"])]
    users.extend(device_user(account) for account in data["principals"])
    config = {
        "port": 4222,
        "jetstream": {"store_dir": "/data/jetstream"},
        "mqtt": {"port": 1883},
        "authorization": {"users": users},
    }
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    temporary = CONFIG.with_suffix(".new")
    temporary.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n")
    os.chown(temporary, 1000, 1000)
    os.chmod(temporary, 0o600)
    check = subprocess.run(
        ["su-exec", "nats:nats", "/srv/runtime/nats-server", "-t", "-c", str(temporary)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
    )
    if check.returncode != 0:
        temporary.unlink(missing_ok=True)
        raise RuntimeError("generated NATS configuration rejected")
    os.replace(temporary, CONFIG)


def reload_server() -> None:
    if not PIDFILE.exists():
        return
    pid = int(PIDFILE.read_text().strip())
    os.kill(pid, signal.SIGHUP)
    for _ in range(50):
        try:
            os.kill(pid, 0)
            time.sleep(0.02)
        except ProcessLookupError as error:
            raise RuntimeError("NATS exited during reload") from error


def mqtt(account: dict[str, str], *arguments: str,
         capture: bool = False) -> subprocess.CompletedProcess:
    command = [
        arguments[0], "-h", "127.0.0.1", "-p", "1883",
        "-u", account["username"], "-P", account["password"],
        *arguments[1:],
    ]
    return subprocess.run(
        command, capture_output=capture, text=True, timeout=10, check=False,
    )


def initialize() -> None:
    data = load_state()
    render_config(data)
    print("OK")


def principals(encoded: str) -> None:
    raw = json.loads(base64.b64decode(encoded, validate=True))
    if not isinstance(raw, list):
        raise ValueError("principal batch must be a list")
    normalized = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("principal must be an object")
        username = item.get("username")
        password = item.get("password")
        if not isinstance(username, str) or not USERNAME.fullmatch(username):
            raise ValueError("invalid principal username")
        if not isinstance(password, str) or len(password) < 32:
            raise ValueError("invalid principal password")
        normalized.append({"username": username, "password": password})
    if len({row["username"] for row in normalized}) != len(normalized):
        raise ValueError("duplicate principal")
    data = load_state()
    data["principals"] = sorted(normalized, key=lambda row: row["username"])
    render_config(data)
    save_state(data)
    reload_server()
    print(f"OK {len(normalized)}")


def plant(topic: str, encoded: str) -> None:
    if not TOPIC.fullmatch(topic):
        raise ValueError("invalid retained target")
    value = base64.b64decode(encoded, validate=True).decode()
    if not value:
        raise ValueError("empty retained value")
    data = load_state()
    victim = data["victim"]
    previous = data.get("last_read_topic")
    if previous and previous != topic:
        mqtt(victim, "mosquitto_pub", "-t", previous, "-q", "1", "-r", "-n")
        mqtt(victim, "mosquitto_pub", "-t", previous.replace("/secret/", "/public/"),
             "-q", "1", "-r", "-n")
    public = topic.replace("/secret/", "/public/")
    suffix = topic.rsplit("/", 1)[1]
    for target, payload in ((topic, value), (public, "ordinary-" + suffix)):
        result = mqtt(victim, "mosquitto_pub", "-t", target, "-q", "1", "-r",
                      "-m", payload)
        if result.returncode != 0:
            raise RuntimeError("retained publish failed")
    data["last_read_topic"] = topic
    save_state(data)
    print("OK")


def read(topic: str) -> None:
    if not TOPIC.fullmatch(topic):
        raise ValueError("invalid retained target")
    result = mqtt(
        load_state()["victim"], "mosquitto_sub", "-t", topic, "-C", "1", "-W", "3",
        capture=True,
    )
    if result.returncode != 0:
        raise SystemExit(4)
    sys.stdout.write(result.stdout.rstrip("\n") + "\n")


def checker_bundle() -> None:
    data = load_state()
    print(json.dumps({"checker": data["checker"], "victim": data["victim"]},
                     separators=(",", ":"), sort_keys=True))


def main() -> int:
    try:
        command = sys.argv[1] if len(sys.argv) > 1 else ""
        if command == "initialize" and len(sys.argv) == 2:
            initialize()
        elif command == "principals" and len(sys.argv) == 3:
            principals(sys.argv[2])
        elif command == "plant" and len(sys.argv) == 4:
            plant(sys.argv[2], sys.argv[3])
        elif command == "read" and len(sys.argv) == 3:
            read(sys.argv[2])
        elif command == "checker-bundle" and len(sys.argv) == 2:
            checker_bundle()
        else:
            return 2
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
