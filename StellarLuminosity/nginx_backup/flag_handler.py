"""Rotate and observe the protected native Nginx UI node credential."""

from __future__ import annotations

import base64
from collections.abc import Mapping
import hashlib
import hmac
import json
import re
import time

from challenges.interface import (
    Flag,
    FlagHandler,
    FlagObservation,
    ObservationStatus,
    VulboxTarget,
)

from ._client import (
    fetch_backup,
    json_request,
    login,
    restore_backup,
    rewrite_node_credential,
)


_ADMIN_MANIFEST = "/srv/nginx-ui/private/admin.json"
_SEED_RE = re.compile(r"[0-9a-f]{64}")
_USERNAME_RE = re.compile(r"[0-9a-f]{32}")
_PASSWORD_RE = re.compile(r"[A-Za-z0-9_-]{16}")


def _pack(value: dict[str, str]) -> str:
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unpack(handle: object) -> dict[str, str] | None:
    if not isinstance(handle, str) or not handle:
        return None
    try:
        raw = base64.urlsafe_b64decode(handle + "=" * (-len(handle) % 4))
        value = json.loads(raw)
    except (ValueError, TypeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict) or value.get("v") != "1":
        return None
    if not all(isinstance(value.get(key), str) and value[key] for key in ("target", "flag")):
        return None
    return value


def _admin(target: VulboxTarget) -> tuple[str, str]:
    exec_in = target.meta.get("exec_in_container")
    if exec_in is None:
        raise RuntimeError("Nginx UI administrator bridge unavailable")
    rc, output = exec_in(target.host, f"cat {_ADMIN_MANIFEST}")
    if rc != 0:
        raise RuntimeError("Nginx UI administrator credential unavailable")
    try:
        value = json.loads(output)
    except json.JSONDecodeError as error:
        raise RuntimeError("Nginx UI administrator manifest malformed") from error
    username = value.get("username") if isinstance(value, dict) else None
    password = value.get("password") if isinstance(value, dict) else None
    if (
        not isinstance(username, str)
        or not _USERNAME_RE.fullmatch(username)
        or not isinstance(password, str)
        or not _PASSWORD_RE.fullmatch(password)
    ):
        raise RuntimeError("Nginx UI administrator manifest malformed")
    return username, password


def _node_name(seed: str) -> str:
    if not isinstance(seed, str) or not _SEED_RE.fullmatch(seed):
        raise ValueError("round_context_seed must be 64 lowercase hexadecimal characters")
    digest = hmac.new(
        bytes.fromhex(seed), b"node-credential:target", hashlib.sha256
    ).hexdigest()
    return "Node " + digest[:24]


def _credential_status(
    target: VulboxTarget, secret: str, expected_name: str
) -> tuple[int, bool]:
    status, document = json_request(
        target.host,
        target.ports["service"],
        "GET",
        "/api/settings",
        headers={"X-Node-Secret": secret},
    )
    node = document.get("node") if isinstance(document, dict) else None
    return status, bool(isinstance(node, dict) and node.get("name") == expected_name)


class NginxUiFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "nginx-ui-node-credential"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def plant(
        self, target: VulboxTarget, flags: Mapping[str, Flag]
    ) -> Mapping[str, str]:
        if set(flags) != {"node-credential"}:
            raise ValueError("expected exactly the node-credential store")
        return {
            "node-credential": self._plant_one(
                target, flags["node-credential"].value
            )
        }

    def _plant_one(self, target: VulboxTarget, value: str) -> str:
        seed = target.meta.get("round_context_seed")
        target_name = _node_name(seed)
        handle = _pack({"v": "1", "target": target_name, "flag": value})
        try:
            status, matches = _credential_status(target, value, target_name)
            if status == 200 and matches:
                return handle
        except (OSError, RuntimeError):
            pass

        username, password = _admin(target)
        port = target.ports["service"]
        token = login(target.host, port, username, password)
        archive, key, iv, security = fetch_backup(target.host, port, token)
        replacement = rewrite_node_credential(
            archive,
            key,
            iv,
            node_name=target_name,
            node_secret=value,
        )
        restore_backup(target.host, port, token, replacement, security)

        deadline = time.monotonic() + 45
        last_status = 0
        while time.monotonic() < deadline:
            try:
                last_status, matches = _credential_status(target, value, target_name)
                if last_status == 200 and matches:
                    login(target.host, port, username, password)
                    return handle
            except (OSError, RuntimeError):
                pass
            time.sleep(0.5)
        raise RuntimeError(
            f"Nginx UI did not activate rotated node credential (HTTP {last_status})"
        )

    def retrieve(
        self, target: VulboxTarget, handle: str, expected: str | None = None
    ) -> FlagObservation:
        state = _unpack(handle)
        if state is None:
            return FlagObservation(ObservationStatus.ERROR, detail="invalid handle")
        secret = expected if expected is not None else state["flag"]
        try:
            status, matches = _credential_status(target, secret, state["target"])
        except OSError:
            return FlagObservation(ObservationStatus.ERROR, detail="service unreachable")
        except RuntimeError:
            return FlagObservation(ObservationStatus.ERROR, detail="malformed response")
        if status == 200 and matches:
            return FlagObservation(ObservationStatus.PRESENT, value=secret)
        if status in (401, 403) or (status == 200 and not matches):
            return FlagObservation(
                ObservationStatus.NOT_FOUND, detail="node credential not active"
            )
        return FlagObservation(ObservationStatus.ERROR, detail=f"HTTP {status}")

    def flag_id(self, handle: str) -> str | None:
        state = _unpack(handle)
        return state["target"] if state is not None else None
