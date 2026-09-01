"""External legitimate-workflow checker for etcd."""

from __future__ import annotations

import base64
import ipaddress
import json
import random
import secrets
import shlex
import socket
import subprocess
import urllib.error
import urllib.request

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

USERNAME = "analyst"
PASSWORD = "analyst-pass-v1"
TIMEOUT = 8


def _connectable(host: str, port: int) -> bool:
    try:
        socket.create_connection((host, port), 3).close()
        return True
    except OSError:
        return False


def resolve_host(target: VulboxTarget) -> str | None:
    host = target.host
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return host if _connectable(host, target.ports["service"]) else None
    if _connectable(host, target.ports["service"]):
        return host
    try:
        output = subprocess.run(
            [
                "docker",
                "inspect",
                "-f",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
                host,
            ],
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.split()
        return next(
            (address for address in output if _connectable(address, target.ports["service"])),
            None,
        )
    except Exception:  # noqa: BLE001 - Docker is absent in facility pollers
        return None


def _b64(value: str) -> str:
    return base64.b64encode(value.encode()).decode()


def _request(
    base: str,
    path: str,
    payload: dict[str, object],
    *,
    token: str | None = None,
) -> tuple[int, bytes]:
    headers = {
        "Content-Type": "application/json",
        "User-Agent": random.choice(("etcdctl/3.4", "go-etcd-client/3", "curl/8")),
        "X-Request-ID": secrets.token_hex(8),
    }
    if token:
        headers["Authorization"] = token
    request = urllib.request.Request(
        base + path,
        data=json.dumps(payload).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def _authenticate(base: str) -> str:
    status, raw = _request(
        base,
        "/v3/auth/authenticate",
        {"name": USERNAME, "password": PASSWORD},
    )
    if status != 200:
        raise RuntimeError(f"authentication returned HTTP {status}")
    token = json.loads(raw).get("token")
    if not isinstance(token, str) or not token:
        raise RuntimeError("authentication returned no token")
    return token


def _values(node: object) -> list[str]:
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "value" and isinstance(value, str):
                found.append(value)
            else:
                found.extend(_values(value))
    elif isinstance(node, list):
        for value in node:
            found.extend(_values(value))
    return found


def _put(base: str, token: str, key: str, value: str) -> None:
    status, _ = _request(
        base,
        "/v3/kv/put",
        {"key": _b64(key), "value": _b64(value)},
        token=token,
    )
    if status != 200:
        raise RuntimeError(f"allowed put returned HTTP {status}")


def _delete(base: str, token: str, key: str) -> None:
    status, _ = _request(
        base, "/v3/kv/deleterange", {"key": _b64(key)}, token=token
    )
    if status != 200:
        raise RuntimeError(f"allowed delete returned HTTP {status}")


def _best_effort_delete(base: str, token: str, key: str) -> None:
    try:
        _delete(base, token, key)
    except Exception:  # noqa: BLE001 - cleanup must not mask the first failure
        pass


def _exercise(target: VulboxTarget) -> None:
    host = resolve_host(target)
    if host is None:
        raise RuntimeError("public service is unreachable")
    base = f"http://{host}:{target.ports['service']}"
    token = _authenticate(base)
    nonce = secrets.token_hex(10)
    # These look like ordinary application records rather than advertising a
    # checker-only namespace that a defender could special-case.
    key_one = f"/teams/analyst/config/{nonce}/source"
    key_two = f"/teams/analyst/config/{nonce}/derived"
    key_delete = f"/teams/analyst/config/{nonce}/retired"
    value_one = secrets.token_hex(16)
    value_two = secrets.token_hex(16)
    # Match the real rotating flag's public record shape. A canary under a
    # different prefix would let a defense recognize verifier traffic while
    # leaving the actual flag path exposed.
    protected_key = (
        f"/services/production/{nonce}/credentials/database-password"
    )
    protected_value = secrets.token_hex(20)
    encoded_protected = base64.urlsafe_b64encode(protected_value.encode()).decode()

    exec_in = target.meta["exec_in_container"]
    rc, output = exec_in(
        target.host,
        f"/arena/store.py plant {shlex.quote(protected_key)} "
        f"{shlex.quote(encoded_protected)}",
    )
    if rc != 0:
        raise RuntimeError(f"canary provision failed: {(output or '')[-160:]}")

    try:
        direct_status, _ = _request(
            base,
            "/v3/kv/range",
            {"key": _b64(protected_key)},
            token=token,
        )
        if direct_status != 403:
            raise RuntimeError(
                f"direct protected read returned HTTP {direct_status}, expected 403"
            )

        _put(base, token, key_one, value_one)
        _put(base, token, key_delete, secrets.token_hex(16))
        nested_payload = {
            "success": [
                {
                    "request_txn": {
                        "success": [
                            {"request_range": {"key": _b64(key_one)}},
                            {
                                "request_put": {
                                    "key": _b64(key_two),
                                    "value": _b64(value_two),
                                }
                            },
                            {
                                "request_delete_range": {
                                    "key": _b64(key_delete),
                                }
                            },
                        ]
                    }
                }
            ]
        }
        status, raw = _request(base, "/v3/kv/txn", nested_payload, token=token)
        if status != 200:
            raise RuntimeError(f"allowed nested transaction returned HTTP {status}")
        decoded_values = {
            base64.b64decode(value).decode(errors="replace")
            for value in _values(json.loads(raw))
        }
        if value_one not in decoded_values:
            raise RuntimeError("nested transaction did not read the fresh source value")

        status, raw = _request(
            base,
            "/v3/kv/range",
            {"key": _b64(key_two)},
            token=token,
        )
        if status != 200 or value_two not in {
            base64.b64decode(value).decode(errors="replace")
            for value in _values(json.loads(raw))
        }:
            raise RuntimeError("nested transaction did not persist the fresh derived value")

        status, raw = _request(
            base,
            "/v3/kv/range",
            {"key": _b64(key_delete)},
            token=token,
        )
        if status != 200 or _values(json.loads(raw)):
            raise RuntimeError("nested transaction did not delete the retired value")

        _delete(base, token, key_one)
        _delete(base, token, key_two)
        for deleted_key in (key_one, key_two):
            status, raw = _request(
                base,
                "/v3/kv/range",
                {"key": _b64(deleted_key)},
                token=token,
            )
            if status != 200 or _values(json.loads(raw)):
                raise RuntimeError("allowed delete did not remove the fresh key")

        protected_payload = {
            "success": [
                {
                    "request_txn": {
                        "success": [
                            {"request_range": {"key": _b64(protected_key)}}
                        ]
                    }
                }
            ]
        }
        status, raw = _request(base, "/v3/kv/txn", protected_payload, token=token)
        if status == 200:
            values = {
                base64.b64decode(value).decode(errors="replace")
                for value in _values(json.loads(raw))
            }
            if protected_value not in values:
                raise RuntimeError("protected nested read returned a canned response")
        elif status != 403:
            raise RuntimeError(f"protected nested read returned HTTP {status}")
    finally:
        _best_effort_delete(base, token, key_one)
        _best_effort_delete(base, token, key_two)
        _best_effort_delete(base, token, key_delete)
        exec_in(target.host, f"/arena/store.py delete {shlex.quote(protected_key)}")


class EtcdChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "etcd-nested-rbac-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        try:
            _exercise(target)
            return CheckResult("checker", True, "randomized nested transaction workflow passed")
        except Exception as error:  # noqa: BLE001 - checker failures are data
            return CheckResult(
                "checker",
                False,
                f"{type(error).__name__}: {str(error)[:220]}",
            )
