"""External gameplay checker for changedetection.io.

Every decisive assertion uses the public authenticated API. Fresh benign
watches prove the complete legitimate watch chain before and after harmless
host-access probes. Each probe may remain available or be rejected by an
equivalent narrow defense without coupling health to one patch implementation.
"""

from __future__ import annotations

import ipaddress
import json
import random
import secrets
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

API_TOKEN = "changedetection-operator-api-token-v1"
TIMEOUT = 10
PUBLIC_TEXT = "changedetection-checker-text"

XPATH_FAMILY = {
    "unparsed-text": (
        "unparsed-text('file:///arena/checker-public.txt')",
        PUBLIC_TEXT,
        None,
    ),
    "unparsed-text-lines": (
        "string-join(unparsed-text-lines('file:///arena/checker-public.txt'), '|')",
        PUBLIC_TEXT,
        None,
    ),
    "unparsed-text-available": (
        "if (unparsed-text-available('file:///arena/checker-public.txt')) "
        "then 'probe-ok' else 'probe-missing'",
        "probe-ok",
        None,
    ),
    "doc": (
        "string(doc('file:///arena/checker-public.xml')/probe)",
        None,
        "error retrieving resource",
    ),
    "doc-available": (
        "if (doc-available('file:///arena/checker-public.xml')) "
        "then 'probe-ok' else 'probe-missing'",
        "probe-missing",
        None,
    ),
    "environment-variable": (
        "environment-variable('CHECKER_PUBLIC_ENV')",
        None,
        "no filters were found",
    ),
    "available-environment-variables": (
        "if (some $name in available-environment-variables() satisfies "
        "$name = 'CHECKER_PUBLIC_ENV') then 'probe-ok' else 'probe-missing'",
        "probe-missing",
        None,
    ),
}


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
            (
                address
                for address in output
                if _connectable(address, target.ports["service"])
            ),
            None,
        )
    except Exception:  # noqa: BLE001 - Docker is absent in facility pollers
        return None


def _headers() -> dict[str, str]:
    headers = {
        "Content-Type": "application/json",
        "x-api-key": API_TOKEN,
        "User-Agent": random.choice(
            ("changedetection-operator/1.0", "python-requests/2.34", "curl/8.14")
        ),
    }
    if random.random() < 0.7:
        headers["X-Request-ID"] = secrets.token_hex(8)
    return headers


def _request(
    base: str,
    path: str,
    *,
    method: str = "GET",
    payload: dict[str, object] | None = None,
) -> tuple[int, bytes]:
    body = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        base + path,
        data=body,
        headers=_headers(),
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def _delete_watch(base: str, watch_uuid: str) -> None:
    try:
        _request(base, f"/api/v1/watch/{watch_uuid}", method="DELETE")
    except Exception:  # noqa: BLE001 - best-effort cleanup
        pass


def _watch_result(
    base: str,
    xpath: str,
    expected: str | None,
    *,
    fixture_value: str | None = None,
    allowed_error: str | None = None,
    allow_blocked: bool = False,
) -> str:
    """Return ``allowed`` or ``blocked`` for one fresh XPath watch."""
    marker = fixture_value or secrets.token_hex(8)
    fixture_url = "http://127.0.0.1:8081/page?" + urllib.parse.urlencode(
        {"value": marker}
    )
    status, raw = _request(
        base,
        "/api/v1/watch",
        method="POST",
        payload={
            "url": fixture_url,
            "title": f"operations-watch-{secrets.token_hex(5)}",
            "fetch_backend": "html_requests",
            "include_filters": [f"xpath:{xpath}"],
        },
    )
    if status == 400:
        if allow_blocked:
            return "blocked"
        raise RuntimeError("required XPath watch was rejected")
    if status != 201:
        raise RuntimeError(f"watch creation returned HTTP {status}")
    try:
        watch_uuid = json.loads(raw)["uuid"]
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise RuntimeError("watch creation returned an invalid envelope") from error

    try:
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            status, history = _request(
                base, f"/api/v1/watch/{watch_uuid}/history/latest"
            )
            if status == 200:
                value = history.decode(errors="replace").strip()
                if value != expected:
                    if allow_blocked:
                        return "blocked"
                    raise RuntimeError("XPath watch returned unexpected content")
                return "allowed"
            if status != 404:
                raise RuntimeError(f"history retrieval returned HTTP {status}")

            status, raw_watch = _request(base, f"/api/v1/watch/{watch_uuid}")
            if status != 200:
                raise RuntimeError(f"watch status returned HTTP {status}")
            watch = json.loads(raw_watch)
            last_error = str(watch.get("last_error") or "")
            if last_error:
                lowered = last_error.lower()
                if allowed_error and allowed_error.lower() in lowered:
                    return "allowed"
                if allow_blocked:
                    return "blocked"
                raise RuntimeError("XPath watch failed unexpectedly")
            time.sleep(random.uniform(0.6, 1.2))
        raise RuntimeError("watch worker did not produce history")
    finally:
        _delete_watch(base, watch_uuid)


def _exercise(base: str) -> str:
    marker = secrets.token_hex(12)
    benign = _watch_result(
        base,
        "string(//main[@id='watch-body'])",
        marker,
        fixture_value=marker,
    )
    if benign != "allowed":
        raise RuntimeError("benign XPath filtering is disabled")

    states = {
        name: _watch_result(
            base,
            expression,
            expected,
            allowed_error=allowed_error,
            allow_blocked=True,
        )
        for name, (expression, expected, allowed_error) in XPATH_FAMILY.items()
    }

    marker = secrets.token_hex(12)
    benign = _watch_result(
        base,
        "string(//main[@id='watch-body'])",
        marker,
        fixture_value=marker,
    )
    if benign != "allowed":
        raise RuntimeError("benign XPath filtering is disabled after host-access probes")

    allowed = sum(state == "allowed" for state in states.values())
    blocked = len(states) - allowed
    return f"{allowed} allowed, {blocked} blocked"


class ChangedetectionIoChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "changedetection-io-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        host = resolve_host(target)
        if host is None:
            return CheckResult("checker", False, "public service is unreachable")
        base = f"http://{host}:{target.ports['service']}"
        try:
            family_state = _exercise(base)
        except Exception as error:  # noqa: BLE001 - broken gameplay is a failed check
            return CheckResult(
                "checker",
                False,
                f"watch/XPath/history workflow failed: {type(error).__name__}",
            )
        return CheckResult(
            "checker",
            True,
            f"legitimate watch workflow passed; XPath host-access family {family_state}",
        )
