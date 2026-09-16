"""Shallow marimo liveness and trusted editor-token handoff."""

from __future__ import annotations

import base64
import json
import re
import secrets
import shlex
import socket
import threading
import urllib.error
import urllib.parse
import urllib.request

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget


_EDITOR_TOKEN_META = "_marimo_editor_token"
_EDITOR_ERROR_META = "_marimo_editor_token_error"
_HEALTH_OPERATION_META = "_marimo_health_operation"
_HEALTH_EXPECTED_META = "_marimo_health_expected"
_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}")
_LOCKS_GUARD = threading.Lock()
_LOCKS: dict[tuple[str, int], threading.Lock] = {}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        del request, fp, code, msg, headers, newurl
        return None


def _health_lock(target: VulboxTarget) -> threading.Lock:
    key = (target.host, target.ports["service"])
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(key, threading.Lock())


class MarimoFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "marimo-notebook-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        with _health_lock(target):
            return self._run_locked(target)

    def _run_locked(self, target: VulboxTarget) -> CheckResult:
        process = self._process(target)
        tcp = self._tcp(target)
        http = self._http(target)
        children = [process, tcp, http]
        if all(child.passed for child in children):
            self._prepare_editor_token(target)
            self._prepare_health_operation(target)
        return CheckResult(
            "marimo-notebook",
            all(child.passed for child in children),
            children=children,
        )

    @staticmethod
    def _process(target: VulboxTarget) -> CheckResult:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            return CheckResult("process", False, "no exec bridge")
        rc, output = exec_in(
            target.host,
            "generation=$(cat /run/marimo/service.generation 2>/dev/null) && "
            "pid=$(cat /run/marimo/service.pid 2>/dev/null) && "
            "awk '/^Uid:/{print $2}' /proc/$pid/status && "
            "tr '\\0' '\\n' </proc/$pid/cmdline | "
            "grep -qxF \"arena_generation=$generation\" && "
            "! tr '\\0' ' ' </proc/$pid/cmdline | grep -q -- '--token-password ' && "
            "/arena/service-owner.sh \"$pid\" 2718",
        )
        detail = (output or "").strip()
        return CheckResult("process", rc == 0 and detail == "1000", f"uid={detail}")

    @staticmethod
    def _tcp(target: VulboxTarget) -> CheckResult:
        try:
            socket.create_connection(
                (target.host, target.ports["service"]), timeout=4
            ).close()
            return CheckResult("tcp", True, "public port reachable")
        except OSError as error:
            return CheckResult("tcp", False, type(error).__name__)

    @staticmethod
    def _http(target: VulboxTarget) -> CheckResult:
        url = f"http://{target.host}:{target.ports['service']}/"
        try:
            opener = urllib.request.build_opener(_NoRedirect)
            try:
                opener.open(url, timeout=8)
                return CheckResult("http", False, "public root did not require login")
            except urllib.error.HTTPError as redirect:
                if redirect.code != 303:
                    return CheckResult("http", False, f"public root HTTP {redirect.code}")
                location = redirect.headers.get("Location", "")
            parsed = urllib.parse.urlparse(location)
            expected = (target.host, target.ports["service"])
            next_url = urllib.parse.parse_qs(parsed.query).get("next", [""])[0]
            next_parsed = urllib.parse.urlparse(next_url)
            public_redirect = (
                parsed.hostname == expected[0]
                and parsed.port == expected[1]
                and parsed.path == "/auth/login"
                and next_parsed.hostname == expected[0]
                and next_parsed.port == expected[1]
            )
            if not public_redirect:
                return CheckResult("http", False, f"private or malformed redirect: {location[:160]}")
            with urllib.request.urlopen(location, timeout=8) as response:
                body = response.read(8192).lower()
            passed = response.status == 200 and b"marimo" in body and b"password" in body
            return CheckResult("http", passed, f"public login HTTP {response.status}")
        except (OSError, ValueError, urllib.error.URLError) as error:
            return CheckResult("http", False, type(error).__name__)

    @staticmethod
    def _prepare_editor_token(target: VulboxTarget) -> None:
        try:
            exec_in = target.meta.get("exec_in_container")
            if exec_in is None:
                raise RuntimeError("facility exec bridge is unavailable")
            rc, output = exec_in(
                target.host, "/arena/facility.py editor-token"
            )
            token = (output or "").strip()
            if rc != 0 or _TOKEN_RE.fullmatch(token) is None:
                raise RuntimeError(
                    f"editor token handoff failed: rc={rc}"
                )
            target.meta[_EDITOR_TOKEN_META] = token
            target.meta.pop(_EDITOR_ERROR_META, None)
        except Exception as error:  # surfaced by the external checker
            target.meta[_EDITOR_ERROR_META] = f"{type(error).__name__}: {error}"[:180]

    @staticmethod
    def _prepare_health_operation(target: VulboxTarget) -> None:
        target.meta.pop(_HEALTH_OPERATION_META, None)
        target.meta.pop(_HEALTH_EXPECTED_META, None)
        try:
            exec_in = target.meta.get("exec_in_container")
            if exec_in is None:
                raise RuntimeError("facility exec bridge is unavailable")
            operation = secrets.token_hex(16)
            expected = secrets.token_hex(20)
            payload = base64.b64encode(
                json.dumps(
                    {"operation": operation, "output": expected},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).decode()
            rc, output = exec_in(
                target.host,
                f"printf %s {shlex.quote(payload)} | "
                "/arena/facility.py health-operation",
            )
            if rc != 0 or (output or "").strip() != "OK":
                raise RuntimeError(f"health operation setup failed: rc={rc}")
            target.meta[_HEALTH_OPERATION_META] = operation
            target.meta[_HEALTH_EXPECTED_META] = expected
        except Exception as error:  # surfaced by the external checker
            target.meta[_EDITOR_ERROR_META] = f"{type(error).__name__}: {error}"[:180]
