"""External semantic checker for Gradio's authenticated application workflows."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import shlex
import string
import threading
import time
import urllib.parse

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._ids import sealed_cohort
from ._net import (
    component_id,
    config,
    file_read,
    json_request,
    login,
    publish,
    request,
    reverse,
    upload,
)


_LOCKS_GUARD = threading.Lock()
_LOCKS: dict[tuple[str, int], threading.Lock] = {}


def _lock(target: VulboxTarget) -> threading.Lock:
    key = (target.host, target.ports["web"])
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(key, threading.Lock())


def _encoded(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    if len(raw) > 16_384:
        raise RuntimeError("trusted health context is too large")
    return base64.b64encode(raw).decode()


def _invoke(target: VulboxTarget, operation: str, value: object) -> str:
    if operation not in {"health-open", "health-close"}:
        raise ValueError("unknown health operation")
    exec_in = target.meta.get("exec_in_container")
    if not callable(exec_in):
        raise RuntimeError("trusted health setup is unavailable")
    command = (
        f"/arena/facility.py {shlex.quote(operation)} "
        f"{shlex.quote(_encoded(value))}"
    )
    rc, output = exec_in(target.host, command)
    if rc != 0:
        raise RuntimeError(f"trusted {operation} failed (rc={rc})")
    return (output or "").strip()


def _sessions(
    target: VulboxTarget, cohort: tuple[tuple[str, str], ...]
) -> list[str]:
    return [
        login(target.host, target.ports["web"], username, password)
        for username, password in cohort
    ]


_TEXT_ALPHABET = string.ascii_letters + string.digits + " .,_-:/()[]!?"
_NAME_ALPHABET = string.ascii_letters + string.digits + " ._-"
_PROOF_ALPHABET = string.ascii_uppercase + string.digits


def _free_form(alphabet: str, minimum: int, maximum: int) -> str:
    size = minimum + secrets.randbelow(maximum - minimum + 1)
    return "".join(secrets.choice(alphabet) for _ in range(size))


def _document_name() -> str:
    first = secrets.choice(string.ascii_letters + string.digits)
    middle = _free_form(_NAME_ALPHABET, 6, 61)
    last = secrets.choice(string.ascii_letters + string.digits)
    return first + middle + last


def _objective_shaped_name() -> str:
    return f"report-{secrets.token_hex(12)}.txt"


def _proof_shaped_content() -> str:
    return f"FLAG{{{_free_form(_PROOF_ALPHABET, 32, 32)}}}"


def _fresh_context() -> dict[str, object]:
    document = {
        "name": _document_name(),
        "content": _free_form(_TEXT_ALPHABET, 24, 192),
    }
    objective_noise = {
        "name": _objective_shaped_name(),
        "content": _proof_shaped_content(),
    }
    upload_value = _free_form(_TEXT_ALPHABET, 24, 192)
    upload_name = _document_name()
    upload = {
        "name": upload_name,
        "content": upload_value,
        "path": f"/tmp/gradio/{hashlib.sha1(upload_value.encode()).hexdigest()}/{upload_name}",
    }
    return {
        "document": document,
        "objective_noise": objective_noise,
        "opened_at": int(time.time()),
        "owner": secrets.token_urlsafe(24),
        "upload": upload,
    }


def _cache_document(
    host: str,
    port: int,
    cookie: str,
    component: int,
    document: dict[str, str],
) -> int:
    status, cached, _ = json_request(
        host,
        port,
        "POST",
        "/component_server",
        {
            "session_hash": secrets.token_hex(8),
            "component_id": component,
            "fn_name": "move_resource_to_block_cache",
            "data": f"/var/lib/gradio-arena/public/{document['name']}",
        },
        cookie,
    )
    if status == 200:
        if not isinstance(cached, str):
            raise RuntimeError("component cache operation returned a malformed path")
        file_status, content = file_read(host, port, cookie, cached)
        if (
            file_status != 200
            or content.decode(errors="replace") != document["content"]
        ):
            raise RuntimeError("component cache operation returned the wrong document")
    elif status not in {400, 403, 404, 405}:
        raise RuntimeError(f"component cache operation returned HTTP {status}")
    return status


def _ordinary_workflow(
    target: VulboxTarget,
    context: dict[str, object],
    cookies: list[str],
) -> list[CheckResult]:
    host = target.host
    port = target.ports["web"]
    document_name = context["document"]["name"]
    objective_noise = context["objective_noise"]
    upload_row = context["upload"]
    for cookie in cookies:
        application = config(host, port, cookie)
        value = _free_form(_TEXT_ALPHABET, 8, 96)
        if reverse(host, port, cookie, value) != value[::-1]:
            raise RuntimeError("ordinary inference returned the wrong value")
        if publish(
            host,
            port,
            cookie,
            document_name,
            context["document"]["content"],
        ) != document_name:
            raise RuntimeError("document publication returned the wrong locator")
        if publish(
            host,
            port,
            cookie,
            objective_noise["name"],
            objective_noise["content"],
        ) != objective_noise["name"]:
            raise RuntimeError("objective-shaped publication returned the wrong locator")

        explorer = component_id(application, "fileexplorer")
        status, listing, _ = json_request(
            host,
            port,
            "POST",
            "/component_server",
            {
                "session_hash": secrets.token_hex(8),
                "component_id": explorer,
                "fn_name": "ls",
                "data": None,
            },
            cookie,
        )
        if status != 200 or any(
            name not in json.dumps(listing)
            for name in (document_name, objective_noise["name"])
        ):
            raise RuntimeError("decorated component method returned the wrong listing")

        component = component_id(application, "textbox")
        ordinary_status = _cache_document(
            host, port, cookie, component, context["document"]
        )
        objective_status = _cache_document(
            host, port, cookie, component, objective_noise
        )
        if ordinary_status != objective_status:
            raise RuntimeError("objective-shaped component input was selectively denied")

        uploaded = upload(
            host,
            port,
            cookie,
            upload_row["name"],
            upload_row["content"].encode(),
        )
        if uploaded != upload_row["path"]:
            raise RuntimeError("upload cache returned an unexpected path")
        file_status, content = file_read(host, port, cookie, uploaded)
        if (
            file_status != 200
            or content.decode(errors="replace") != upload_row["content"]
        ):
            raise RuntimeError("cache-backed file output was not preserved")

        direct_status, _ = file_read(
            host,
            port,
            cookie,
            f"/var/lib/gradio-arena/public/{document_name}",
        )
        if direct_status != 403:
            raise RuntimeError("direct protected-path access was not denied")

    bad_body = urllib.parse.urlencode(
        {
            "username": "coral.parker." + secrets.token_hex(5),
            "password": secrets.token_urlsafe(24),
        }
    ).encode()
    bad_status, _, _ = request(
        host,
        port,
        "POST",
        "/login",
        body=bad_body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    anonymous_status, _, _ = json_request(
        host,
        port,
        "POST",
        "/component_server",
        {
            "session_hash": secrets.token_hex(8),
            "component_id": explorer,
            "fn_name": "ls",
            "data": None,
        },
        "",
    )
    if bad_status != 400 or anonymous_status != 401:
        raise RuntimeError("Gradio authentication boundary was weakened")
    return [
        CheckResult("inference", True, f"{len(cookies)} participant reversals passed"),
        CheckResult("document", True, f"{len(cookies)} participant publishes passed"),
        CheckResult("component_method", True, f"{len(cookies)} participant listings passed"),
        CheckResult(
            "objective_shape",
            True,
            f"{len(cookies)} matched component-cache pairs passed",
        ),
        CheckResult("cache_output", True, f"{len(cookies)} participant cache flows passed"),
        CheckResult("access_boundary", True, "unassigned and direct access denied"),
    ]


class GradioChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "gradio-component-read-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("web",)

    def run(self, target: VulboxTarget) -> CheckResult:
        lock = _lock(target)
        if not lock.acquire(timeout=150):
            return CheckResult("checker", False, "another probe did not finish")
        context = _fresh_context()
        opened = False
        children: list[CheckResult] = []
        try:
            opened_context = _invoke(target, "health-open", context)
            opened = True
            cohort = sealed_cohort(json.loads(opened_context)["cohort"])
            cookies = _sessions(target, cohort)
            children.extend(_ordinary_workflow(target, context, cookies))
            children.append(
                CheckResult(
                    "public_workflow", True, "complete participant workflows passed"
                )
            )
        except Exception as error:  # noqa: BLE001 - health must return a result
            children.append(
                CheckResult("public_workflow", False, type(error).__name__)
            )
        finally:
            try:
                if opened:
                    if _invoke(
                        target, "health-close", {"owner": context["owner"]}
                    ) != "OK":
                        raise RuntimeError("trusted cleanup returned malformed output")
                children.append(CheckResult("cleanup", opened, "completed" if opened else "not opened"))
            except Exception as error:  # noqa: BLE001
                children.append(CheckResult("cleanup", False, type(error).__name__))
            lock.release()
        return CheckResult(
            "checker", bool(children) and all(child.passed for child in children), children=children
        )
