"""External randomized checker for Openfire's legitimate workflows."""

from __future__ import annotations

import secrets
import time
import urllib.parse

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._client import (
    OpenfireError,
    delete_plugin,
    delete_user,
    ensure_user,
    login,
    upload_plugin,
)
from ._health_identity import checker_principal_pools, issued_principals
from ._plugin import health_plugin, health_property, ordinary_plugin_identity
from ._xmpp import exchange


_WORDS = (
    "archive", "board", "calendar", "campus", "community", "contacts",
    "courses", "directory", "events", "groups", "library", "meetings",
    "messages", "notes", "projects", "resources", "rooms", "schedule",
    "support", "teams", "updates", "workspace",
)


def _username() -> str:
    return "user" + secrets.token_hex(8)


def _plugin_identity() -> tuple[str, str, str, str]:
    canonical, display_name, description = ordinary_plugin_identity(
        secrets.token_bytes(32)
    )
    return canonical, display_name, description, secrets.token_hex(16)


def _message() -> str:
    words = [secrets.choice(_WORDS) for _ in range(5 + secrets.randbelow(8))]
    return " ".join((words[0].title(), *words[1:])) + "."


def _wait_for_property(
    admin, property_name: str, property_value: str, present: bool
) -> None:
    deadline = time.monotonic() + 15
    marker = property_name.encode()
    value = property_value.encode()
    path = "/server-properties.jsp?" + urllib.parse.urlencode(
        {"searchName": property_name}
    )
    while time.monotonic() < deadline:
        page = admin.request("GET", path)
        if page.status != 200:
            time.sleep(0.5)
            continue
        found = marker in page.body and value in page.body
        if found is present:
            return
        time.sleep(0.5)
    state = "appear" if present else "disappear"
    raise OpenfireError(f"plugin property did not {state}")


class OpenfireChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "openfire-server-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service", "xmpp")

    def run(self, target: VulboxTarget) -> CheckResult:
        try:
            pools = checker_principal_pools(target)
            admin_username, admin_password = secrets.choice(pools["administrator"])
            roster = [*issued_principals(target), secrets.choice(pools["ordinary"])]
            secrets.SystemRandom().shuffle(roster)
        except (KeyError, RuntimeError, ValueError) as exc:
            return CheckResult(
                name="checker",
                passed=False,
                detail=f"facility identity unavailable: {exc}",
            )

        lifecycle_user = _username()
        lifecycle_password = "Of9!" + secrets.token_hex(16)
        canonical = ""
        base_url = f"http://{target.host}:{target.ports['service']}"
        try:
            admin = login(base_url, admin_username, admin_password)
            ensure_user(admin, lifecycle_user, lifecycle_password, "Openfire User")
            exchange(
                target.host,
                target.ports["xmpp"],
                roster,
                [_message() for _ in roster],
            )
            canonical, display_name, description, property_value = _plugin_identity()
            payload = health_plugin(
                canonical, display_name, description, property_value
            )
            property_name = health_property(canonical, property_value)
            upload_plugin(admin, canonical + ".jar", payload)
            page = admin.request("GET", "/plugin-admin.jsp")
            if page.status != 200 or display_name.encode() not in page.body:
                raise OpenfireError("uploaded health plugin was not listed")
            _wait_for_property(admin, property_name, property_value, True)
            delete_plugin(admin, canonical)
            _wait_for_property(admin, property_name, property_value, False)
            canonical = ""
            delete_user(admin, lifecycle_user)
            lifecycle_user = ""
        except Exception as exc:
            detail = (
                str(exc)
                if isinstance(exc, (OpenfireError, RuntimeError))
                else type(exc).__name__
            )
            return CheckResult(name="checker", passed=False, detail=detail[-240:])
        finally:
            try:
                cleanup = login(base_url, admin_username, admin_password)
                if canonical:
                    delete_plugin(cleanup, canonical)
                if lifecycle_user:
                    delete_user(cleanup, lifecycle_user)
            except Exception:
                pass
        return CheckResult(
            name="checker",
            passed=True,
            detail=(
                f"{len(roster)}-identity XMPP exchange covering every issued "
                "participant and admin user/plugin lifecycle passed"
            ),
        )
