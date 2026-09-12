"""External randomized checker for Openfire's legitimate workflows."""

from __future__ import annotations

import secrets
import string
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
from ._health_identity import checker_admin_credentials
from ._plugin import health_plugin, health_property
from ._xmpp import exchange


def _username() -> str:
    return "".join(secrets.choice(string.ascii_lowercase) for _ in range(14))


def _wait_for_property(admin, property_name: str, nonce: str, present: bool) -> None:
    deadline = time.monotonic() + 15
    marker = property_name.encode()
    value = ("active-" + nonce).encode()
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
    raise OpenfireError(f"plugin integration property did not {state}")


class OpenfireChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "openfire-setup-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service", "xmpp")

    def run(self, target: VulboxTarget) -> CheckResult:
        try:
            admin_username, admin_password = checker_admin_credentials(target)
        except RuntimeError:
            return CheckResult(
                name="checker", passed=False, detail="facility identity unavailable"
            )

        nonce = secrets.token_hex(8)
        users = [_username(), _username()]
        passwords = ["Of9!" + secrets.token_hex(14), "Of9!" + secrets.token_hex(14)]
        canonical = ""
        base_url = f"http://{target.host}:{target.ports['service']}"
        try:
            admin = login(base_url, admin_username, admin_password)
            for username, password in zip(users, passwords, strict=True):
                ensure_user(admin, username, password, "Openfire User")
            exchange(
                target.host,
                target.ports["xmpp"],
                (users[0], passwords[0]),
                (users[1], passwords[1]),
                "arena-xmpp-" + secrets.token_hex(16),
            )
            canonical, payload = health_plugin(nonce)
            property_name = health_property(nonce)
            upload_plugin(admin, canonical + ".jar", payload)
            page = admin.request("GET", "/plugin-admin.jsp")
            if page.status != 200 or ("Integration " + nonce).encode() not in page.body:
                raise OpenfireError("uploaded health plugin was not listed")
            _wait_for_property(admin, property_name, nonce, True)
            delete_plugin(admin, canonical)
            _wait_for_property(admin, property_name, nonce, False)
            canonical = ""
            for username in users:
                delete_user(admin, username)
            users.clear()
        except Exception as exc:
            detail = str(exc) if isinstance(exc, (OpenfireError, RuntimeError)) else type(exc).__name__
            return CheckResult(name="checker", passed=False, detail=detail[-240:])
        finally:
            try:
                cleanup = login(base_url, admin_username, admin_password)
                if canonical:
                    delete_plugin(cleanup, canonical)
                for username in users:
                    delete_user(cleanup, username)
            except Exception:
                pass
        return CheckResult(
            name="checker",
            passed=True,
            detail="two-user XMPP exchange and admin user/plugin lifecycle passed",
        )
