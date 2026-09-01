"""External randomized checker for Openfire's legitimate workflows."""

from __future__ import annotations

import secrets

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
from ._plugin import health_plugin
from ._xmpp import exchange


class OpenfireChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "openfire-setup-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("admin", "xmpp")

    def run(self, target: VulboxTarget) -> CheckResult:
        try:
            admin_username, admin_password = checker_admin_credentials(target)
        except RuntimeError:
            return CheckResult(
                name="checker", passed=False, detail="facility identity unavailable"
            )

        nonce = secrets.token_hex(8)
        users = [f"health-{nonce}-a", f"health-{nonce}-b"]
        passwords = ["Of9!" + secrets.token_hex(14), "Of9!" + secrets.token_hex(14)]
        canonical = ""
        base_url = f"http://{target.host}:{target.ports['admin']}"
        try:
            admin = login(base_url, admin_username, admin_password)
            for username, password in zip(users, passwords, strict=True):
                ensure_user(admin, username, password, "Arena Health User")
            exchange(
                target.host,
                target.ports["xmpp"],
                (users[0], passwords[0]),
                (users[1], passwords[1]),
                "arena-xmpp-" + secrets.token_hex(16),
            )
            canonical, payload = health_plugin(nonce)
            upload_plugin(admin, canonical + ".jar", payload)
            page = admin.request("GET", "/plugin-admin.jsp")
            if page.status != 200 or ("Arena Health " + nonce).encode() not in page.body:
                raise OpenfireError("uploaded health plugin was not listed")
            delete_plugin(admin, canonical)
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
