"""External checker for SSO, WebDAV, and the native Team-Folder boundary."""

from __future__ import annotations

import json
import secrets

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._api import NextcloudClient, resolve_host, unauthenticated_status


class CaddyNextcloudChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "caddy-nextcloud-sso-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            return CheckResult("checker", False, "no exec bridge")
        rc, out = exec_in(target.host, "/arena/facility.py checker-bundle")
        try:
            bundle = json.loads((out or "").strip()) if rc == 0 else {}
            ordinary = bundle["ordinary"]
            guarded = bundle["guarded"]
            for account in (ordinary, guarded):
                if not account.get("username") or not account.get("password"):
                    raise ValueError
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return CheckResult("checker", False, "facility bundle unavailable")

        base = f"http://{resolve_host(target.host)}:{target.ports['service']}"
        ordinary_client = NextcloudClient(
            base, ordinary["username"], ordinary["password"])
        guarded_client = NextcloudClient(
            base, guarded["username"], guarded["password"])
        suffix = secrets.token_hex(8)
        own_target = "checker-" + suffix + ".txt"
        guarded_target = "Guarded/checker-" + suffix + ".txt"
        own_value = ("own-" + secrets.token_hex(16)).encode()
        guarded_value = ("guarded-" + secrets.token_hex(16)).encode()
        children: list[CheckResult] = []
        try:
            unauth = unauthenticated_status(base)
            children.append(CheckResult(
                "unauthenticated_denial", unauth == 401, f"status={unauth}"))

            ordinary_login = ordinary_client.login()
            guarded_login = guarded_client.login()
            children.append(CheckResult(
                "sso_login", ordinary_login and guarded_login,
                f"ordinary={ordinary_login}, guarded={guarded_login}"))
            if not ordinary_login or not guarded_login:
                return CheckResult("checker", False, children=children)

            put_status, _ = ordinary_client.webdav("PUT", own_target, own_value)
            get_status, own_read = ordinary_client.webdav("GET", own_target)
            delete_status, _ = ordinary_client.webdav("DELETE", own_target)
            gone_status, _ = ordinary_client.webdav("GET", own_target)
            own_ok = (
                put_status in (201, 204) and get_status == 200
                and own_read == own_value and delete_status == 204
                and gone_status == 404
            )
            children.append(CheckResult(
                "own_webdav_crud", own_ok,
                f"PUT={put_status}, GET={get_status}, DELETE={delete_status}, gone={gone_status}"))

            guard_put, _ = guarded_client.webdav(
                "PUT", guarded_target, guarded_value)
            denied, _ = ordinary_client.webdav("GET", guarded_target)
            owner_get, owner_read = guarded_client.webdav("GET", guarded_target)
            boundary_ok = (
                guard_put in (201, 204) and denied == 404
                and owner_get == 200 and owner_read == guarded_value
            )
            children.append(CheckResult(
                "team_folder_boundary", boundary_ok,
                f"PUT={guard_put}, ordinary={denied}, guarded={owner_get}"))
        except Exception as error:  # noqa: BLE001
            children.append(CheckResult("protocol_exception", False, str(error)))
        finally:
            try:
                guarded_client.webdav("DELETE", guarded_target)
            except Exception:  # noqa: BLE001
                pass
        return CheckResult("checker", bool(children) and all(c.passed for c in children),
                           children=children)
