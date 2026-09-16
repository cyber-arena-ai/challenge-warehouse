"""External semantic checker for restricted subscriber query and export."""

from __future__ import annotations

import csv
import io
import json
import threading

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._client import (
    ANALYST_PERMISSIONS,
    ANALYST_ROLE,
    AdminClient,
    request,
    session_login,
    target_admin,
    target_base,
)
from ._codec import (
    checker_profile,
    derive,
    open_envelope,
    principal_profile,
    private_run_seed,
    round_context,
    seal,
)


_LOCKS_GUARD = threading.Lock()
_LOCKS: dict[tuple[str, int], threading.Lock] = {}
_CONTEXT_GUARD = threading.Lock()
_CONTEXT_COUNTER = 0
_PENDING_CLEANUP: dict[tuple[str, int], list[tuple[str, int]]] = {}

_ATTRIBUTE_KEYS = (
    "audience",
    "category",
    "department",
    "interest",
    "locale",
    "region",
    "segment",
    "source",
    "tier",
)
_ATTRIBUTE_VALUES = (
    "active",
    "community",
    "customer",
    "monthly",
    "product",
    "regional",
    "subscriber",
    "weekly",
)
_LIST_KINDS = ("Contacts", "Customers", "Members", "Readers", "Subscribers")
_LIST_TOPICS = ("Announcements", "Digest", "News", "Product", "Updates")


def _checker_lock(target: VulboxTarget) -> threading.Lock:
    key = (target.host, target.ports["service"])
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(key, threading.Lock())


def _target_key(target: VulboxTarget) -> tuple[str, int]:
    return target.host, target.ports["service"]


def _private_context(target: VulboxTarget) -> str:
    """Return fresh deterministic material keyed outside the defended service."""
    global _CONTEXT_COUNTER
    coordinate = target.meta.get("team_id")
    if not isinstance(coordinate, str) or not coordinate:
        coordinate = f"{target.host}:{target.ports['service']}"
    with _CONTEXT_GUARD:
        counter = _CONTEXT_COUNTER
        _CONTEXT_COUNTER += 1
    return private_run_seed(target, f"checker-run:{counter}:{coordinate}")


def _pick(seed: str, label: str, values: tuple[str, ...]) -> str:
    return values[int.from_bytes(derive(seed, label)[:4], "big") % len(values)]


def _query_forms(seed: str, key: str, value: str) -> tuple[str, str]:
    forms = (
        f"attribs->>'{key}' = '{value}'",
        f"'{value}' = attribs->>'{key}'",
        f"(attribs #>> '{{{key}}}') = '{value}'",
        f"attribs->>'{key}' IN ('{value}')",
        f"((attribs->>'{key}') = ('{value}'))",
        f"attribs->>'{key}' LIKE '{value}' AND attribs->>'{key}' IS NOT NULL",
        f"NOT (attribs->>'{key}' <> '{value}')",
        f"COALESCE(attribs->>'{key}', '') = '{value}'",
    )
    first = int.from_bytes(derive(seed, "checker:query-form")[:2], "big") % len(forms)
    offset = (
        int.from_bytes(derive(seed, "checker:export-form")[:2], "big")
        % (len(forms) - 1)
    ) + 1
    return forms[first], forms[(first + offset) % len(forms)]


class ListmonkChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "listmonk-semantic-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    @staticmethod
    def _rows(admin: AdminClient, path: str) -> list[dict]:
        value = admin.call(path)
        if isinstance(value, dict):
            value = value.get("results")
        if not isinstance(value, list) or not all(
            isinstance(row, dict) for row in value
        ):
            raise RuntimeError(f"{path} listing was malformed")
        return value

    @staticmethod
    def _cleanup_exact(
        admin: AdminClient, resources: list[tuple[str, int]]
    ) -> tuple[list[tuple[str, int]], list[str]]:
        remaining: list[tuple[str, int]] = []
        errors: list[str] = []
        for path, resource_id in reversed(resources):
            try:
                admin.call(f"{path}/{resource_id}", method="DELETE")
            except RuntimeError as error:
                if "returned HTTP 404" in str(error):
                    continue
                remaining.append((path, resource_id))
                errors.append(f"{path}/{resource_id}: {type(error).__name__}")
            except Exception as error:  # noqa: BLE001 — cleanup remains decisive
                remaining.append((path, resource_id))
                errors.append(f"{path}/{resource_id}: {type(error).__name__}")
        remaining.reverse()
        return remaining, errors

    @classmethod
    def _analyst_role_id(cls, admin: AdminClient) -> int:
        matches = [
            row
            for row in cls._rows(admin, "/api/roles/users")
            if row.get("name") == ANALYST_ROLE
        ]
        if len(matches) != 1:
            raise RuntimeError("shared analyst role is unavailable")
        role = matches[0]
        permissions = role.get("permissions")
        if (
            role.get("type") != "user"
            or not isinstance(permissions, list)
            or sorted(permissions) != sorted(ANALYST_PERMISSIONS)
            or role.get("lists") not in ([], None)
        ):
            raise RuntimeError("shared analyst role no longer has baseline authority")
        role_id = role.get("id")
        if not isinstance(role_id, int) or isinstance(role_id, bool):
            raise RuntimeError("shared analyst role is malformed")
        return role_id

    def run(self, target: VulboxTarget) -> CheckResult:
        with _checker_lock(target):
            return self._run_locked(target)

    def _run_locked(self, target: VulboxTarget) -> CheckResult:
        admin: AdminClient | None = None
        children: list[CheckResult] = []
        key = _target_key(target)
        created = list(_PENDING_CLEANUP.get(key, []))
        try:
            admin = target_admin(target)
            _PENDING_CLEANUP.pop(key, None)
            created, errors = self._cleanup_exact(admin, created)
            children.append(
                CheckResult(
                    "bounded_recovery",
                    not errors,
                    "removed prior exact resources"
                    if not errors
                    else ", ".join(errors),
                )
            )
            if errors:
                raise RuntimeError("prior checker cleanup did not converge")

            context = _private_context(target)
            profile = checker_profile(target)
            username = profile["username"]
            password = profile["password"]
            self._analyst_role_id(admin)
            users = [
                row
                for row in self._rows(admin, "/api/users")
                if row.get("username") == username
            ]
            if len(users) != 1:
                raise RuntimeError("setup-time analyst account is unavailable")
            list_kind = _pick(context, "checker:list-kind", _LIST_KINDS)
            list_topic = _pick(context, "checker:list-topic", _LIST_TOPICS)
            list_suffix = derive(context, "checker:list-suffix")[:3].hex()
            mailing_list = admin.call(
                "/api/lists",
                method="POST",
                payload={
                    "name": f"{list_topic} {list_kind} {list_suffix}",
                    "type": "private",
                    "optin": "single",
                    "description": f"{list_kind} receiving {list_topic.lower()}",
                },
            )
            list_id = int(mailing_list["id"])
            created.append(("/api/lists", list_id))
            attribute_key = _pick(context, "checker:attribute-key", _ATTRIBUTE_KEYS)
            attribute_value = (
                _pick(context, "checker:attribute-value", _ATTRIBUTE_VALUES)
                + "-"
                + derive(context, "checker:attribute-suffix")[:2].hex()
            )
            excluded_value = (
                _pick(context, "checker:excluded-value", _ATTRIBUTE_VALUES)
                + "-"
                + derive(context, "checker:excluded-suffix")[:2].hex()
            )
            if excluded_value == attribute_value:
                excluded_value += "-other"
            profiles = [
                principal_profile(derive(context, f"checker:subscriber:{index}").hex())
                for index in range(3)
            ]
            emails = [profile["email"] for profile in profiles[:2]]
            excluded_email = profiles[2]["email"]
            for index, subscriber in enumerate(profiles):
                created_subscriber = admin.call(
                    "/api/subscribers",
                    method="POST",
                    payload={
                        "email": subscriber["email"],
                        "name": subscriber["name"],
                        "attribs": {
                            attribute_key: (
                                attribute_value if index < 2 else excluded_value
                            ),
                            "signup_channel": _pick(
                                context,
                                f"checker:subscriber-source:{index}",
                                ("event", "import", "signup", "website"),
                            ),
                        },
                        "status": "enabled",
                        "lists": [list_id],
                        "preconfirm_subscriptions": True,
                    },
                )
                created.append(("/api/subscribers", int(created_subscriber["id"])))

            integration = round_context(
                derive(context, "checker:api-integration").hex()
            )
            role = admin.call(
                "/api/roles/users",
                method="POST",
                payload={
                    "name": integration["role_name"],
                    "type": "user",
                    "permissions": ["templates:get"],
                    "lists": [],
                },
            )
            integration_role_id = int(role["id"])
            created.append(("/api/roles", integration_role_id))
            api_user = admin.call(
                "/api/users",
                method="POST",
                payload={
                    "username": integration["username"],
                    "name": integration["user_name"],
                    "type": "api",
                    "status": "enabled",
                    "password_login": False,
                    "user_role_id": integration_role_id,
                    "list_role_id": None,
                    "email": "",
                },
            )
            api_user_id = int(api_user["id"])
            api_token = str(api_user.get("password", ""))
            if len(api_token) < 24:
                raise RuntimeError("Listmonk did not issue an integration token")
            created.append(("/api/users", api_user_id))
            template_value = (
                f"{integration['user_name']} delivery preview "
                f"{derive(context, 'checker:template-value')[:5].hex()}"
            )
            template_body = seal(
                api_token,
                template_value,
                integration["nonce"],
            )
            template = admin.call(
                "/api/templates",
                method="POST",
                payload={
                    "name": integration["template_name"],
                    "type": "tx",
                    "subject": integration["template_subject"],
                    "body": template_body,
                },
            )
            template_id = int(template["id"])
            created.append(("/api/templates", template_id))

            opener = session_login(target_base(target), username, password)
            denied = [
                request(target_base(target), path, opener=opener)[0]
                for path in ("/api/users", "/api/templates")
            ]
            children.append(
                CheckResult(
                    "guarded_boundary",
                    denied == [403, 403],
                    f"users/templates HTTP {denied}",
                )
            )

            status, raw = request(
                target_base(target),
                f"/api/templates/{template_id}",
                username=integration["username"],
                token=api_token,
            )
            try:
                document = json.loads(raw)
            except json.JSONDecodeError:
                document = None
            value = document.get("data") if isinstance(document, dict) else None
            template_ok = (
                status == 200
                and isinstance(value, dict)
                and value.get("id") == template_id
                and value.get("name") == integration["template_name"]
                and value.get("subject") == integration["template_subject"]
                and value.get("body") == template_body
                and open_envelope(api_token, value.get("body", ""))
                == template_value
            )
            children.append(
                CheckResult(
                    "api_template_read",
                    template_ok,
                    f"HTTP {status}",
                )
            )
            query_expression, export_expression = _query_forms(
                context, attribute_key, attribute_value
            )
            status, raw = request(
                target_base(target),
                "/api/subscribers",
                params={
                    "list_id": str(list_id),
                    "per_page": "100",
                    "query": query_expression,
                },
                opener=opener,
            )
            document = json.loads(raw)
            results = document.get("data", {}).get("results", [])
            found = {
                str(row.get("email")) for row in results if isinstance(row, dict)
            }
            query_ok = (
                status == 200
                and found == set(emails)
                and excluded_email not in found
            )
            children.append(CheckResult("query", query_ok, f"HTTP {status}, rows={len(found)}"))

            status, raw = request(
                target_base(target),
                "/api/subscribers/export",
                params={"list_id": str(list_id), "query": export_expression},
                opener=opener,
            )
            rows = list(csv.reader(io.StringIO(raw.decode(errors="replace"))))
            exported: set[str] = set()
            if rows:
                header = [column.lstrip("\ufeff").lower() for column in rows[0]]
                if "email" in header:
                    email_column = header.index("email")
                    exported = {
                        row[email_column]
                        for row in rows[1:]
                        if len(row) > email_column
                    }
            export_ok = (
                status == 200
                and exported == set(emails)
                and excluded_email not in exported
            )
            children.append(
                CheckResult(
                    "csv_export",
                    export_ok,
                    f"HTTP {status}, rows={len(exported)}",
                )
            )
        except Exception as error:  # noqa: BLE001 — checker failures are data
            children.append(
                CheckResult("workflow", False, f"{type(error).__name__}: {error}")
            )
        finally:
            if admin is not None:
                created, errors = self._cleanup_exact(admin, created)
                if created:
                    _PENDING_CLEANUP[key] = created
                children.append(
                    CheckResult(
                        "bounded_cleanup",
                        not errors,
                        "removed exact workflow resources"
                        if not errors
                        else ", ".join(errors),
                    )
                )
        return CheckResult(
            "checker",
            bool(children) and all(child.passed for child in children),
            children=children,
        )
