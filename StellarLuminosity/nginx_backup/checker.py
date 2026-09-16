"""External semantic checker for Nginx UI administration workflows."""

from __future__ import annotations

import binascii
import hashlib
import io
import json
import re
import secrets
import string
import threading
import time
from urllib.parse import urlencode
import zipfile

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._browser import HeadlessPage
from ._client import (
    fetch_backup_payload,
    json_request,
    login,
)
from ._health_identity import existing_admin_credentials, fresh_admin_credentials


_NATIVE_USERNAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{7,19}")
_PASSWORD_RE = re.compile(r"[A-Za-z0-9_-]{8,20}")
_LANGUAGES = (
    "ar",
    "de_DE",
    "en",
    "es",
    "fr_FR",
    "ja_JP",
    "ko_KR",
    "pt_PT",
    "ru_RU",
    "tr_TR",
    "uk_UA",
    "vi_VN",
    "zh_CN",
    "zh_TW",
)
_RUN_LOCKS: dict[tuple[str, int], threading.Lock] = {}
_RUN_LOCKS_GUARD = threading.Lock()
def _target_lock(target: VulboxTarget) -> threading.Lock:
    key = (target.host, target.ports["service"])
    with _RUN_LOCKS_GUARD:
        return _RUN_LOCKS.setdefault(key, threading.Lock())


def _random_identifier(min_length: int, max_length: int) -> str:
    length = min_length + secrets.randbelow(max_length - min_length + 1)
    return secrets.choice(string.ascii_lowercase) + "".join(
        secrets.choice(string.ascii_lowercase + string.digits)
        for _ in range(length - 1)
    )


def _create_admin(
    host: str,
    port: int,
    bootstrap_token: str,
    *,
    existing_username: str,
) -> tuple[int, str, str]:
    username, password = fresh_admin_credentials(existing_username)
    status, user = json_request(
        host,
        port,
        "POST",
        "/api/users",
        payload={
            "name": username,
            "password": password,
            "status": True,
            "language": "en",
        },
        headers={"Authorization": bootstrap_token},
    )
    user_id = user.get("id") if isinstance(user, dict) else None
    if (
        status != 200
        or not isinstance(user_id, int)
        or user_id <= 1
        or not _NATIVE_USERNAME_RE.fullmatch(username)
        or not _PASSWORD_RE.fullmatch(password)
    ):
        raise RuntimeError("Nginx UI temporary administrator creation failed")
    return user_id, username, password


def _frontend_routes(
    host: str,
    port: int,
    principals: tuple[tuple[str, str], ...],
) -> tuple[bool, str]:
    origin = f"http://{host}:{port}/"
    route_checks = (
        (
            "/backup/backup-and-restore",
            ("System Backup", "Create Backup", "System Restore"),
        ),
        (
            "/backup/auto-backup",
            ("Auto Backup", "Backup Type", "Schedule", "Last Backup Status"),
        ),
    )
    for principal, token in principals:
        with HeadlessPage() as page:
            page.navigate(origin)
            deadline = time.monotonic() + 10
            while page.evaluate("document.readyState") != "complete":
                if time.monotonic() >= deadline:
                    return False, principal + " root document did not load"
                time.sleep(0.05)
            page.evaluate(
                "localStorage.setItem('user', JSON.stringify({token: "
                + json.dumps(token)
                + ", shortToken: ''}))"
            )
            for route, required_text in route_checks:
                page.navigate(
                    origin
                    + "?"
                    + secrets.token_hex(6)
                    + "="
                    + secrets.token_hex(8)
                    + "#"
                    + route
                )
                deadline = time.monotonic() + 12
                while True:
                    state = page.evaluate(
                        "JSON.stringify({"
                        "route: location.hash.slice(1).split('?')[0],"
                        "text: document.body ? document.body.innerText : ''"
                        "})"
                    )
                    rendered = json.loads(state) if isinstance(state, str) else {}
                    if rendered.get("route") == route and all(
                        text in rendered.get("text", "") for text in required_text
                    ):
                        break
                    if time.monotonic() >= deadline:
                        return False, principal + " " + route + " did not render"
                    time.sleep(0.1)
    return True, "both administrators rendered manual and automatic backup pages"


def _check_admin_workflow(
    target: VulboxTarget,
    username: str,
    password: str,
    principal: str,
    *,
    private_user_id: int,
    private_username: str,
    private_language: str | None = None,
) -> list[CheckResult]:
    children: list[CheckResult] = []
    token: str | None = None
    original_language: str | None = None
    language_changed = False
    config_name = f"{_random_identifier(6, 18)}.conf"
    config_created = False
    try:
        port = target.ports["service"]
        token = login(target.host, port, username, password)
        children.append(
            CheckResult(f"{principal}_encrypted_login", bool(token), "fresh request")
        )

        user_status, user = json_request(
            target.host,
            port,
            "GET",
            "/api/user",
            headers={"Authorization": token},
        )
        original_language = user.get("language")
        if (
            user_status != 200
            or user.get("name") != username
            or not isinstance(original_language, str)
        ):
            raise RuntimeError("Nginx UI returned an invalid current user")
        probe_language = secrets.choice(
            [language for language in _LANGUAGES if language != original_language]
        )
        language_changed = True
        language_status, language_result = json_request(
            target.host,
            port,
            "POST",
            "/api/user/language",
            payload={"language": probe_language},
            headers={"Authorization": token},
        )
        if (
            language_status != 200
            or language_result.get("language") != probe_language
        ):
            raise RuntimeError("Nginx UI did not update the administrator language")
        settings_status, settings = json_request(
            target.host,
            port,
            "GET",
            "/api/settings/server/name",
            headers={"Authorization": token},
        )
        settings_ok = bool(
            settings_status == 200
            and isinstance(settings.get("name"), str)
            and settings["name"]
        )
        children.append(
            CheckResult(
                f"{principal}_protected_settings",
                settings_ok,
                f"HTTP {settings_status}",
            )
        )

        marker = secrets.token_urlsafe(12 + secrets.randbelow(13))
        source_variable = _random_identifier(5, 16)
        target_variable = _random_identifier(5, 16)
        config_content = (
            f"map $http_{source_variable} ${target_variable} {{\n"
            f'    default "{marker}";\n'
            "}\n"
        )
        create_status, created = json_request(
            target.host,
            port,
            "POST",
            "/api/configs",
            payload={
                "name": config_name,
                "base_dir": "/conf.d",
                "content": config_content,
                "overwrite": False,
                "sync_node_ids": [],
            },
            headers={"Authorization": token},
        )
        config_created = create_status == 200
        config_status, config = json_request(
            target.host,
            port,
            "GET",
            "/api/config?" + urlencode({"path": f"conf.d/{config_name}"}),
            headers={"Authorization": token},
        )
        config_ok = bool(
            create_status == 200
            and config_status == 200
            and created.get("content") == config_content
            and config.get("content") == config_content
        )
        children.append(
            CheckResult(
                f"{principal}_native_config",
                config_ok,
                f"create={create_status}, read={config_status}",
            )
        )

        private_user = (
            private_user_id,
            private_username,
            probe_language if private_language is None else private_language,
        )
        backup_payload = fetch_backup_payload(
            target.host, port, token, private_user=private_user
        )
        with zipfile.ZipFile(io.BytesIO(backup_payload.nginx)) as backup:
            backup_config_info = backup.getinfo(f"conf.d/{config_name}")
            backup_config_raw = backup.read(backup_config_info)
            backup_config = backup_config_raw.decode("utf-8")
        backup_ok = bool(
            backup_config == config_content
            and backup_config_info.file_size == len(backup_config_raw)
            and backup_config_info.CRC
            == binascii.crc32(backup_config_raw) & 0xFFFFFFFF
            and backup_payload.manifest.nginx_hash
            == hashlib.sha256(backup_payload.nginx).hexdigest()
            and backup_payload.manifest.version == "2.3.2"
        )
        children.append(
            CheckResult(
                f"{principal}_authenticated_backup",
                backup_ok,
                f"nginx-body={len(backup_payload.nginx)}, "
                f"config-body={len(backup_config_raw)}",
            )
        )
    except Exception as error:  # noqa: BLE001 - checker errors are health data
        children.append(
            CheckResult(f"{principal}_workflow", False, type(error).__name__)
        )
    finally:
        if token is not None:
            try:
                delete_status, _ = json_request(
                    target.host,
                    target.ports["service"],
                    "POST",
                    "/api/config_delete",
                    payload={
                        "base_path": "/conf.d",
                        "name": config_name,
                        "sync_node_ids": [],
                    },
                    headers={"Authorization": token},
                )
                cleanup_ok = (
                    delete_status == 200
                    if config_created
                    else delete_status in (200, 404)
                )
                children.append(
                    CheckResult(
                        f"{principal}_config_cleanup",
                        cleanup_ok,
                        f"HTTP {delete_status}",
                    )
                )
            except Exception as error:  # noqa: BLE001 - health data
                children.append(
                    CheckResult(
                        f"{principal}_config_cleanup", False, type(error).__name__
                    )
                )
        if language_changed and token is not None and original_language is not None:
            try:
                restore_status, restored = json_request(
                    target.host,
                    target.ports["service"],
                    "POST",
                    "/api/user/language",
                    payload={"language": original_language},
                    headers={"Authorization": token},
                )
                cleanup_ok = bool(
                    restore_status == 200
                    and restored.get("language") == original_language
                )
                children.append(
                    CheckResult(
                        f"{principal}_workflow_cleanup",
                        cleanup_ok,
                        f"HTTP {restore_status}",
                    )
                )
            except Exception as error:  # noqa: BLE001 - health data
                children.append(
                    CheckResult(
                        f"{principal}_workflow_cleanup", False, type(error).__name__
                    )
                )
    return children


class NginxUiChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "nginx-ui-workflow"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        with _target_lock(target):
            return self._run_locked(target)

    def _run_locked(self, target: VulboxTarget) -> CheckResult:
        children: list[CheckResult] = []
        bootstrap_token: str | None = None
        user_id: int | None = None
        try:
            port = target.ports["service"]
            existing_username, existing_password = existing_admin_credentials(target)
            bootstrap_token = login(
                target.host, port, existing_username, existing_password
            )
            user_id, username, password = _create_admin(
                target.host,
                port,
                bootstrap_token,
                existing_username=existing_username,
            )
            peer_token = login(target.host, port, username, password)
            frontend_ok, frontend_detail = _frontend_routes(
                target.host,
                port,
                (("existing", bootstrap_token), ("peer", peer_token)),
            )
            children.append(
                CheckResult(
                    "public_ui",
                    frontend_ok,
                    frontend_detail,
                )
            )
            children.extend(
                _check_admin_workflow(
                    target,
                    existing_username,
                    existing_password,
                    "existing",
                    private_user_id=user_id,
                    private_username=username,
                    private_language="en",
                )
            )
            children.extend(
                _check_admin_workflow(
                    target,
                    username,
                    password,
                    "peer",
                    private_user_id=user_id,
                    private_username=username,
                )
            )
        except Exception as error:  # noqa: BLE001 - checker errors are health data
            children.append(CheckResult("workflow", False, type(error).__name__))
        finally:
            if bootstrap_token is not None and user_id is not None:
                try:
                    delete_status, _ = json_request(
                        target.host,
                        target.ports["service"],
                        "DELETE",
                        f"/api/users/{user_id}",
                        headers={"Authorization": bootstrap_token},
                    )
                    children.append(
                        CheckResult(
                            "principal_cleanup",
                            delete_status == 204,
                            f"HTTP {delete_status}",
                        )
                    )
                except Exception as error:  # noqa: BLE001 - health data
                    children.append(
                        CheckResult("principal_cleanup", False, type(error).__name__)
                    )
        return CheckResult(
            "checker", bool(children) and all(child.passed for child in children), children=children
        )
