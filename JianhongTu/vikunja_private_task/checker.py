"""External checker for the normal shared-project REST and CalDAV workflow."""

from __future__ import annotations

import secrets
import string
import threading

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._client import VikunjaApi
from ._profiles import (
    BASELINE_PROJECT_DESCRIPTION,
    BASELINE_PROJECT_TITLE,
    is_baseline_project_identifier,
    read_profile,
)
from .checker_identity import (
    NATIVE_ACCOUNT_PATH,
    checker_writer_identities,
    issued_principals,
    open_native_account,
)


PROTECTED_PREFIX = "FLAG{"


def _related_tasks(task: dict | None) -> dict[int, dict]:
    related = (task or {}).get("related_tasks") or {}
    return {
        item["id"]: item for items in related.values() for item in (items or [])
        if isinstance(item, dict) and isinstance(item.get("id"), int)
    }


class VikunjaChecker(FunctionalityTest):
    def __init__(self) -> None:
        self._lock = threading.Lock()

    @property
    def name(self) -> str:
        return "vikunja-private-task-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    @staticmethod
    def _credentials(target: VulboxTarget) -> tuple[str, str, str]:
        return secrets.choice(checker_writer_identities(target))

    @staticmethod
    def _login_or_register(
        api: VikunjaApi, identity: tuple[str, str, str],
    ) -> tuple[str | None, bool, str]:
        username, email, password = identity
        status, token, login_detail = api.login_result(username, password)
        if token:
            return token, False, "login=" + login_detail
        register_status, register_detail = api.register_result(
            username, email, password)
        if register_status != 200:
            return (
                None,
                False,
                f"login={login_detail}; register={register_detail}",
            )
        final_status, token, final_detail = api.login_result(username, password)
        return (
            token,
            True,
            f"login={login_detail}; register={register_detail}; "
            f"retry={final_detail}; retry_status={final_status}",
        )

    @staticmethod
    def _native_session(
        api: VikunjaApi, target: VulboxTarget,
    ) -> tuple[str, str]:
        """Log in fresh as the very account objective placement records under."""
        rc, out = target.meta["exec_in_container"](
            target.host, f"cat {NATIVE_ACCOUNT_PATH}")
        sealed = ((out or "").strip().splitlines() or [""])[-1]
        if rc != 0 or not sealed:
            raise RuntimeError("native account state is unavailable")
        username, password = open_native_account(target, sealed)
        status, token, detail = api.login_result(username, password)
        if not token:
            raise RuntimeError(f"native account login -> {status} ({detail})")
        return username, token

    @staticmethod
    def _issued_sessions(
        api: VikunjaApi, target: VulboxTarget,
    ) -> tuple[tuple[str, str, str], ...]:
        sessions: list[tuple[str, str, str]] = []
        cohort = issued_principals(target)
        for index, (username, password) in enumerate(cohort, start=1):
            status, token, _detail = api.login_result(username, password)
            if not token:
                raise RuntimeError(
                    f"issued principal {index}/{len(cohort)} login -> {status}")
            sessions.append((username, password, token))
        return tuple(sessions)

    @staticmethod
    def _cleanup_native(
        api: VikunjaApi, native: tuple[str, str], owner_token: str,
        baseline_project_id: int, pending_tasks: set[int],
    ) -> str:
        """Remove native-account probe records with that same account.

        Granted projects an interrupted probe left behind are reclaimed too:
        objective placement never grants a checker account anything outside the
        baseline project, so every other native project visible here is ours.
        """
        native_username, native_token = native
        stale = sorted(
            int(project["id"]) for project in api.all_projects(owner_token)
            if (
                isinstance(project.get("owner"), dict)
                and project["owner"].get("username") == native_username
                and isinstance(project.get("id"), int)
                and int(project["id"]) not in (0, baseline_project_id)
            )
        )
        for project_id in stale:
            status = api.delete_project(native_token, project_id)
            if status not in (200, 204, 404):
                raise RuntimeError(f"checker native project cleanup -> {status}")
        for task_id in sorted(pending_tasks):
            status = api.delete_task(native_token, task_id)
            if status not in (200, 204, 404):
                raise RuntimeError(f"checker native task cleanup -> {status}")
        return (f"removed_projects={len(stale)}, "
                f"removed_tasks={len(pending_tasks)}")

    def _cleanup(
        self, api: VikunjaApi, token: str, owner_username: str,
        baseline_project_id: int | None, pending_projects: set[int],
        pending_tasks: set[int],
    ) -> tuple[int, int]:
        default_project_id = api.default_project_id(token)
        task_ids = set(pending_tasks)
        if baseline_project_id is not None:
            # Scoped to the probe's own content shape: an unscoped list of the
            # shared project expands every relation, objective ones included.
            task_ids.update(
                int(task["id"])
                for task in api.find_tasks(
                    token, baseline_project_id, PROTECTED_PREFIX)
                if (
                    isinstance(task.get("created_by"), dict)
                    and task["created_by"].get("username") == owner_username
                    and isinstance(task.get("id"), int)
                    and int(task["id"]) > 0
                )
            )
        for task_id in sorted(task_ids):
            status = api.delete_task(token, task_id)
            if status not in (200, 204, 404):
                raise RuntimeError(f"checker task cleanup -> {status}")
            pending_tasks.discard(task_id)

        projects = api.all_projects(token)
        project_ids = set(pending_projects)
        project_ids.update(
            int(project["id"])
            for project in projects
            if (
                isinstance(project.get("owner"), dict)
                and project["owner"].get("username") == owner_username
                and isinstance(project.get("id"), int)
                and int(project["id"]) > 0
                and int(project["id"]) != default_project_id
            )
        )
        for project_id in sorted(project_ids):
            status = api.delete_project(token, project_id)
            if status not in (200, 204, 404):
                raise RuntimeError(f"checker project cleanup -> {status}")
            pending_projects.discard(project_id)
        return len(project_ids), len(task_ids)

    @staticmethod
    def _caldav_record(api: VikunjaApi, username: str, password: str,
                       project_id: int, title: str,
                       content: str) -> tuple[int, bool]:
        propfind, hrefs = api.caldav_hrefs(username, password, project_id)
        for href in hrefs:
            status, raw = api.caldav_get(username, password, href)
            if (
                status == 200
                and title.encode() in raw
                and content.encode() in raw
            ):
                return propfind, True
        return propfind, False

    @staticmethod
    def _baseline_project(api: VikunjaApi, token: str) -> dict:
        candidates = [
            project for project in api.all_projects(token)
            if (
                project.get("title") == BASELINE_PROJECT_TITLE
                and project.get("description") == BASELINE_PROJECT_DESCRIPTION
                and is_baseline_project_identifier(project.get("identifier"))
            )
        ]
        if len(candidates) != 1:
            raise RuntimeError("checker baseline project is unavailable or ambiguous")
        project_id = candidates[0].get("id")
        if not isinstance(project_id, int) or project_id <= 0:
            raise RuntimeError("checker baseline project identity is invalid")
        return candidates[0]

    def run(self, target: VulboxTarget) -> CheckResult:
        with self._lock:
            return self._run(target)

    def _run(self, target: VulboxTarget) -> CheckResult:
        api = VikunjaApi(f"http://{target.host}:{target.ports['service']}")
        suffix = secrets.token_hex(16)
        profile = read_profile(suffix)
        protected_contents = [PROTECTED_PREFIX + "".join(
            secrets.choice(string.ascii_uppercase + string.digits)
            for _ in range(32)
        ) + "}" for _ in range(3)]
        peer_content, private_content, native_content = protected_contents
        owner, owner_email, owner_password = self._credentials(target)
        pending_projects: set[int] = set()
        pending_tasks: set[int] = set()
        native_tasks: set[int] = set()
        children: list[CheckResult] = []
        owner_token: str | None = None
        native: tuple[str, str] | None = None
        baseline_project_id: int | None = None
        try:
            registration_ok, registration_detail = api.registration_available()
            owner_token, owner_created, owner_detail = self._login_or_register(
                api, (owner, owner_email, owner_password))
            issued_sessions = self._issued_sessions(api, target)
            ok = registration_ok and bool(owner_token and issued_sessions)
            children.append(CheckResult(
                "accounts",
                ok,
                f"registration={registration_detail}; "
                f"created={int(owner_created)}; owner[{owner_detail}]; "
                f"issued={len(issued_sessions)} fresh logins",
            ))
            if not ok:
                return CheckResult("checker", False, children=children)

            native = self._native_session(api, target)
            native_token = native[1]
            shared = self._baseline_project(api, owner_token)
            baseline_project_id = int(shared["id"])
            removed_projects, removed_tasks = self._cleanup(
                api, owner_token, owner, baseline_project_id,
                pending_projects, pending_tasks)
            recovered_native = self._cleanup_native(
                api, native, owner_token, baseline_project_id, set())
            children.append(CheckResult(
                "bounded_recovery", True,
                f"removed_projects={removed_projects}, "
                f"removed_tasks={removed_tasks}, native[{recovered_native}]"))

            private = api.create_project(
                owner_token,
                profile.private_project_title,
                description=profile.private_project_description,
                identifier=profile.private_project_identifier,
            )
            pending_projects.add(int(private["id"]))
            native_project = api.create_project(
                native_token,
                profile.shared_project_title,
                description=profile.shared_project_description,
                identifier=profile.shared_project_identifier,
            )
            share_status = api.share_project(
                native_token, int(native_project["id"]), owner)
            shared_task = api.create_task(native_token, int(shared["id"]),
                                          profile.shared_task_title,
                                          profile.shared_task_description)
            native_tasks.add(int(shared_task["id"]))
            peer = api.create_task(native_token, int(shared["id"]),
                                   profile.peer_task_title,
                                   peer_content)
            native_tasks.add(int(peer["id"]))
            native_task = api.create_task(native_token,
                                          int(native_project["id"]),
                                          profile.private_task_title,
                                          native_content)
            native_tasks.add(int(native_task["id"]))
            private_task = api.create_task(owner_token, int(private["id"]),
                                           profile.private_task_title,
                                           private_content)
            carrier_id = int(shared_task["id"])
            relation_statuses = [
                api.relate(native_token, carrier_id, int(peer["id"])),
                api.relate(owner_token, carrier_id, int(private_task["id"])),
                api.relate(native_token, carrier_id, int(native_task["id"])),
            ]
            children.append(CheckResult(
                "facility_authority",
                all(s in (200, 201) for s in relation_statuses)
                and share_status in (200, 201),
                f"relations={relation_statuses}, native_share={share_status}",
            ))

            owner_status, owner_task, _ = api.get_task(
                owner_token, int(shared_task["id"]))
            owner_related = _related_tasks(owner_task)
            expected_owner = {
                int(peer["id"]), int(private_task["id"]), int(native_task["id"]),
            }
            relations_present = expected_owner <= owner_related.keys()
            protected_shape_preserved = (
                owner_related.get(int(private_task["id"]), {}).get("description")
                == private_content
                and owner_related.get(int(native_task["id"]), {}).get("description")
                == native_content
            )
            children.append(CheckResult(
                "owner_relations",
                owner_status == 200
                and relations_present
                and protected_shape_preserved,
                f"task={owner_status}, "
                f"relations={relations_present}, "
                f"content={protected_shape_preserved}",
            ))

            shared_reads: list[bool] = []
            boundary_reads: list[bool] = []
            shared_caldav_reads: list[bool] = []
            for issued_username, issued_password, issued_token in issued_sessions:
                shared_status, task, _ = api.get_task(
                    issued_token, int(shared_task["id"]))
                reader_related = _related_tasks(task)
                peer_preserved = (
                    reader_related.get(int(peer["id"]), {}).get("description")
                    == peer_content
                )
                shared_reads.append(shared_status == 200 and peer_preserved)
                denied_status, _, _ = api.get_task(
                    issued_token, int(private_task["id"]))
                create_status, _ = api.request(
                    "PUT", f"/api/v1/projects/{shared['id']}/tasks",
                    token=issued_token, body={"title": "New shared task " + suffix})
                boundary_reads.append(
                    denied_status in (403, 404) and create_status == 403)
                propfind, found = self._caldav_record(
                    api, issued_username, issued_password, int(shared["id"]),
                    profile.peer_task_title, peer_content)
                shared_caldav_reads.append(propfind == 207 and found)
            children.append(CheckResult(
                "shared_read",
                all(shared_reads),
                f"issued={sum(shared_reads)}/{len(shared_reads)} REST relation reads",
            ))

            native_listed = any(
                item.get("id") == int(native_task["id"])
                for item in api.find_tasks(
                    owner_token, int(native_project["id"]),
                    profile.private_task_title)
            )
            native_status, native_read, _ = api.get_task(
                owner_token, int(native_task["id"]))
            native_preserved = (
                (native_read or {}).get("description") == native_content
            )
            children.append(CheckResult(
                "native_read",
                native_listed and native_status == 200 and native_preserved,
                f"listed={native_listed}, task={native_status}, "
                f"content={native_preserved}",
            ))

            children.append(CheckResult(
                "boundaries", all(boundary_reads),
                f"issued={sum(boundary_reads)}/{len(boundary_reads)} read-only boundaries",
            ))

            children.append(CheckResult(
                "shared_caldav", all(shared_caldav_reads),
                f"issued={sum(shared_caldav_reads)}/{len(shared_caldav_reads)} CalDAV reads",
            ))
            for name, username, password, project_id, title, content in (
                ("private_caldav", owner, owner_password, int(private["id"]),
                 profile.private_task_title, private_content),
                ("native_caldav", owner, owner_password,
                 int(native_project["id"]), profile.private_task_title,
                 native_content),
            ):
                propfind, found = self._caldav_record(
                    api, username, password, project_id, title, content)
                children.append(CheckResult(
                    name, propfind == 207 and found,
                    f"PROPFIND={propfind}, task_get={found}",
                ))
        except Exception as error:  # noqa: BLE001
            children.append(CheckResult("exception", False, str(error)))
        finally:
            if native is not None and baseline_project_id is not None:
                try:
                    children.append(CheckResult(
                        "native_cleanup", True, self._cleanup_native(
                            api, native, owner_token, baseline_project_id,
                            native_tasks)))
                except Exception as error:  # noqa: BLE001
                    children.append(CheckResult(
                        "native_cleanup", False, str(error)))
            if owner_token:
                try:
                    removed = self._cleanup(
                        api, owner_token, owner, baseline_project_id,
                        pending_projects, pending_tasks)
                    children.append(CheckResult(
                        "bounded_cleanup", True,
                        f"removed_projects={removed[0]}, "
                        f"removed_tasks={removed[1]}"))
                except Exception as error:  # noqa: BLE001
                    children.append(CheckResult(
                        "bounded_cleanup", False, str(error)))
        return CheckResult("checker", all(child.passed for child in children),
                           children=children)
