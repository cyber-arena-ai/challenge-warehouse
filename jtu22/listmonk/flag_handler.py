"""Application-native principals and rotating credential objective placement."""

from __future__ import annotations

import base64
from collections.abc import Mapping
import json
import shlex
from typing import Any

from challenges.interface import (
    BaselinePrincipal,
    Flag,
    FlagHandler,
    FlagObservation,
    ObservationStatus,
    VulboxTarget,
)

from ._client import (
    ANALYST_PERMISSIONS,
    ANALYST_ROLE,
    create_analyst_user,
    ensure_role,
    request,
    target_admin,
    target_base,
)
from ._codec import (
    checker_profile,
    open_envelope,
    pack_handle,
    principal_profile,
    public_locator,
    derive,
    round_context,
    seal,
    unpack_handle,
)

STORE = "api-token"
JOURNAL_PATH = "/srv/listmonk/private/objective-journal.json"
ISSUED_PATH = "/srv/listmonk/private/objective-issued"
ISSUED_VALUE = "listmonk-objective-v1"


def _empty_journal() -> dict[str, Any]:
    return {"v": 1, "current": None, "previous": None, "pending": None}


def _generation_names(
    generation: object,
) -> tuple[str | None, str | None, str | None]:
    if not isinstance(generation, dict):
        return None, None, None
    username = generation.get("username")
    template_name = generation.get("template_name")
    role_name = generation.get("role_name")
    return (
        username if isinstance(username, str) else None,
        template_name if isinstance(template_name, str) else None,
        role_name if isinstance(role_name, str) else None,
    )


class ListmonkFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "listmonk-credential-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    @staticmethod
    def _exec(target: VulboxTarget, command: str) -> str:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            raise RuntimeError("no facility exec bridge")
        rc, output = exec_in(target.host, command)
        if rc != 0:
            raise RuntimeError("objective journal operation failed")
        return output or ""

    def _load_journal(self, target: VulboxTarget) -> dict[str, Any]:
        marker = self._exec(
            target,
            f"if [ ! -e {shlex.quote(ISSUED_PATH)} ]; then printf missing; "
            f"elif [ -f {shlex.quote(ISSUED_PATH)} ]; then printf 'file\\n'; "
            f"cat {shlex.quote(ISSUED_PATH)}; else printf invalid; fi",
        )
        if marker == "missing":
            issued = False
        elif marker == f"file\n{ISSUED_VALUE}\n":
            issued = True
        else:
            raise RuntimeError("objective issuance marker is malformed")

        state = self._exec(
            target,
            f"if [ ! -e {shlex.quote(JOURNAL_PATH)} ]; then printf missing; "
            f"elif [ -f {shlex.quote(JOURNAL_PATH)} ]; then printf 'file\\n'; "
            f"cat {shlex.quote(JOURNAL_PATH)}; else printf invalid; fi",
        )
        if state == "missing":
            if issued:
                raise RuntimeError("objective journal is missing after issuance")
            return _empty_journal()
        if not state.startswith("file\n"):
            raise RuntimeError("objective journal is malformed")
        raw = state.removeprefix("file\n")
        if not raw:
            raise RuntimeError("objective journal is malformed")
        try:
            journal = json.loads(raw)
        except json.JSONDecodeError as error:
            raise RuntimeError("objective journal is malformed") from error
        if (
            not isinstance(journal, dict)
            or journal.get("v") != 1
            or any(
                journal.get(name) is not None
                and not isinstance(journal.get(name), dict)
                for name in ("current", "previous", "pending")
            )
            or all(
                journal.get(name) is None
                for name in ("current", "previous", "pending")
            )
        ):
            raise RuntimeError("objective journal is malformed")
        return journal

    def _mark_issued(self, target: VulboxTarget) -> None:
        path = shlex.quote(ISSUED_PATH)
        temporary = shlex.quote(ISSUED_PATH + ".next")
        self._exec(
            target,
            "set -eu; umask 077; "
            f"printf '%s\\n' {shlex.quote(ISSUED_VALUE)} > {temporary}; "
            f"chmod 0600 {temporary}; mv -f {temporary} {path}",
        )

    def _write_journal(
        self, target: VulboxTarget, journal: Mapping[str, Any]
    ) -> None:
        raw = json.dumps(journal, separators=(",", ":"), sort_keys=True).encode()
        encoded = base64.b64encode(raw).decode()
        directory = shlex.quote(JOURNAL_PATH.rsplit("/", 1)[0])
        path = shlex.quote(JOURNAL_PATH)
        temporary = shlex.quote(JOURNAL_PATH + ".next")
        self._exec(
            target,
            "set -eu; "
            f"install -d -m 0700 {directory}; umask 077; "
            f"printf %s {shlex.quote(encoded)} | base64 -d > {temporary}; "
            f"mv -f {temporary} {path}",
        )

    @staticmethod
    def _rows(admin: Any, path: str) -> list[dict[str, Any]]:
        rows = admin.call(path)
        if not isinstance(rows, list) or not all(
            isinstance(row, dict) for row in rows
        ):
            raise RuntimeError(f"Listmonk {path} listing was malformed")
        return rows

    def _delete_generation(self, admin: Any, generation: object) -> None:
        username, template_name, role_name = _generation_names(generation)
        if template_name:
            for row in self._rows(admin, "/api/templates"):
                if row.get("name") == template_name:
                    admin.call(f"/api/templates/{int(row['id'])}", method="DELETE")
        if username:
            for row in self._rows(admin, "/api/users"):
                if row.get("username") == username:
                    admin.call(f"/api/users/{int(row['id'])}", method="DELETE")
        if role_name:
            for row in self._rows(admin, "/api/roles/users"):
                if row.get("name") == role_name:
                    admin.call(
                        f"/api/roles/{int(row['id'])}", method="DELETE"
                    )

    def provision_principals(
        self, target: VulboxTarget, seeds: Mapping[str, str]
    ) -> Mapping[str, BaselinePrincipal]:
        admin = target_admin(target)
        role_id = ensure_role(admin, ANALYST_ROLE, ANALYST_PERMISSIONS)
        existing = admin.call("/api/users")
        if not isinstance(existing, list):
            raise RuntimeError("Listmonk user listing was malformed")
        by_username = {
            str(row.get("username")): int(row["id"])
            for row in existing
            if isinstance(row, dict) and "id" in row
        }
        profiles = {
            attacker: principal_profile(seed)
            for attacker, seed in sorted(seeds.items())
        }
        checker = checker_profile(target)
        all_profiles = [(attacker, profile) for attacker, profile in profiles.items()]
        all_profiles.append((None, checker))
        usernames = [profile["username"] for _, profile in all_profiles]
        if len(set(usernames)) != len(usernames):
            raise RuntimeError("analyst identity derivation collided")
        desired_users = set(usernames)
        for row in existing:
            if not isinstance(row, dict):
                continue
            user_role = row.get("user_role")
            if (
                row.get("type") == "user"
                and isinstance(user_role, dict)
                and user_role.get("id") == role_id
                and row.get("username") not in desired_users
            ):
                admin.call(f"/api/users/{int(row['id'])}", method="DELETE")
        principals: dict[str, BaselinePrincipal] = {}
        for attacker, profile in sorted(
            all_profiles, key=lambda item: item[1]["username"]
        ):
            username = profile["username"]
            if username in by_username:
                admin.call(f"/api/users/{by_username[username]}", method="DELETE")
            create_analyst_user(admin, role_id, profile)
            if attacker is not None:
                principals[attacker] = BaselinePrincipal(
                    principal_id=username,
                    credentials={
                        "username": username,
                        "password": profile["password"],
                    },
                )
        return principals

    def plant(
        self, target: VulboxTarget, flags: Mapping[str, Flag]
    ) -> Mapping[str, str]:
        if set(flags) != {STORE}:
            raise ValueError(f"expected store {STORE!r}, got {sorted(flags)}")
        seed = target.meta.get("round_context_seed")
        if not isinstance(seed, str):
            raise ValueError("round_context_seed is required")
        identity = round_context(seed)
        username = identity["username"]
        template_name = identity["template_name"]
        role_name = identity["role_name"]
        nonce = identity["nonce"]
        context = derive(seed, "api-token:generation").hex()
        proof = flags[STORE].value
        journal = self._load_journal(target)
        admin = target_admin(target)

        if journal.get("previous") is not None:
            self._delete_generation(admin, journal["previous"])
            journal["previous"] = None
            self._write_journal(target, journal)

        pending = journal.get("pending")
        if isinstance(pending, dict) and (
            pending.get("context") != context or pending.get("proof") != proof
        ):
            self._delete_generation(admin, pending)
            journal["pending"] = None
            self._write_journal(target, journal)

        current = journal.get("current")
        if isinstance(current, dict) and current.get("context") == context:
            if (
                current.get("proof") != proof
                or not isinstance(current.get("handle"), str)
                or any(
                    current.get(name) != identity[name]
                    for name in (
                        "username",
                        "template_name",
                        "role_name",
                        "user_name",
                        "template_subject",
                    )
                )
            ):
                raise RuntimeError("round context was reused with different proof state")
            ensure_role(admin, role_name, ["templates:get"])
            observed = self.retrieve(target, current["handle"], proof)
            if observed.status is ObservationStatus.PRESENT:
                self._mark_issued(target)
                return {STORE: current["handle"]}
            if observed.status is ObservationStatus.ERROR:
                raise RuntimeError("current target audit failed")
            self._delete_generation(admin, current)
            journal["current"] = None
            self._write_journal(target, journal)
            current = None

        pending = journal.get("pending")
        if not isinstance(pending, dict):
            pending = {
                "context": context,
                "username": username,
                "template_name": template_name,
                "role_name": role_name,
                "user_name": identity["user_name"],
                "template_subject": identity["template_subject"],
                "proof": proof,
                "user_id": None,
                "token": None,
                "role_id": None,
                "template_id": None,
                "handle": None,
            }
            journal["pending"] = pending
            self._write_journal(target, journal)

        if any(
            pending.get(name) != identity[name]
            for name in (
                "username",
                "template_name",
                "role_name",
                "user_name",
                "template_subject",
            )
        ):
            raise RuntimeError("pending target identity does not match round context")

        target_role = ensure_role(admin, role_name, ["templates:get"])
        pending["role_id"] = target_role
        self._write_journal(target, journal)

        token = pending.get("token")
        user_id = pending.get("user_id")
        if not isinstance(token, str) or len(token) < 24:
            existing_users = [
                row
                for row in self._rows(admin, "/api/users")
                if row.get("username") == username
            ]
            for row in existing_users:
                admin.call(f"/api/users/{int(row['id'])}", method="DELETE")
            user = admin.call(
                "/api/users",
                method="POST",
                payload={
                    "username": username,
                    "name": pending["user_name"],
                    "type": "api",
                    "status": "enabled",
                    "password_login": False,
                    "user_role_id": target_role,
                    "list_role_id": None,
                    "email": "",
                },
            )
            token = str(user.get("password", "")) if isinstance(user, dict) else ""
            if len(token) < 24:
                raise RuntimeError("Listmonk did not generate a target API credential")
            user_id = int(user["id"])
            pending.update({"user_id": user_id, "token": token})
            self._write_journal(target, journal)
        elif not isinstance(user_id, int) or isinstance(user_id, bool):
            raise RuntimeError("pending target identity is malformed")

        template_payload = {
            "name": template_name,
            "type": "tx",
            "subject": pending["template_subject"],
            "body": seal(token, proof, nonce),
        }
        current_templates = [
            row
            for row in self._rows(admin, "/api/templates")
            if row.get("name") == template_name
        ]
        if len(current_templates) > 1:
            raise RuntimeError("duplicate current Listmonk proof template")
        if current_templates:
            template_id = int(current_templates[0]["id"])
            template = admin.call(
                f"/api/templates/{template_id}",
                method="PUT",
                payload=template_payload,
            )
        else:
            template = admin.call(
                "/api/templates", method="POST", payload=template_payload
            )
        template_id = int(template["id"])
        handle = pack_handle(
            {
                "v": 1,
                "store": STORE,
                "username": username,
                "token": token,
                "template_id": template_id,
                "template_name": template_name,
                "proof": proof,
            }
        )
        pending.update({"template_id": template_id, "handle": handle})
        self._write_journal(target, journal)

        observed = self.retrieve(target, handle, proof)
        if observed.status is not ObservationStatus.PRESENT:
            raise RuntimeError(f"staged target verification failed: {observed.status.value}")

        journal = {
            "v": 1,
            "current": pending,
            "previous": current,
            "pending": None,
        }
        self._write_journal(target, journal)
        self._mark_issued(target)
        return {STORE: handle}

    def retrieve(
        self, target: VulboxTarget, handle: str, expected: str | None = None
    ) -> FlagObservation:
        try:
            value = unpack_handle(handle)
            if value is None or value.get("store") != STORE:
                return FlagObservation(ObservationStatus.ERROR, detail="invalid handle")
            username = value["username"]
            token = value["token"]
            template_id = value["template_id"]
            planted = value["proof"]
            if not isinstance(username, str) or not isinstance(token, str):
                raise ValueError
            if not isinstance(template_id, int) or isinstance(template_id, bool):
                raise ValueError
            if not isinstance(planted, str):
                raise ValueError
            status, raw = request(
                target_base(target),
                f"/api/templates/{template_id}",
                username=username,
                token=token,
            )
            if status in (401, 403):
                return FlagObservation(
                    ObservationStatus.AUTH_REJECTED, detail="target credential rejected"
                )
            if status == 404:
                return FlagObservation(ObservationStatus.NOT_FOUND)
            if status != 200:
                return FlagObservation(
                    ObservationStatus.ERROR, detail=f"template read HTTP {status}"
                )
            document: Any = json.loads(raw)
            envelope = document["data"]["body"]
            if not isinstance(envelope, str):
                raise ValueError
            actual = open_envelope(token, envelope)
            if actual is None:
                return FlagObservation(ObservationStatus.MISMATCH)
            wanted = expected if expected is not None else planted
            if actual != wanted:
                return FlagObservation(ObservationStatus.MISMATCH, value=actual)
            return FlagObservation(ObservationStatus.PRESENT, value=actual)
        except Exception as error:  # noqa: BLE001 — retrieve is fail-closed
            return FlagObservation(
                ObservationStatus.ERROR, detail=f"credential audit failed: {type(error).__name__}"
            )

    def flag_id(self, handle: str) -> str | None:
        return public_locator(handle)
