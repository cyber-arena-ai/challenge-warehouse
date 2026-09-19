"""Application-native principals and archived-record objective placement."""

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
    authenticate,
    b64,
    delete_key,
    document,
    put_key,
    request,
    target_base,
)
from ._codec import (
    PRINCIPAL_RE,
    ROLE_RE,
    archive_id,
    checker_principals,
    derive,
    prefix_end,
    principal_credentials,
    principal_prefix,
    principal_role,
    target_key,
    valid_archive,
    valid_target_key,
)


STORE = "offline_archive"
LEGACY_ROLE = "configuration-analyst"
PRIVATE_DIR = "/srv/etcd/private"
ROOT_PASSWORD_PATH = f"{PRIVATE_DIR}/root-password"
JOURNAL_PATH = f"{PRIVATE_DIR}/objective-journal.json"
# The proof sits in the framework facility directory rather than the
# challenge's private one. Both are equally out of reach of the fault, which
# yields a keyspace read and never a file read; the facility path is chosen so
# the published locator points an attacker at the infrastructure.
ARCHIVE_DIR = "/arena/archive"
ISSUED_PATH = f"{PRIVATE_DIR}/objective-issued"
ISSUED_VALUE = "etcd-objective-v1"


def _empty_journal() -> dict[str, Any]:
    return {"v": 1, "current": None, "previous": None, "pending": None}


class EtcdFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "etcd-database-credential-flag-handler"

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
            raise RuntimeError("private etcd state operation failed")
        return output or ""

    def _read_private(self, target: VulboxTarget, path: str) -> str:
        value = self._exec(target, f"cat {shlex.quote(path)}").strip()
        if not value:
            raise RuntimeError("private etcd credential is unavailable")
        return value

    def _admin(self, target: VulboxTarget) -> tuple[str, str]:
        base = target_base(target)
        password = self._read_private(target, ROOT_PASSWORD_PATH)
        return base, authenticate(base, "root", password)

    def _read_file_state(self, target: VulboxTarget, path: str) -> str:
        quoted = shlex.quote(path)
        return self._exec(
            target,
            f"if [ ! -e {quoted} ]; then printf missing; "
            f"elif [ -f {quoted} ]; then printf 'file\\n'; cat {quoted}; "
            "else printf invalid; fi",
        )

    def _load_journal(self, target: VulboxTarget) -> dict[str, Any]:
        marker = self._read_file_state(target, ISSUED_PATH)
        if marker == "missing":
            issued = False
        elif marker == f"file\n{ISSUED_VALUE}\n":
            issued = True
        else:
            raise RuntimeError("objective issuance marker is malformed")

        state = self._read_file_state(target, JOURNAL_PATH)
        if state == "missing":
            if issued:
                raise RuntimeError("objective journal is missing after issuance")
            return _empty_journal()
        if not state.startswith("file\n") or not state.removeprefix("file\n"):
            raise RuntimeError("objective journal is malformed")
        try:
            journal = json.loads(state.removeprefix("file\n"))
        except json.JSONDecodeError as error:
            raise RuntimeError("objective journal is malformed") from error
        slots = ("current", "previous", "pending")
        if (
            not isinstance(journal, dict)
            or journal.get("v") != 1
            or any(
                journal.get(slot) is not None
                and not isinstance(journal.get(slot), dict)
                for slot in slots
            )
            or all(journal.get(slot) is None for slot in slots)
        ):
            raise RuntimeError("objective journal is malformed")
        return journal

    def _write_private_json(
        self, target: VulboxTarget, path: str, value: Mapping[str, Any]
    ) -> None:
        raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
        encoded = base64.b64encode(raw).decode()
        temporary = shlex.quote(path + ".next")
        quoted = shlex.quote(path)
        self._exec(
            target,
            "set -eu; umask 077; "
            f"printf %s {shlex.quote(encoded)} | base64 -d > {temporary}; "
            f"chmod 0600 {temporary}; mv -f {temporary} {quoted}",
        )

    def _write_journal(
        self, target: VulboxTarget, journal: Mapping[str, Any]
    ) -> None:
        self._write_private_json(target, JOURNAL_PATH, journal)

    @staticmethod
    def _archive_path(record: str) -> str:
        return f"{ARCHIVE_DIR}/{record}.record"

    def _write_archive(
        self, target: VulboxTarget, record: str, value: str
    ) -> None:
        path = self._archive_path(record)
        temporary = shlex.quote(path + ".next")
        quoted = shlex.quote(path)
        encoded = base64.b64encode(value.encode()).decode()
        self._exec(
            target,
            "set -eu; umask 077; "
            f"install -d -m 700 {shlex.quote(ARCHIVE_DIR)}; "
            f"printf %s {shlex.quote(encoded)} | base64 -d > {temporary}; "
            f"chmod 0600 {temporary}; mv -f {temporary} {quoted}",
        )

    def _sweep_archives(self, target: VulboxTarget, record: str) -> None:
        """Clear every archived record except the current one.

        Journal-driven retirement removes exactly what the journal records, so
        a lost or hand-edited journal would strand prior generations' proofs on
        the victim. This sweep is the backstop and does not depend on the
        journal being intact.
        """
        keep = shlex.quote(f"{record}.record")
        self._exec(
            target,
            f"[ -d {shlex.quote(ARCHIVE_DIR)} ] || exit 0; "
            f"find {shlex.quote(ARCHIVE_DIR)} -mindepth 1 ! -name {keep} "
            "-exec rm -f {} +",
        )

    def _delete_archive(self, target: VulboxTarget, record: str) -> None:
        # `.next` is the per-generation temporary name used by _write_archive;
        # an interrupted write leaves one behind holding that round's proof, so
        # retiring a generation must clear both names.
        path = shlex.quote(self._archive_path(record))
        self._exec(target, f"rm -f {path} {path}.next")

    def _mark_issued(self, target: VulboxTarget) -> None:
        temporary = shlex.quote(ISSUED_PATH + ".next")
        path = shlex.quote(ISSUED_PATH)
        self._exec(
            target,
            "set -eu; umask 077; "
            f"printf '%s\\n' {shlex.quote(ISSUED_VALUE)} > {temporary}; "
            f"chmod 0600 {temporary}; mv -f {temporary} {path}",
        )

    @staticmethod
    def _generation_key(generation: object) -> str | None:
        if not isinstance(generation, dict):
            return None
        key = generation.get("key")
        return key if valid_target_key(key) else None

    @staticmethod
    def _generation_archive(generation: object) -> str | None:
        if not isinstance(generation, dict):
            return None
        record = generation.get("archive")
        return record if valid_archive(record) else None

    @staticmethod
    def _delete(base: str, token: str, key: str) -> None:
        status, raw = delete_key(base, token, key)
        document(status, raw, "protected-key cleanup")

    @staticmethod
    def _put(base: str, token: str, key: str, value: str) -> None:
        status, raw = put_key(base, token, key, value)
        document(status, raw, "protected-key placement")

    def provision_principals(
        self, target: VulboxTarget, seeds: Mapping[str, str]
    ) -> Mapping[str, BaselinePrincipal]:
        base, token = self._admin(target)
        team_id = target.meta.get("team_id")
        if not isinstance(team_id, str) or not team_id:
            raise RuntimeError("target identity unavailable")
        assignments: list[tuple[str | None, str, str]] = [
            (None, username, password)
            for username, password in checker_principals(team_id)
        ]
        assignments.extend(
            (attacker, *principal_credentials(seed))
            for attacker, seed in sorted(seeds.items())
        )
        usernames = [username for _, username, _ in assignments]
        credentials = [(username, password) for _, username, password in assignments]
        if len(usernames) != len(set(usernames)) or len(credentials) != len(
            set(credentials)
        ):
            raise RuntimeError("ordinary principal identity collision")

        status, raw = request(base, "/v3/auth/user/list", {}, token=token)
        users = document(status, raw, "user listing").get("users")
        if not isinstance(users, list) or not all(isinstance(user, str) for user in users):
            raise RuntimeError("etcd user listing was malformed")
        for username in users:
            if PRINCIPAL_RE.fullmatch(username) is not None:
                status, raw = request(
                    base, "/v3/auth/user/delete", {"name": username}, token=token
                )
                document(status, raw, "ordinary user cleanup")

        status, raw = request(base, "/v3/auth/role/list", {}, token=token)
        roles = document(status, raw, "role listing").get("roles", [])
        if not isinstance(roles, list) or not all(isinstance(role, str) for role in roles):
            raise RuntimeError("etcd role listing was malformed")
        for role in roles:
            if role == LEGACY_ROLE or ROLE_RE.fullmatch(role) is not None:
                status, raw = request(
                    base, "/v3/auth/role/delete", {"role": role}, token=token
                )
                document(status, raw, "ordinary role cleanup")

        principals: dict[str, BaselinePrincipal] = {}
        for attacker, username, password in sorted(
            assignments, key=lambda row: row[1]
        ):
            role = principal_role(username)
            prefix = principal_prefix(username)
            status, raw = request(
                base, "/v3/auth/role/add", {"name": role}, token=token
            )
            document(status, raw, "ordinary role creation")
            status, raw = request(
                base,
                "/v3/auth/role/grant",
                {
                    "name": role,
                    "perm": {
                        "permType": "READWRITE",
                        "key": b64(prefix),
                        "range_end": b64(prefix_end(prefix)),
                    },
                },
                token=token,
            )
            document(status, raw, "ordinary prefix grant")
            status, raw = request(
                base,
                "/v3/auth/user/add",
                {"name": username, "password": password},
                token=token,
            )
            document(status, raw, "principal creation")
            status, raw = request(
                base,
                "/v3/auth/user/grant",
                {"user": username, "role": role},
                token=token,
            )
            document(status, raw, "principal role grant")
            authenticate(base, username, password)
            if attacker is not None:
                principals[attacker] = BaselinePrincipal(
                    principal_id=username,
                    credentials={"username": username, "password": password},
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
        key = target_key(seed)
        record = archive_id(seed)
        context = derive(seed, "database-password:generation").hex()
        proof = flags[STORE].value
        # The protected key keeps rotating so the prefix-authorization
        # boundary the fault crosses stays live and crossable; it carries
        # round-derived noise instead of the proof.
        noise = derive(seed, "protected-record:value").hex()[:32]
        journal = self._load_journal(target)
        base, token = self._admin(target)

        current = journal.get("current")
        same_context = (
            isinstance(current, dict) and current.get("context") == context
        )
        if same_context and (
            current.get("proof") != proof
            or current.get("key") != key
            or current.get("archive") != record
        ):
            raise RuntimeError("round context was reused with different proof state")

        previous_key = self._generation_key(journal.get("previous"))
        if journal.get("previous") is not None and not same_context:
            if previous_key is None:
                raise RuntimeError("previous objective generation is malformed")
            previous_archive = self._generation_archive(journal.get("previous"))
            if previous_archive is None:
                raise RuntimeError("previous objective generation is malformed")
            self._delete(base, token, previous_key)
            self._delete_archive(target, previous_archive)
            journal["previous"] = None
            self._write_journal(target, journal)

        pending = journal.get("pending")
        if isinstance(pending, dict) and (
            pending.get("context") != context or pending.get("proof") != proof
        ):
            pending_key = self._generation_key(pending)
            if pending_key is None:
                raise RuntimeError("pending objective generation is malformed")
            pending_archive = self._generation_archive(pending)
            if pending_archive is None:
                raise RuntimeError("pending objective generation is malformed")
            self._delete(base, token, pending_key)
            self._delete_archive(target, pending_archive)
            journal["pending"] = None
            self._write_journal(target, journal)

        if same_context:
            self._put(base, token, key, noise)
            self._write_archive(target, record, proof)
            observed = self.retrieve(target, record, proof)
            if observed.status is not ObservationStatus.PRESENT:
                raise RuntimeError(
                    f"current target verification failed: {observed.status.value}"
                )
            self._sweep_archives(target, record)
            self._mark_issued(target)
            return {STORE: record}

        pending = journal.get("pending")
        if not isinstance(pending, dict):
            pending = {
                "context": context, "key": key, "archive": record, "proof": proof,
            }
            journal["pending"] = pending
            self._write_journal(target, journal)
        elif pending.get("key") != key or pending.get("archive") != record:
            raise RuntimeError("pending objective generation is malformed")

        self._put(base, token, key, noise)
        self._write_archive(target, record, proof)
        observed = self.retrieve(target, record, proof)
        if observed.status is not ObservationStatus.PRESENT:
            raise RuntimeError(f"staged target verification failed: {observed.status.value}")

        journal = {
            "v": 1,
            "current": pending,
            "previous": current,
            "pending": None,
        }
        self._write_journal(target, journal)
        self._sweep_archives(target, record)
        self._mark_issued(target)
        return {STORE: record}

    def retrieve(
        self, target: VulboxTarget, handle: str, expected: str | None = None
    ) -> FlagObservation:
        if not valid_archive(handle):
            return FlagObservation(ObservationStatus.ERROR, detail="invalid handle")
        try:
            state = self._read_file_state(target, self._archive_path(handle))
            if state == "missing":
                return FlagObservation(ObservationStatus.NOT_FOUND)
            if not state.startswith("file\n"):
                return FlagObservation(
                    ObservationStatus.ERROR, detail="archived record is malformed"
                )
            actual = state.removeprefix("file\n")
            if expected is not None and actual != expected:
                return FlagObservation(ObservationStatus.MISMATCH, value=actual)
            return FlagObservation(ObservationStatus.PRESENT, value=actual)
        except Exception as error:  # noqa: BLE001 — retrieve must fail closed
            return FlagObservation(
                ObservationStatus.ERROR,
                detail=f"archived read failed: {type(error).__name__}",
            )

    def flag_id(self, handle: str) -> str | None:
        return self._archive_path(handle) if valid_archive(handle) else None
