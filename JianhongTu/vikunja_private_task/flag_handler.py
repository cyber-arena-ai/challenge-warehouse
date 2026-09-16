"""Baseline principals and READ/EXECUTE objective placement for Vikunja."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import shlex
from collections.abc import Mapping

from challenges.interface import (
    BaselinePrincipal,
    Flag,
    FlagHandler,
    FlagObservation,
    ObservationStatus,
    RepairResult,
    VulboxTarget,
    exec_read_observe,
)

from ._client import VikunjaApi
from ._ids import (
    STORE_COMMAND,
    STORE_PRIVATE_TASK,
    catflag_command,
    decode_read_target,
    derive_principal,
    encode_read_target,
    pack_handle,
    public_flag_id,
    unpack_handle,
)
from ._profiles import (
    BASELINE_PROJECT_DESCRIPTION,
    BASELINE_PROJECT_TITLE,
    fresh_project_identifier,
    is_baseline_project_identifier,
    read_profile,
)
from .checker_identity import (
    ISSUED_COHORT_PATH,
    NATIVE_ACCOUNT_PATH,
    checker_writer_identities,
    seal_issued_cohort,
    seal_native_account,
)

OBJECTIVE_DIR = "/var/lib/arena/command"
PLANT_STATE_DIR = "/var/lib/vikunja-plants"
GROUP_STATE_PATH = PLANT_STATE_DIR + "/group.state"
INITIALIZED_PATH = "/var/lib/.vikunja-plants.initialized"
BASELINE_INITIALIZED_PATH = "/var/lib/.vikunja-baseline.initialized"
BASELINE_PROJECT_PATH = "/arena/state/baseline_project_id"
PRINCIPALS_PATH = "/arena/state/baseline_principals"
_ROUND_SEED_RE = re.compile(r"[0-9a-f]{64}")
_CONTEXT_RE = re.compile(r"[0-9a-f]{64}")
_IDENTITY_RE = re.compile(r"[0-9a-f]{32}")
_GROUP_SLOTS = ("current", "previous", "pending")
_STEP_NAMES = {
    "shared_project_id",
    "private_project_id",
    "shared_task_id",
    "peer_task_id",
    "private_task_id",
}


def _round_context(seed: object) -> dict[str, str]:
    """Derive independent, proof-free identities for one objective group."""
    if not isinstance(seed, str) or _ROUND_SEED_RE.fullmatch(seed) is None:
        raise ValueError("round context seed is unavailable")
    key = bytes.fromhex(seed)

    def derive(label: str) -> bytes:
        return hmac.new(
            key,
            f"vikunja-private-task\0round-context-v1\0{label}".encode(),
            hashlib.sha256,
        ).digest()

    return {
        "group": derive("group:journal").hex(),
        "command_operation": derive(f"{STORE_COMMAND}:operation").hex()[:32],
        "read_tag": derive(f"{STORE_PRIVATE_TASK}:records").hex()[:32],
    }


class VikunjaFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "vikunja-private-task-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def _api(self, target: VulboxTarget) -> VikunjaApi:
        return VikunjaApi(f"http://{target.host}:{target.ports['service']}")

    @staticmethod
    def _exec(target: VulboxTarget, command: str) -> tuple[int, str]:
        return target.meta["exec_in_container"](target.host, command)

    def _facility_token(self, target: VulboxTarget) -> str:
        rc, out = self._exec(target, "/arena/facility.sh token")
        token = (out or "").strip().splitlines()[-1:] or [""]
        if rc == 3:
            raise PermissionError("facility account rejected")
        if rc != 0 or not token[0]:
            raise RuntimeError("facility token unavailable")
        return token[0]

    def _seal_native_account(self, target: VulboxTarget) -> None:
        """Publish the placement credential the checker authenticates with."""
        rc, out = self._exec(
            target,
            "set -eu; . /arena/secrets/facility.env; "
            "printf '%s\\n%s\\n' \"$FACILITY_USER\" \"$FACILITY_PASS\" "
            "| base64 | tr -d '\\n'",
        )
        if rc != 0:
            raise RuntimeError("native account credential unavailable")
        username, password = base64.b64decode(
            (out or "").strip().splitlines()[-1]).decode().splitlines()[:2]
        sealed = base64.b64encode(
            (seal_native_account(target, username, password) + "\n").encode()
        ).decode()
        rc, _ = self._exec(
            target,
            "set -eu; umask 077; "
            f"printf %s {sealed} | base64 -d > {NATIVE_ACCOUNT_PATH}.new; "
            f"chown root:root {NATIVE_ACCOUNT_PATH}.new; "
            f"chmod 0600 {NATIVE_ACCOUNT_PATH}.new; "
            f"mv -f {NATIVE_ACCOUNT_PATH}.new {NATIVE_ACCOUNT_PATH}",
        )
        if rc != 0:
            raise RuntimeError("could not persist native account state")

    def _baseline_marker(self, target: VulboxTarget) -> str:
        rc, out = self._exec(
            target,
            "set -eu; "
            f"test -f {BASELINE_INITIALIZED_PATH} && "
            f"test ! -L {BASELINE_INITIALIZED_PATH}; "
            f"test \"$(stat -c '%u:%g:%a' {BASELINE_INITIALIZED_PATH})\" "
            "= '0:0:400'; "
            f"cat {BASELINE_INITIALIZED_PATH}",
        )
        marker = (out or "").strip()
        if rc != 0 or marker not in {
            "vikunja-baseline-v1:virgin", "vikunja-baseline-v1:issued",
        }:
            raise RuntimeError("Vikunja baseline state is not safely reconstructible")
        return marker

    def _cached_baseline_project(self, target: VulboxTarget) -> tuple[bool, int | None]:
        rc, out = self._exec(
            target,
            f"if [ -e {BASELINE_PROJECT_PATH} ] || "
            f"[ -L {BASELINE_PROJECT_PATH} ]; then "
            f"test -f {BASELINE_PROJECT_PATH} && "
            f"test ! -L {BASELINE_PROJECT_PATH} && "
            f"test \"$(stat -c '%u:%g:%a' {BASELINE_PROJECT_PATH})\" "
            "= '0:0:600' && "
            f"cat {BASELINE_PROJECT_PATH}; else exit 44; fi",
        )
        if rc == 44:
            return False, None
        if rc != 0:
            raise RuntimeError("Vikunja baseline project cache is unsafe")
        try:
            project_id = int((out or "").strip())
        except ValueError:
            return True, None
        return True, project_id if project_id > 0 else None

    def _persist_baseline_project(self, target: VulboxTarget,
                                  project_id: int) -> None:
        rc, _ = self._exec(
            target,
            "set -eu; umask 077; "
            f"printf '%s\\n' {project_id} > {BASELINE_PROJECT_PATH}.new; "
            f"chown root:root {BASELINE_PROJECT_PATH}.new; "
            f"chmod 0600 {BASELINE_PROJECT_PATH}.new; "
            f"mv -f {BASELINE_PROJECT_PATH}.new {BASELINE_PROJECT_PATH}",
        )
        if rc != 0:
            raise RuntimeError("could not persist baseline project id")

    def _baseline_project(self, target: VulboxTarget, api: VikunjaApi,
                          token: str) -> int:
        marker = self._baseline_marker(target)
        cache_present, cached_id = self._cached_baseline_project(target)
        candidates = [
            project for project in api.all_projects(token)
            if (
                project.get("title") == BASELINE_PROJECT_TITLE
                and project.get("description") == BASELINE_PROJECT_DESCRIPTION
                and is_baseline_project_identifier(project.get("identifier"))
            )
        ]
        if len(candidates) > 1:
            raise RuntimeError("native baseline project marker is ambiguous")
        if candidates:
            project_id = candidates[0].get("id")
            if not isinstance(project_id, int) or project_id <= 0:
                raise RuntimeError("native baseline project identity is invalid")
        else:
            if marker != "vikunja-baseline-v1:virgin" or cache_present:
                raise RuntimeError("issued native baseline project is missing")
            project = api.create_project(
                token,
                BASELINE_PROJECT_TITLE,
                description=BASELINE_PROJECT_DESCRIPTION,
                identifier=fresh_project_identifier(),
            )
            project_id = project.get("id")
            if not isinstance(project_id, int) or project_id <= 0:
                raise RuntimeError("baseline project create returned no identity")
        if cached_id != project_id:
            self._persist_baseline_project(target, project_id)
        return project_id

    def _restore_baseline_grants(self, api: VikunjaApi, token: str,
                                 project_id: int,
                                 grants: Mapping[str, int]) -> None:
        permissions = api.project_permissions(token, project_id)
        for username, wanted in sorted(grants.items()):
            if username not in permissions:
                status = api.share_project(token, project_id, username)
                if status not in (200, 201):
                    raise RuntimeError(f"baseline project regrant -> {status}")
                permissions[username] = 0
            if permissions[username] != wanted:
                status = api.set_project_permission(
                    token, project_id, username, wanted)
            else:
                continue
            if status not in (200, 201):
                raise RuntimeError(f"baseline project regrant -> {status}")
        restored = api.project_permissions(token, project_id)
        if any(restored.get(username) != wanted
               for username, wanted in grants.items()):
            raise RuntimeError("baseline project grants did not converge")

    def _cached_baseline_usernames(
        self, target: VulboxTarget,
    ) -> tuple[bool, set[str] | None]:
        rc, out = self._exec(
            target,
            f"if [ -e {PRINCIPALS_PATH} ] || [ -L {PRINCIPALS_PATH} ]; then "
            f"test -f {PRINCIPALS_PATH} && test ! -L {PRINCIPALS_PATH} && "
            f"test \"$(stat -c '%u:%g:%a' {PRINCIPALS_PATH})\" = '0:0:600' && "
            f"cat {PRINCIPALS_PATH}; else exit 44; fi",
        )
        if rc == 44:
            return False, None
        if rc != 0:
            raise RuntimeError("Vikunja baseline principal cache is unsafe")
        usernames = (out or "").splitlines()
        if (
            not usernames
            or usernames != sorted(usernames)
            or len(set(usernames)) != len(usernames)
            or any(re.fullmatch(r"reader[0-9a-f]{10}", item) is None
                   for item in usernames)
        ):
            return True, None
        return True, set(usernames)

    def _baseline_usernames(self, target: VulboxTarget) -> set[str]:
        marker = self._baseline_marker(target)
        present, usernames = self._cached_baseline_usernames(target)
        if marker == "vikunja-baseline-v1:issued":
            if not present or usernames is None:
                raise RuntimeError("issued baseline principal manifest is invalid")
            return usernames
        if present:
            raise RuntimeError("baseline principal provisioning is incomplete")
        return set()

    def _persist_baseline_principals(self, target: VulboxTarget,
                                     usernames: list[str]) -> None:
        encoded = base64.b64encode(
            ("\n".join(sorted(usernames)) + "\n").encode()).decode()
        command = (
            "set -eu; umask 077; "
            f"printf %s {encoded} | base64 -d > {PRINCIPALS_PATH}.new; "
            f"chown root:root {PRINCIPALS_PATH}.new; "
            f"chmod 0600 {PRINCIPALS_PATH}.new; "
            f"mv -f {PRINCIPALS_PATH}.new {PRINCIPALS_PATH}"
        )
        rc, _ = self._exec(target, command)
        if rc != 0:
            raise RuntimeError("could not persist baseline principals")

    def _persist_issued_cohort(
        self, target: VulboxTarget, identities: list[tuple[str, str, str]],
    ) -> None:
        sealed = seal_issued_cohort(
            target,
            ((username, password) for username, _email, password in identities),
        )
        encoded = base64.b64encode((sealed + "\n").encode()).decode()
        rc, _ = self._exec(
            target,
            "set -eu; umask 077; "
            f"rm -f {ISSUED_COHORT_PATH}.new; "
            f"printf %s {shlex.quote(encoded)} | base64 -d "
            f"> {ISSUED_COHORT_PATH}.new; "
            f"chown root:root {ISSUED_COHORT_PATH}.new; "
            f"chmod 0400 {ISSUED_COHORT_PATH}.new; "
            f"mv -f {ISSUED_COHORT_PATH}.new {ISSUED_COHORT_PATH}",
        )
        if rc != 0:
            raise RuntimeError("could not persist issued principal cohort")

    def _mark_baseline_issued(self, target: VulboxTarget) -> None:
        encoded = base64.b64encode(b"vikunja-baseline-v1:issued\n").decode()
        rc, _ = self._exec(
            target,
            "set -eu; umask 077; "
            f"printf %s {encoded} | base64 -d > {BASELINE_INITIALIZED_PATH}.new; "
            f"chown root:root {BASELINE_INITIALIZED_PATH}.new; "
            f"chmod 0400 {BASELINE_INITIALIZED_PATH}.new; "
            f"mv -f {BASELINE_INITIALIZED_PATH}.new {BASELINE_INITIALIZED_PATH}",
        )
        if rc != 0:
            raise RuntimeError("could not persist baseline initialization state")

    def _reserve_baseline_usernames(
        self, target: VulboxTarget, usernames: set[str],
    ) -> None:
        marker = self._baseline_marker(target)
        present, saved = self._cached_baseline_usernames(target)
        if present and saved is None:
            raise RuntimeError("Vikunja baseline principal manifest is unsafe")
        if marker == "vikunja-baseline-v1:issued":
            if not present or saved != usernames:
                raise RuntimeError("issued baseline principal manifest conflicts")
            return
        if present:
            if saved != usernames:
                raise RuntimeError("reserved baseline principal manifest conflicts")
        else:
            self._persist_baseline_principals(target, sorted(usernames))
        self._mark_baseline_issued(target)

    @staticmethod
    def _ensure_accounts(
        api: VikunjaApi, identities: list[tuple[str, str, str]],
    ) -> None:
        for username, email, password in sorted(identities):
            status = api.register(username, email, password)
            if status not in (200, 400):
                raise RuntimeError("principal account provisioning failed")

    def provision_principals(
        self, target: VulboxTarget, seeds: Mapping[str, str],
    ) -> Mapping[str, BaselinePrincipal]:
        api = self._api(target)
        token = self._facility_token(target)
        identities = {
            attacker: derive_principal(seed)
            for attacker, seed in sorted(seeds.items())
        }
        if not identities:
            raise ValueError("at least one baseline principal is required")
        checker_writers = checker_writer_identities(target)
        all_identities = list(identities.values()) + list(checker_writers)
        if len({item[0] for item in all_identities}) != len(all_identities):
            raise RuntimeError("Vikunja principal derivation collision")
        project_id = self._baseline_project(target, api, token)
        expected_usernames = {
            username for username, _email, _password in identities.values()
        }
        self._reserve_baseline_usernames(target, expected_usernames)
        self._seal_native_account(target)
        self._ensure_accounts(api, all_identities)
        grants = {
            username: 0 for username, _email, _password in identities.values()
        }
        for writer in checker_writers:
            grants[writer[0]] = 1
        self._restore_baseline_grants(api, token, project_id, grants)
        self._persist_issued_cohort(target, list(identities.values()))
        granted: dict[str, BaselinePrincipal] = {}
        for attacker, (username, _email, password) in identities.items():
            granted[attacker] = BaselinePrincipal(
                principal_id=username,
                credentials={"username": username, "password": password},
            )
        return granted

    def plant(self, target: VulboxTarget,
              flags: Mapping[str, Flag]) -> Mapping[str, str]:
        expected = {STORE_PRIVATE_TASK, STORE_COMMAND}
        if set(flags) != expected:
            raise ValueError(f"expected stores {sorted(expected)}, got {sorted(flags)}")
        context = _round_context(target.meta.get("round_context_seed"))
        values = {store: flags[store].value for store in sorted(expected)}
        journal = self._load_journal(target)
        current = journal["current"]
        if current is not None and current["context"] == context["group"]:
            self._require_group_binding(current, context, values)
            return self._stage_group(target, journal, current)

        pending = journal["pending"]
        if pending is not None and pending["context"] != context["group"]:
            self._retire_group(target, pending)
            journal["pending"] = None
            self._write_journal(target, journal)
            pending = None
        previous = journal["previous"]
        if previous is not None:
            self._retire_group(target, previous)
            journal["previous"] = None
            self._write_journal(target, journal)

        if pending is None:
            pending = self._new_group(context, values)
            journal["pending"] = pending
            self._write_journal(target, journal)
        else:
            self._require_group_binding(pending, context, values)

        handles = self._stage_group(target, journal, pending)
        journal["previous"] = journal["current"]
        journal["current"] = pending
        journal["pending"] = None
        self._write_journal(target, journal)
        return handles

    @staticmethod
    def _new_group(context: Mapping[str, str], values: Mapping[str, str]) -> dict:
        return {
            "v": 1,
            "context": context["group"],
            "command_operation": context["command_operation"],
            "read_tag": context["read_tag"],
            "flags": dict(values),
            "steps": {},
            "handles": {},
        }

    @classmethod
    def _valid_group(cls, group: object, *, complete: bool) -> bool:
        if not isinstance(group, dict) or set(group) != {
            "v", "context", "command_operation", "read_tag", "flags", "steps",
            "handles",
        }:
            return False
        if (
            group.get("v") != 1
            or not isinstance(group.get("context"), str)
            or _CONTEXT_RE.fullmatch(group["context"]) is None
            or not isinstance(group.get("command_operation"), str)
            or _IDENTITY_RE.fullmatch(group["command_operation"]) is None
            or not isinstance(group.get("read_tag"), str)
            or _IDENTITY_RE.fullmatch(group["read_tag"]) is None
        ):
            return False
        values = group.get("flags")
        if (
            not isinstance(values, dict)
            or set(values) != {STORE_COMMAND, STORE_PRIVATE_TASK}
            or any(not isinstance(value, str) or not value for value in values.values())
        ):
            return False
        steps = group.get("steps")
        if not isinstance(steps, dict) or set(steps) - _STEP_NAMES:
            return False
        if any(
            not isinstance(item, int) or isinstance(item, bool) or item <= 0
            for item in steps.values()
        ):
            return False
        handles = group.get("handles")
        if (
            not isinstance(handles, dict)
            or set(handles) - {STORE_COMMAND, STORE_PRIVATE_TASK}
            or any(not isinstance(handle, str) or not handle for handle in handles.values())
        ):
            return False
        if complete and (
            set(handles) != {STORE_COMMAND, STORE_PRIVATE_TASK}
            or set(steps) != _STEP_NAMES
        ):
            return False
        command_handle = handles.get(STORE_COMMAND)
        if command_handle is not None:
            payload = unpack_handle(command_handle)
            if payload != {
                "store": STORE_COMMAND,
                "op": group["command_operation"],
                "flag": values[STORE_COMMAND],
            }:
                return False
        read_handle = handles.get(STORE_PRIVATE_TASK)
        if read_handle is not None:
            payload = unpack_handle(read_handle)
            target = decode_read_target(payload.get("target")) if payload else None
            if (
                payload is None
                or set(payload) != {
                    "store", "target", "shared_project_id", "shared_task_id",
                    "private_project_id", "private_task_id", "peer_task_id",
                    "tag", "flag",
                }
                or payload.get("store") != STORE_PRIVATE_TASK
                or payload.get("tag") != group["read_tag"]
                or payload.get("flag") != values[STORE_PRIVATE_TASK]
                or target is None
                or payload.get("private_project_id") != steps.get("private_project_id")
                or payload.get("private_task_id") != steps.get("private_task_id")
                or payload.get("peer_task_id") != steps.get("peer_task_id")
                or payload.get("shared_project_id") != steps.get("shared_project_id")
                or payload.get("shared_task_id") != steps.get("shared_task_id")
            ):
                return False
        return True

    @classmethod
    def _valid_journal(cls, journal: object) -> bool:
        if not isinstance(journal, dict) or set(journal) != {"v", *_GROUP_SLOTS}:
            return False
        if journal.get("v") != 1:
            return False
        contexts: list[str] = []
        for slot in _GROUP_SLOTS:
            group = journal.get(slot)
            if group is None:
                continue
            if not cls._valid_group(group, complete=slot != "pending"):
                return False
            contexts.append(group["context"])
        if len(contexts) != len(set(contexts)):
            return False
        return journal.get("current") is not None or journal.get("previous") is None

    def _load_journal(self, target: VulboxTarget) -> dict:
        rc, marker = self._exec(
            target,
            "set -eu; "
            f"test -d {PLANT_STATE_DIR} && test ! -L {PLANT_STATE_DIR}; "
            f"test \"$(stat -c '%u:%g:%a' {PLANT_STATE_DIR})\" = '0:0:700'; "
            f"test -f {INITIALIZED_PATH} && test ! -L {INITIALIZED_PATH}; "
            f"test \"$(stat -c '%u:%g:%a' {INITIALIZED_PATH})\" = '0:0:400'; "
            f"cat {INITIALIZED_PATH}",
        )
        marker = (marker or "").strip()
        if rc != 0 or marker not in {
            "vikunja-plants-v1:virgin", "vikunja-plants-v1:issued",
        }:
            raise RuntimeError("Vikunja placement state is not safely reconstructible")
        rc, raw = self._exec(
            target,
            "set -eu; "
            f"rm -f {GROUP_STATE_PATH}.new; "
            f"if [ -e {GROUP_STATE_PATH} ] || [ -L {GROUP_STATE_PATH} ]; then "
            f"test -f {GROUP_STATE_PATH} && test ! -L {GROUP_STATE_PATH}; "
            f"test \"$(stat -c '%u:%g:%a' {GROUP_STATE_PATH})\" = '0:0:600'; "
            f"cat {GROUP_STATE_PATH}; else exit 44; fi",
        )
        if rc == 44:
            if marker == "vikunja-plants-v1:issued":
                raise RuntimeError(
                    "Vikunja placement state is not safely reconstructible")
            return {"v": 1, "current": None, "previous": None, "pending": None}
        journal = unpack_handle((raw or "").strip()) if rc == 0 else None
        if not self._valid_journal(journal):
            raise RuntimeError("Vikunja placement state is not safely reconstructible")
        if marker == "vikunja-plants-v1:virgin":
            self._mark_placement_issued(target)
        return journal

    def _mark_placement_issued(self, target: VulboxTarget) -> None:
        encoded = base64.b64encode(b"vikunja-plants-v1:issued\n").decode()
        rc, _ = self._exec(
            target,
            "set -eu; umask 077; "
            f"printf %s {encoded} | base64 -d > {INITIALIZED_PATH}.new; "
            f"chown root:root {INITIALIZED_PATH}.new; "
            f"chmod 0400 {INITIALIZED_PATH}.new; "
            f"mv -f {INITIALIZED_PATH}.new {INITIALIZED_PATH}",
        )
        if rc != 0:
            raise RuntimeError("could not persist Vikunja placement marker")

    def _write_journal(self, target: VulboxTarget, journal: dict) -> None:
        if not self._valid_journal(journal):
            raise RuntimeError("refusing invalid Vikunja placement state")
        encoded = base64.b64encode(
            (pack_handle(journal) + "\n").encode()).decode()
        rc, _ = self._exec(
            target,
            "set -eu; umask 077; "
            f"rm -f {GROUP_STATE_PATH}.new; "
            f"printf %s {shlex.quote(encoded)} | base64 -d > {GROUP_STATE_PATH}.new; "
            f"chown root:root {GROUP_STATE_PATH}.new; "
            f"chmod 0600 {GROUP_STATE_PATH}.new; "
            f"mv -f {GROUP_STATE_PATH}.new {GROUP_STATE_PATH}",
        )
        if rc != 0:
            raise RuntimeError("could not persist Vikunja placement group")
        self._mark_placement_issued(target)

    @staticmethod
    def _require_group_binding(
        group: dict, context: Mapping[str, str], values: Mapping[str, str],
    ) -> None:
        if (
            group["context"] != context["group"]
            or group["command_operation"] != context["command_operation"]
            or group["read_tag"] != context["read_tag"]
            or group["flags"] != dict(values)
        ):
            raise RuntimeError("Vikunja placement group binding conflicts")

    def _record_step(self, target: VulboxTarget, journal: dict, state: dict,
                     name: str, item: int) -> None:
        steps = dict(state["steps"])
        prior = steps.get(name)
        if prior is not None and prior != item:
            raise RuntimeError("Vikunja placement group conflicts")
        steps[name] = item
        state["steps"] = steps
        self._write_journal(target, journal)

    def _record_handle(self, target: VulboxTarget, journal: dict, state: dict,
                       store: str, handle: str) -> None:
        prior = state["handles"].get(store)
        if prior is not None and prior != handle:
            raise RuntimeError("Vikunja placement group handle conflicts")
        if prior is None:
            state["handles"][store] = handle
            self._write_journal(target, journal)

    def _retire_group(self, target: VulboxTarget, state: dict) -> None:
        operation = state["command_operation"]
        rc, _ = self._exec(target, f"rm -f {OBJECTIVE_DIR}/{operation}")
        if rc != 0:
            raise RuntimeError("could not retire prior command objective")
        steps = state["steps"]
        if not steps:
            return
        api = self._api(target)
        token = self._facility_token(target)
        for key in ("shared_task_id", "peer_task_id"):
            task_id = steps.get(key)
            if task_id is None:
                continue
            status = api.delete_task(token, task_id)
            if status not in (200, 204, 404):
                raise RuntimeError(f"prior {key} cleanup -> {status}")
        project_id = steps.get("private_project_id")
        if project_id is not None:
            status = api.delete_project(token, project_id)
            if status not in (200, 204, 404):
                raise RuntimeError(f"prior private project cleanup -> {status}")

    def _stage_group(
        self, target: VulboxTarget, journal: dict, state: dict,
    ) -> dict[str, str]:
        handles = {
            STORE_COMMAND: self._plant_command(
                target, journal, state, state["flags"][STORE_COMMAND]),
            STORE_PRIVATE_TASK: self._plant_read(
                target, journal, state, state["flags"][STORE_PRIVATE_TASK]),
        }
        for store, handle in handles.items():
            observed = self.retrieve(
                target, handle, expected=state["flags"][store])
            if observed.status is not ObservationStatus.PRESENT:
                raise RuntimeError(f"{store} objective did not converge")
        return handles

    def _plant_command(self, target: VulboxTarget, journal: dict,
                       state: dict, value: str) -> str:
        operation = state["command_operation"]
        self._write_command_objective(target, operation, value)
        handle = pack_handle({"store": STORE_COMMAND, "op": operation, "flag": value})
        self._record_handle(target, journal, state, STORE_COMMAND, handle)
        observed = self.retrieve(target, handle, expected=value)
        if observed.status is not ObservationStatus.PRESENT:
            raise RuntimeError(
                "command objective could not be restored through its operation")
        return handle

    def _write_command_objective(self, target: VulboxTarget, operation: str,
                                 value: str) -> None:
        if _IDENTITY_RE.fullmatch(operation) is None:
            raise ValueError("invalid command operation")
        payload = base64.b64encode(f"{operation}\n{value}\n".encode()).decode()
        objective_path = f"{OBJECTIVE_DIR}/{operation}"
        command = (
            f"install -d -o root -g root -m 0700 {OBJECTIVE_DIR}; "
            f"printf %s {payload} | base64 -d > {objective_path}.new; "
            f"chown root:root {objective_path}.new; chmod 0600 {objective_path}.new; "
            f"mv -f {objective_path}.new {objective_path}"
        )
        rc, _ = self._exec(target, command)
        if rc != 0:
            raise RuntimeError("command objective placement failed")

    def _converge_project(self, target: VulboxTarget, api: VikunjaApi,
                          token: str, journal: dict, state: dict) -> int:
        profile = read_profile(state["read_tag"])
        projects = api.all_projects(token)
        marked = [
            project for project in projects
            if (
                project.get("identifier") == profile.private_project_identifier
                and project.get("description") == profile.private_project_description
            )
        ]
        if len(marked) > 1:
            raise RuntimeError("reserved private project marker is ambiguous")
        exact_titles = [
            project for project in projects
            if project.get("title") == profile.private_project_title
        ]
        saved_id = state["steps"].get("private_project_id")
        if saved_id is not None:
            if api.get_project(token, saved_id) != 200:
                raise RuntimeError("reserved private project is missing")
            if marked and marked[0].get("id") != saved_id:
                raise RuntimeError("reserved private project marker conflicts")
            return saved_id
        if marked:
            project_id = marked[0].get("id")
            if not isinstance(project_id, int) or project_id <= 0:
                raise RuntimeError("reserved private project identity is invalid")
        else:
            if exact_titles:
                raise RuntimeError("reserved private project state conflicts")
            project = api.create_project(
                token,
                profile.private_project_title,
                description=profile.private_project_description,
                identifier=profile.private_project_identifier,
            )
            project_id = project.get("id")
            if not isinstance(project_id, int) or project_id <= 0:
                raise RuntimeError("private project create returned no identity")
        self._record_step(
            target, journal, state, "private_project_id", project_id)
        return project_id

    def _converge_task(self, target: VulboxTarget, api: VikunjaApi,
                       token: str, journal: dict, state: dict, *, role: str,
                       project_id: int, title: str, description: str) -> dict:
        id_key = role + "_id"
        marked = [
            task for task in api.find_tasks(token, project_id, title)
            if task.get("title") == title
        ]
        if len(marked) > 1:
            raise RuntimeError(f"reserved {role} marker is ambiguous")
        saved_id = state["steps"].get(id_key)
        if saved_id is not None:
            status, task, _ = api.get_task(token, saved_id)
            if status != 200 or task is None:
                raise RuntimeError(f"reserved {role} is missing")
            if task.get("project_id") != project_id:
                raise RuntimeError(f"reserved {role} marker conflicts")
        elif marked:
            task = marked[0]
            saved_id = task.get("id")
            if (
                not isinstance(saved_id, int)
                or saved_id <= 0
                or task.get("project_id") != project_id
            ):
                raise RuntimeError(f"reserved {role} identity is invalid")
            self._record_step(target, journal, state, id_key, saved_id)
        else:
            task = api.create_task(token, project_id, title, description)
            saved_id = task.get("id")
            if not isinstance(saved_id, int) or saved_id <= 0:
                raise RuntimeError(f"{role} create returned no identity")
            self._record_step(target, journal, state, id_key, saved_id)
        if task.get("title") != title or task.get("description") != description:
            task = api.update_task(
                token, task, title=title, description=description)
        return task

    def _plant_read(self, target: VulboxTarget, journal: dict,
                    state: dict, value: str) -> str:
        api = self._api(target)
        token = self._facility_token(target)
        shared_project = self._baseline_project(target, api, token)
        self._record_step(
            target, journal, state, "shared_project_id", shared_project)
        baseline_usernames = self._baseline_usernames(target)
        self._restore_baseline_grants(
            api, token, shared_project,
            {username: 0 for username in baseline_usernames})
        return self._converge_read(
            target, api, token, shared_project, baseline_usernames,
            journal, state, value)

    def _reconcile_read(self, target: VulboxTarget, api: VikunjaApi, token: str,
                        shared_project: int, baseline_usernames: set[str],
                        handle: str, value: str) -> None:
        payload = unpack_handle(handle) or {}
        public = payload.get("target")
        decoded = decode_read_target(public) if isinstance(public, str) else None
        private_task_id = payload.get("private_task_id")
        private_project_id = payload.get("private_project_id")
        peer_task_id = payload.get("peer_task_id")
        tag = payload.get("tag")
        if (
            not isinstance(public, str)
            or decoded is None
            or payload.get("shared_project_id") != shared_project
            or not isinstance(payload.get("shared_task_id"), int)
            or payload["shared_task_id"] <= 0
            or not isinstance(private_task_id, int)
            or private_task_id <= 0
            or private_task_id != decoded.get("private_task_id")
            or not isinstance(private_project_id, int)
            or private_project_id <= 0
            or not isinstance(peer_task_id, int)
            or peer_task_id <= 0
            or not isinstance(tag, str)
            or not tag
        ):
            raise RuntimeError("cached read placement metadata is irreconstructible")

        profile = read_profile(tag)
        expected_tasks = (
            (payload["shared_task_id"], shared_project,
             profile.shared_task_title, profile.shared_task_description),
            (peer_task_id, shared_project,
             profile.peer_task_title, profile.peer_task_description),
            (private_task_id, private_project_id,
             profile.private_task_title, value),
        )
        tasks: dict[int, dict] = {}
        for task_id, project_id, title, description in expected_tasks:
            status, task, _ = api.get_task(token, task_id)
            if status in (403, 404):
                raise RuntimeError("cached read placement identity is missing")
            if status != 200 or task is None:
                raise RuntimeError(f"cached task read -> {status}")
            if task.get("project_id") != project_id:
                raise RuntimeError("cached read placement moved across projects")
            tasks[task_id] = task

        private_permissions = api.project_permissions(token, private_project_id)
        for username in sorted(
                baseline_usernames & private_permissions.keys()):
            status = api.unshare_project(token, private_project_id, username)
            if status not in (200, 201):
                raise RuntimeError(f"cached private project unshare -> {status}")

        for task_id, _, title, description in expected_tasks:
            task = tasks[task_id]
            if task.get("title") != title or task.get("description") != description:
                tasks[task_id] = api.update_task(
                    token, task, title=title, description=description)

        shared_task = tasks[payload["shared_task_id"]]
        related = self._related_ids(shared_task)
        for other_task in (peer_task_id, private_task_id):
            if other_task not in related:
                status = api.relate(token, payload["shared_task_id"], other_task)
                if status not in (200, 201):
                    raise RuntimeError(f"cached relation restore -> {status}")

        encoded = base64.b64encode(profile.private_task_title.encode()).decode()
        rc, out = self._exec(
            target, f"/arena/facility.sh find-uid {private_project_id} {encoded}")
        private_uid = (out or "").strip().splitlines()[-1:] or [""]
        if rc != 0:
            raise RuntimeError("cached private CalDAV uid unavailable")
        if private_uid[0] != decoded.get("private_uid"):
            raise RuntimeError("cached private CalDAV identity changed")

    @staticmethod
    def _related_ids(task: dict) -> set[int]:
        relations = task.get("related_tasks") or {}
        return {
            item["id"] for items in relations.values() for item in (items or [])
            if isinstance(item, dict) and isinstance(item.get("id"), int)
        }

    def _converge_read(self, target: VulboxTarget, api: VikunjaApi,
                       token: str, shared_project: int,
                       baseline_usernames: set[str], journal: dict, state: dict,
                       value: str) -> str:
        tag = state["read_tag"]
        profile = read_profile(tag)
        private_project_id = self._converge_project(
            target, api, token, journal, state)
        shared = self._converge_task(
            target,
            api,
            token,
            journal,
            state,
            role="shared_task",
            project_id=shared_project,
            title=profile.shared_task_title,
            description=profile.shared_task_description,
        )
        peer = self._converge_task(
            target,
            api,
            token,
            journal,
            state,
            role="peer_task",
            project_id=shared_project,
            title=profile.peer_task_title,
            description=profile.peer_task_description,
        )
        private = self._converge_task(
            target,
            api,
            token,
            journal,
            state,
            role="private_task",
            project_id=private_project_id,
            title=profile.private_task_title,
            description=value,
        )
        shared_task_id = int(shared["id"])
        peer_task_id = int(peer["id"])
        private_task_id = int(private["id"])
        status, current_shared, _ = api.get_task(token, shared_task_id)
        if status != 200 or current_shared is None:
            raise RuntimeError("reserved shared task is unavailable")
        related = self._related_ids(current_shared)
        for other_task in (peer_task_id, private_task_id):
            if other_task not in related:
                status = api.relate(token, shared_task_id, other_task)
                if status not in (200, 201):
                    raise RuntimeError("reserved relation create failed")

        encoded = base64.b64encode(profile.private_task_title.encode()).decode()
        rc, out = self._exec(
            target, f"/arena/facility.sh find-uid {private_project_id} {encoded}")
        private_uid = (out or "").strip().splitlines()[-1:] or [""]
        if rc != 0 or not private_uid[0]:
            raise RuntimeError("private CalDAV uid unavailable")
        public = encode_read_target(
            private_task_id=private_task_id,
            private_uid=private_uid[0],
        )
        handle = pack_handle({
            "store": STORE_PRIVATE_TASK,
            "target": public,
            "shared_project_id": shared_project,
            "shared_task_id": shared_task_id,
            "private_project_id": private_project_id,
            "private_task_id": private_task_id,
            "peer_task_id": peer_task_id,
            "tag": tag,
            "flag": value,
        })
        self._record_handle(
            target, journal, state, STORE_PRIVATE_TASK, handle)
        self._reconcile_read(
            target, api, token, shared_project, baseline_usernames, handle, value)
        return handle

    def retrieve(self, target: VulboxTarget, handle: str,
                 expected: str | None = None) -> FlagObservation:
        payload = unpack_handle(handle)
        if payload is None:
            return FlagObservation(ObservationStatus.ERROR, detail="unreadable handle")
        wanted = expected if expected is not None else payload.get("flag")
        if payload.get("store") == STORE_COMMAND:
            operation = payload.get("op")
            if (
                not isinstance(operation, str)
                or _IDENTITY_RE.fullmatch(operation) is None
            ):
                return FlagObservation(ObservationStatus.ERROR,
                                       detail="missing operation id")
            return exec_read_observe(target, catflag_command(operation), wanted)
        if payload.get("store") != STORE_PRIVATE_TASK:
            return FlagObservation(ObservationStatus.ERROR, detail="unknown store")
        task_id = payload.get("private_task_id")
        if not isinstance(task_id, int) or not isinstance(wanted, str):
            return FlagObservation(ObservationStatus.ERROR, detail="invalid read handle")
        try:
            api = self._api(target)
            token = self._facility_token(target)
            status, task, _ = api.get_task(token, task_id)
        except PermissionError:
            return FlagObservation(ObservationStatus.AUTH_REJECTED,
                                   detail="facility account rejected")
        except Exception:
            return FlagObservation(ObservationStatus.ERROR, detail="task observation failed")
        if status in (403, 404):
            return FlagObservation(ObservationStatus.NOT_FOUND)
        if status != 200 or task is None:
            return FlagObservation(ObservationStatus.ERROR, detail=f"task read -> {status}")
        actual = task.get("description")
        if actual == wanted:
            return FlagObservation(ObservationStatus.PRESENT, value=actual)
        return FlagObservation(ObservationStatus.MISMATCH)

    def repair(self, target: VulboxTarget, handle: str) -> RepairResult:
        payload = unpack_handle(handle)
        if payload is None or payload.get("store") != STORE_PRIVATE_TASK:
            return RepairResult.NO_ACTION
        try:
            rc, _ = self._exec(target, "/arena/facility.sh repair")
        except Exception:  # noqa: BLE001
            return RepairResult.FAILED
        return RepairResult.REPAIRED if rc == 0 else RepairResult.FAILED

    def flag_id(self, handle: str) -> str | None:
        return public_flag_id(handle)
