"""Baseline principals and READ/EXECUTE objective placement for Vikunja."""

from __future__ import annotations

import base64
import hashlib
import secrets
from collections.abc import Mapping

from challenges.interface import (
    BaselinePrincipal,
    Flag,
    FlagHandler,
    FlagObservation,
    ObservationStatus,
    VulboxTarget,
    exec_read_observe,
)

from ._client import VikunjaApi, resolve_host
from ._ids import (
    STORE_COMMAND,
    STORE_PRIVATE_TASK,
    catflag_command,
    derive_principal,
    encode_read_target,
    pack_handle,
    public_flag_id,
    unpack_handle,
)

OBJECTIVE_DIR = "/var/lib/arena/command"
OBJECTIVE_PATH = OBJECTIVE_DIR + "/objective"
CACHE_DIR = "/arena/state/plants"


class VikunjaFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "vikunja-private-task-flag-handler"

    def _api(self, target: VulboxTarget) -> VikunjaApi:
        host = resolve_host(target.host)
        return VikunjaApi(f"http://{host}:{target.ports['service']}")

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

    def _baseline_project(self, target: VulboxTarget, api: VikunjaApi,
                          token: str) -> int:
        rc, out = self._exec(
            target, "test -s /arena/state/baseline_project_id && "
                    "cat /arena/state/baseline_project_id")
        if rc == 0:
            try:
                return int((out or "").strip())
            except ValueError:
                pass
        project = api.create_project(token, "Arena shared baseline")
        project_id = int(project["id"])
        rc, _ = self._exec(
            target,
            "umask 077; printf '%s\\n' " + str(project_id) +
            " > /arena/state/baseline_project_id.new && "
            "mv /arena/state/baseline_project_id.new /arena/state/baseline_project_id")
        if rc != 0:
            raise RuntimeError("could not persist baseline project id")
        return project_id

    def provision_principals(
        self, target: VulboxTarget, seeds: Mapping[str, str],
    ) -> Mapping[str, BaselinePrincipal]:
        api = self._api(target)
        token = self._facility_token(target)
        project_id = self._baseline_project(target, api, token)
        granted: dict[str, BaselinePrincipal] = {}
        for attacker, seed in sorted(seeds.items()):
            username, email, password = derive_principal(seed)
            api.register(username, email, password)
            session = api.login(username, password)
            if not session:
                raise RuntimeError("baseline login rejected")
            share_status = api.share_project(token, project_id, username)
            if share_status not in (200, 201) and api.get_project(session, project_id) != 200:
                raise RuntimeError("baseline project grant rejected")
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
        return {
            STORE_COMMAND: self._plant_command(target, flags[STORE_COMMAND].value),
            STORE_PRIVATE_TASK: self._plant_read(target, flags[STORE_PRIVATE_TASK].value),
        }

    @staticmethod
    def _cache_key(store: str, value: str) -> str:
        return hashlib.sha256(f"{store}\0{value}".encode()).hexdigest()

    def _cached(self, target: VulboxTarget, store: str, value: str) -> str | None:
        key = self._cache_key(store, value)
        rc, out = self._exec(target, f"test -s {CACHE_DIR}/{key} && cat {CACHE_DIR}/{key}")
        handle = (out or "").strip() if rc == 0 else ""
        payload = unpack_handle(handle)
        if payload and payload.get("store") == store and payload.get("flag") == value:
            return handle
        return None

    def _cache(self, target: VulboxTarget, store: str, value: str,
               handle: str) -> None:
        key = self._cache_key(store, value)
        encoded = base64.b64encode(handle.encode()).decode()
        command = (
            f"install -d -o root -g root -m 0700 {CACHE_DIR}; "
            f"printf %s {encoded} | base64 -d > {CACHE_DIR}/{key}.new; "
            f"chmod 0600 {CACHE_DIR}/{key}.new; "
            f"mv -f {CACHE_DIR}/{key}.new {CACHE_DIR}/{key}"
        )
        rc, _ = self._exec(target, command)
        if rc != 0:
            raise RuntimeError(f"could not persist {store} plant state")

    def _plant_command(self, target: VulboxTarget, value: str) -> str:
        cached = self._cached(target, STORE_COMMAND, value)
        if cached:
            return cached
        operation = secrets.token_hex(16)
        payload = base64.b64encode(f"{operation}\n{value}\n".encode()).decode()
        command = (
            f"install -d -o root -g root -m 0700 {OBJECTIVE_DIR}; "
            f"printf %s {payload} | base64 -d > {OBJECTIVE_PATH}.new; "
            f"chown root:root {OBJECTIVE_PATH}.new; chmod 0600 {OBJECTIVE_PATH}.new; "
            f"mv -f {OBJECTIVE_PATH}.new {OBJECTIVE_PATH}"
        )
        rc, _ = self._exec(target, command)
        if rc != 0:
            raise RuntimeError("command objective placement failed")
        handle = pack_handle({"store": STORE_COMMAND, "op": operation, "flag": value})
        self._cache(target, STORE_COMMAND, value, handle)
        return handle

    def _plant_read(self, target: VulboxTarget, value: str) -> str:
        cached = self._cached(target, STORE_PRIVATE_TASK, value)
        if cached:
            return cached
        api = self._api(target)
        token = self._facility_token(target)
        shared_project = self._baseline_project(target, api, token)
        tag = secrets.token_hex(6)
        private_project_id = 0
        shared_task_ids: list[int] = []
        try:
            private_project = api.create_project(token, "Private arena task " + tag)
            private_project_id = int(private_project["id"])
            shared = api.create_task(token, shared_project, "Shared task " + tag,
                                     "ordinary shared task")
            peer = api.create_task(token, shared_project, "Shared peer " + tag,
                                   "legitimate relation target")
            shared_task_ids = [int(shared["id"]), int(peer["id"])]
            private = api.create_task(token, private_project_id,
                                      "Private task " + tag, value)
            private_task_id = int(private["id"])
            if api.relate(token, shared_task_ids[0], shared_task_ids[1]) not in (200, 201):
                raise RuntimeError("legitimate relation create failed")
            if api.relate(token, shared_task_ids[0], private_task_id) not in (200, 201):
                raise RuntimeError("private relation create failed")
            encoded = base64.b64encode(value.encode()).decode()
            rc, out = self._exec(
                target, f"/arena/facility.sh find-uid {private_project_id} {encoded}")
            private_uid = (out or "").strip().splitlines()[-1:] or [""]
            if rc != 0 or not private_uid[0]:
                raise RuntimeError("private CalDAV uid unavailable")
            public = encode_read_target(
                shared_project_id=shared_project,
                shared_task_id=shared_task_ids[0],
                private_task_id=private_task_id,
                private_uid=private_uid[0],
            )
            handle = pack_handle({
                "store": STORE_PRIVATE_TASK,
                "target": public,
                "private_task_id": private_task_id,
                "flag": value,
            })
            self._cache(target, STORE_PRIVATE_TASK, value, handle)
            return handle
        except Exception:
            for task_id in shared_task_ids:
                api.delete_task(token, task_id)
            if private_project_id:
                api.delete_project(token, private_project_id)
            raise

    def retrieve(self, target: VulboxTarget, handle: str,
                 expected: str | None = None) -> FlagObservation:
        payload = unpack_handle(handle)
        if payload is None:
            return FlagObservation(ObservationStatus.ERROR, detail="unreadable handle")
        wanted = expected if expected is not None else payload.get("flag")
        if payload.get("store") == STORE_COMMAND:
            operation = payload.get("op")
            if not isinstance(operation, str) or not operation:
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

    def flag_id(self, handle: str) -> str | None:
        return public_flag_id(handle)
