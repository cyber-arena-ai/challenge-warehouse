"""Atomic native-API placement for the protected MLflow trace objectives."""

from __future__ import annotations

import base64
from collections.abc import Mapping
import json
import os
from pathlib import Path
import shlex
import sqlite3
import tempfile
from typing import Any

from challenges.interface import (
    BaselinePrincipal,
    Flag,
    FlagHandler,
    FlagObservation,
    ObservationStatus,
    StateReadStatus,
    VulboxTarget,
    read_authoritative_state,
)

from ._client import (
    MlflowClient,
    create_experiment,
    delete_user,
    ensure_user,
    native_gc_command,
    pair_value,
    put_trace,
    target_admin,
    target_base,
    trace_info,
)
from ._codec import (
    USERNAME_DOMAIN,
    derive,
    pack_handle,
    principal_workflow,
    public_locator,
    round_identity,
    unpack_handle,
    username_owned,
    workflow_manifest,
)


READ_STORE = "trace-metadata"
WRITE_STORE = "trace-tag"
JOURNAL_PATH = "/srv/mlflow/private/objective-journal.json"
ISSUED_PATH = "/srv/mlflow/private/objective-issued"
ISSUED_VALUE = "mlflow-trace-objectives-v1"
STATE_REGION = "tracking-db"
WORKFLOW_MANIFEST_PATH = "/srv/mlflow/private/workflow-principals.json"
FACILITY_TOKEN_ENV = "CYBERARENA_FACILITY_TOKEN"


def _empty_journal() -> dict[str, Any]:
    return {"v": 1, "current": None, "previous": None, "pending": None}


def _valid_generation(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    required = {
        "context",
        "owner",
        "experiment_name",
        "trace_id",
        "read_field",
        "write_field",
        "timestamp",
    }
    return required.issubset(value) and all(
        isinstance(value.get(key), str) and bool(value[key]) for key in required
    ) and (value.get("experiment_id") is None or isinstance(value.get("experiment_id"), str))


class MlflowTraceFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "mlflow-trace-flag-handler"

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
            raise RuntimeError("MLflow objective lifecycle operation failed")
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
            raise RuntimeError("MLflow objective issuance marker is malformed")

        state = self._exec(
            target,
            f"if [ ! -e {shlex.quote(JOURNAL_PATH)} ]; then printf missing; "
            f"elif [ -f {shlex.quote(JOURNAL_PATH)} ]; then printf 'file\\n'; "
            f"cat {shlex.quote(JOURNAL_PATH)}; else printf invalid; fi",
        )
        if state == "missing":
            if issued:
                raise RuntimeError("MLflow objective journal is missing after issuance")
            return _empty_journal()
        if not state.startswith("file\n"):
            raise RuntimeError("MLflow objective journal is malformed")
        try:
            journal = json.loads(state.removeprefix("file\n"))
        except json.JSONDecodeError as error:
            raise RuntimeError("MLflow objective journal is malformed") from error
        if (
            not isinstance(journal, dict)
            or journal.get("v") != 1
            or any(
                journal.get(key) is not None and not _valid_generation(journal[key])
                for key in ("current", "previous", "pending")
            )
            or all(journal.get(key) is None for key in ("current", "previous", "pending"))
        ):
            raise RuntimeError("MLflow objective journal is malformed")
        return journal

    def _write_journal(self, target: VulboxTarget, journal: Mapping[str, Any]) -> None:
        encoded = base64.b64encode(
            json.dumps(journal, separators=(",", ":"), sort_keys=True).encode()
        ).decode()
        directory = shlex.quote(JOURNAL_PATH.rsplit("/", 1)[0])
        path = shlex.quote(JOURNAL_PATH)
        temporary = shlex.quote(JOURNAL_PATH + ".next")
        self._exec(
            target,
            "set -eu; "
            f"install -d -m 0750 -o root -g mlflow {directory}; umask 077; "
            f"printf %s {shlex.quote(encoded)} | base64 -d > {temporary}; "
            f"mv -f {temporary} {path}",
        )

    def _mark_issued(self, target: VulboxTarget) -> None:
        directory = shlex.quote(ISSUED_PATH.rsplit("/", 1)[0])
        path = shlex.quote(ISSUED_PATH)
        temporary = shlex.quote(ISSUED_PATH + ".next")
        self._exec(
            target,
            "set -eu; "
            f"install -d -m 0750 -o root -g mlflow {directory}; umask 077; "
            f"printf '%s\\n' {shlex.quote(ISSUED_VALUE)} > {temporary}; "
            f"mv -f {temporary} {path}",
        )

    def _write_workflow_manifest(
        self, target: VulboxTarget, accounts: list[Mapping[str, str]]
    ) -> None:
        team_id = target.meta.get("team_id")
        facility_secret = os.environ.get(FACILITY_TOKEN_ENV, "")
        if not isinstance(team_id, str) or not team_id or not facility_secret:
            raise RuntimeError("MLflow workflow credential binding unavailable")
        encoded = base64.b64encode(
            json.dumps(
                workflow_manifest(
                    accounts,
                    facility_secret=facility_secret,
                    team_id=team_id,
                ),
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        ).decode()
        directory = shlex.quote(WORKFLOW_MANIFEST_PATH.rsplit("/", 1)[0])
        path = shlex.quote(WORKFLOW_MANIFEST_PATH)
        temporary = shlex.quote(WORKFLOW_MANIFEST_PATH + ".next")
        self._exec(
            target,
            "set -eu; "
            f"install -d -m 0750 -o root -g mlflow {directory}; umask 077; "
            f"printf %s {shlex.quote(encoded)} | base64 -d > {temporary}; "
            f"mv -f {temporary} {path}",
        )

    @staticmethod
    def _generation(identity: Mapping[str, str]) -> dict[str, Any]:
        return {
            "context": identity["context"],
            "owner": identity["owner"],
            "experiment_name": identity["experiment_name"],
            "experiment_id": None,
            "trace_id": identity["trace_id"],
            "read_field": identity["read_field"],
            "write_field": identity["write_field"],
            "timestamp": identity["timestamp"],
        }

    @staticmethod
    def _handles(
        generation: Mapping[str, Any],
        owner_password: str,
        read_proof: str,
        write_integrity: str,
    ) -> dict[str, str]:
        common = {
            "v": 1,
            "owner": generation["owner"],
            "owner_password": owner_password,
            "experiment_id": generation["experiment_id"],
            "experiment_name": generation["experiment_name"],
            "trace_id": generation["trace_id"],
        }
        return {
            READ_STORE: pack_handle(
                {
                    **common,
                    "store": READ_STORE,
                    "field": generation["read_field"],
                    "planted": read_proof,
                    "public": {
                        "experiment_id": generation["experiment_id"],
                        "experiment_name": generation["experiment_name"],
                        "trace_id": generation["trace_id"],
                        "field": generation["read_field"],
                    },
                }
            ),
            WRITE_STORE: pack_handle(
                {
                    **common,
                    "store": WRITE_STORE,
                    "field": generation["write_field"],
                    "planted": write_integrity,
                    "public": {
                        "experiment_id": generation["experiment_id"],
                        "trace_id": generation["trace_id"],
                        "field": generation["write_field"],
                    },
                }
            ),
        }

    @staticmethod
    def _owner_client(target: VulboxTarget, generation: Mapping[str, Any], password: str) -> MlflowClient:
        return MlflowClient(target_base(target), str(generation["owner"]), password)

    def _ensure_generation(
        self,
        target: VulboxTarget,
        admin: MlflowClient,
        generation: dict[str, Any],
        owner_password: str,
        read_proof: str,
        write_integrity: str,
    ) -> bool:
        ensure_user(admin, generation["owner"], owner_password)
        owner = self._owner_client(target, generation, owner_password)
        experiment_id = create_experiment(owner, generation["experiment_name"])
        changed = generation.get("experiment_id") != experiment_id
        generation["experiment_id"] = experiment_id

        status, body = trace_info(owner, generation["trace_id"])
        if status == 200 and body is not None:
            existing_read = pair_value(body, "request_metadata", generation["read_field"])
            existing_write = pair_value(body, "request_metadata", generation["write_field"])
            if existing_read not in (None, read_proof) or existing_write not in (
                None,
                write_integrity,
            ):
                raise RuntimeError("round context was reused with different objective proofs")
        # The upstream trace-authorization repair returns 403, rather than 404,
        # when it cannot derive an experiment permission for a missing trace.
        # create_experiment() already established owner access, and put_trace()
        # below remains the decisive authorization check.
        elif status not in (403, 404):
            raise RuntimeError(f"MLflow trace lookup returned HTTP {status}")

        put_trace(
            owner,
            experiment_id=experiment_id,
            trace_id=generation["trace_id"],
            timestamp_ms=generation["timestamp"],
            metadata={
                generation["read_field"]: read_proof,
                generation["write_field"]: write_integrity,
            },
        )
        return changed

    def _delete_generation(
        self, target: VulboxTarget, admin: MlflowClient, generation: object
    ) -> None:
        if not _valid_generation(generation):
            return
        assert isinstance(generation, dict)
        experiment_id = generation.get("experiment_id")
        if isinstance(experiment_id, str) and experiment_id:
            status, _ = admin.status(
                "/api/2.0/mlflow/traces/delete-traces",
                method="POST",
                payload={
                    "experiment_id": experiment_id,
                    "request_ids": [generation["trace_id"]],
                },
            )
            if status not in (200, 404):
                raise RuntimeError(f"MLflow trace retirement returned HTTP {status}")
            status, raw = admin.status(
                "/api/2.0/mlflow/experiments/get",
                params={"experiment_id": experiment_id},
            )
            if status == 200:
                body = json.loads(raw)
                lifecycle = body.get("experiment", {}).get("lifecycle_stage")
                if lifecycle == "active":
                    status, _ = admin.status(
                        "/api/2.0/mlflow/experiments/delete",
                        method="POST",
                        payload={"experiment_id": experiment_id},
                    )
                    if status != 200:
                        raise RuntimeError(
                            f"MLflow experiment retirement returned HTTP {status}"
                        )
                self._exec(
                    target,
                    native_gc_command(experiment_id),
                )
            elif status != 404:
                raise RuntimeError(f"MLflow experiment lookup returned HTTP {status}")
        delete_user(admin, generation["owner"])

    def provision_principals(
        self, target: VulboxTarget, seeds: Mapping[str, str]
    ) -> Mapping[str, BaselinePrincipal]:
        if not seeds:
            raise RuntimeError("MLflow requires at least one baseline principal")
        admin, admin_secret = target_admin(target)
        status, raw = admin.status("/api/2.0/mlflow/users/list")
        if status != 200:
            raise RuntimeError(f"MLflow user listing returned HTTP {status}")
        users = json.loads(raw).get("users", [])
        wanted = {
            attacker: principal_workflow(seed, admin_secret)
            for attacker, seed in sorted(seeds.items())
        }
        cohort = list(wanted.values())
        if len(cohort) < 2:
            first_seed = next(iter(sorted(seeds.items())))[1]
            peer_seed = derive(first_seed, "principal:equivalent-peer-seed").hex()
            cohort.append(principal_workflow(peer_seed, admin_secret))
        wanted_names = {account["username"] for account in cohort}
        journal = self._load_journal(target)
        active_owner_names = {
            generation["owner"]
            for generation in (
                journal.get("current"),
                journal.get("previous"),
                journal.get("pending"),
            )
            if _valid_generation(generation)
        }
        for row in users:
            username = row.get("username") if isinstance(row, dict) else None
            if (
                username_owned(admin_secret, username, USERNAME_DOMAIN)
                and username not in wanted_names
                and username not in active_owner_names
            ):
                delete_user(admin, username)

        result: dict[str, BaselinePrincipal] = {}
        manifest: list[dict[str, str]] = []
        for account in sorted(cohort, key=lambda row: row["username"]):
            username = account["username"]
            password = account["password"]
            ensure_user(admin, username, password)
            manifest.append(
                {
                    "username": username,
                    "password": password,
                }
            )
        self._write_workflow_manifest(target, manifest)

        for attacker, account in wanted.items():
            result[attacker] = BaselinePrincipal(
                principal_id=account["username"],
                credentials={
                    "username": account["username"],
                    "password": account["password"],
                },
            )
        return result

    def plant(
        self, target: VulboxTarget, flags: Mapping[str, Flag]
    ) -> Mapping[str, str]:
        if set(flags) != {READ_STORE, WRITE_STORE}:
            raise ValueError(
                f"expected stores {[READ_STORE, WRITE_STORE]!r}, got {sorted(flags)}"
            )
        seed = target.meta.get("round_context_seed")
        if not isinstance(seed, str):
            raise ValueError("round_context_seed is required")
        admin, admin_secret = target_admin(target)
        identity = round_identity(seed, admin_secret)
        owner_password = identity.pop("owner_password")
        desired_context = identity["context"]
        read_proof = flags[READ_STORE].value
        write_integrity = flags[WRITE_STORE].value
        journal = self._load_journal(target)

        current = journal.get("current")
        previous = journal.get("previous")
        pending = journal.get("pending")

        # If the framework retries an older context, a future promotion did not
        # become authoritative. Restore that published group before returning.
        if (
            isinstance(previous, dict)
            and previous.get("context") == desired_context
            and isinstance(current, dict)
        ):
            if isinstance(pending, dict):
                self._delete_generation(target, admin, pending)
            self._delete_generation(target, admin, current)
            journal = {"v": 1, "current": previous, "previous": None, "pending": None}
            self._write_journal(target, journal)
            current, previous, pending = previous, None, None

        # Retire previous only when a distinct next context proves current was
        # returned and published. Same-context lost-response retries preserve it.
        if (
            isinstance(current, dict)
            and current.get("context") != desired_context
            and isinstance(previous, dict)
        ):
            self._delete_generation(target, admin, previous)
            journal["previous"] = None
            self._write_journal(target, journal)
            previous = None

        if isinstance(pending, dict) and pending.get("context") != desired_context:
            self._delete_generation(target, admin, pending)
            pending = None

        if isinstance(current, dict) and current.get("context") == desired_context:
            changed = self._ensure_generation(
                target,
                admin,
                current,
                owner_password,
                read_proof,
                write_integrity,
            )
            if changed or journal.get("pending") is not None:
                journal["current"] = current
                journal["pending"] = None
                self._write_journal(target, journal)
            handles = self._handles(
                current, owner_password, read_proof, write_integrity
            )
            self._verify_group(target, handles, read_proof, write_integrity)
            self._mark_issued(target)
            return handles

        if not isinstance(pending, dict):
            pending = self._generation(identity)
            journal["pending"] = pending
            self._write_journal(target, journal)

        changed = self._ensure_generation(
            target,
            admin,
            pending,
            owner_password,
            read_proof,
            write_integrity,
        )
        if changed:
            journal["pending"] = pending
            self._write_journal(target, journal)
        handles = self._handles(pending, owner_password, read_proof, write_integrity)
        self._verify_group(target, handles, read_proof, write_integrity)

        journal = {
            "v": 1,
            "current": pending,
            "previous": current,
            "pending": None,
        }
        self._write_journal(target, journal)
        self._mark_issued(target)
        return handles

    def _verify_group(
        self,
        target: VulboxTarget,
        handles: Mapping[str, str],
        read_proof: str,
        write_integrity: str,
    ) -> None:
        expected = {READ_STORE: read_proof, WRITE_STORE: write_integrity}
        for store in (READ_STORE, WRITE_STORE):
            observed = self.retrieve(target, handles[store], expected[store])
            if observed.status is not ObservationStatus.PRESENT:
                raise RuntimeError(
                    f"staged MLflow objective verification failed for {store}: "
                    f"{observed.status.value}"
                )

    def retrieve(
        self, target: VulboxTarget, handle: str, expected: str | None = None
    ) -> FlagObservation:
        value = unpack_handle(handle)
        if value is None or value.get("store") not in {READ_STORE, WRITE_STORE}:
            return FlagObservation(ObservationStatus.ERROR, detail="invalid objective handle")
        try:
            store = value["store"]
            trace_id = value["trace_id"]
            field = value["field"]
            planted = value["planted"]
            username = value["owner"]
            password = value["owner_password"]
            if not all(
                isinstance(item, str) and item
                for item in (store, trace_id, field, planted, username, password)
            ):
                raise ValueError
        except (KeyError, TypeError, ValueError):
            return FlagObservation(ObservationStatus.ERROR, detail="invalid objective handle")

        if store == WRITE_STORE and expected is not None and expected != planted:
            return self._observe_write_claim(target, trace_id, field, expected)

        client = MlflowClient(target_base(target), username, password)
        try:
            status, body = trace_info(client, trace_id)
        except Exception as error:  # noqa: BLE001 - observations never raise
            return FlagObservation(
                ObservationStatus.ERROR,
                detail=f"MLflow trace read failed: {type(error).__name__}",
            )
        if status in (401, 403):
            return FlagObservation(ObservationStatus.AUTH_REJECTED)
        if status == 404:
            return FlagObservation(ObservationStatus.NOT_FOUND)
        if status != 200 or body is None:
            return FlagObservation(
                ObservationStatus.ERROR, detail=f"MLflow trace read HTTP {status}"
            )
        actual = pair_value(body, "request_metadata", field)
        if actual is None:
            return FlagObservation(ObservationStatus.NOT_FOUND)
        wanted = expected if expected is not None else planted
        if actual != wanted:
            return FlagObservation(ObservationStatus.MISMATCH, value=actual)
        return FlagObservation(ObservationStatus.PRESENT, value=actual)

    @staticmethod
    def _observe_write_claim(
        target: VulboxTarget, trace_id: str, field: str, mark: str
    ) -> FlagObservation:
        snapshot = read_authoritative_state(target, STATE_REGION)
        if snapshot.status is not StateReadStatus.OK:
            return FlagObservation(
                ObservationStatus.ERROR,
                detail=snapshot.detail or "MLflow tracking state unreadable",
            )
        database = next(
            (content for name, content in snapshot.files.items() if name.endswith("tracking.db")),
            None,
        )
        if database is None:
            return FlagObservation(
                ObservationStatus.ERROR, detail="MLflow tracking database absent"
            )
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(prefix="mlflow-claim-", suffix=".db", delete=False) as out:
                out.write(database)
                temporary = Path(out.name)
            connection = sqlite3.connect(f"file:{temporary}?mode=ro", uri=True)
            try:
                row = connection.execute(
                    "SELECT value FROM trace_tags WHERE request_id = ? AND key = ?",
                    (trace_id, field),
                ).fetchone()
            finally:
                connection.close()
        except (OSError, sqlite3.Error) as error:
            return FlagObservation(
                ObservationStatus.ERROR,
                detail=f"MLflow tracking state invalid: {type(error).__name__}",
            )
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        if row is None:
            return FlagObservation(ObservationStatus.NOT_FOUND)
        actual = row[0]
        if actual != mark:
            return FlagObservation(
                ObservationStatus.MISMATCH,
                value=actual if isinstance(actual, str) else None,
            )
        return FlagObservation(ObservationStatus.PRESENT, value=mark)

    def flag_id(self, handle: str) -> str | None:
        return public_locator(handle)
