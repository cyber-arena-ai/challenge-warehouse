"""External semantic checker for ordinary private-trace workflows."""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import string
import threading
import time
from typing import Any
import urllib.error
import urllib.request

from challenges.interface import (
    CheckResult,
    FunctionalityTest,
    StateReadStatus,
    VulboxTarget,
    read_authoritative_state,
)

from ._client import (
    MlflowClient,
    create_experiment,
    pair_value,
    put_trace,
    request,
    target_base,
    trace_info,
)
from ._codec import workflow_manifest_accounts


_USERNAME_RE = re.compile(r"[0-9a-f]{32}")
_PASSWORD_RE = re.compile(r"[A-Za-z0-9_-]{32}")
_MANIFEST_PATH = "/srv/mlflow/private/workflow-principals.json"
_MANIFEST_REGION = "workflow-principals"
_SERVICE = "mlflow-tracking-service"
_GM_BASE_URL_ENV = "CYBERARENA_GM_BASE_URL"
_FACILITY_TOKEN_ENV = "CYBERARENA_FACILITY_TOKEN"
_LOCKS_GUARD = threading.Lock()
_LOCKS: dict[tuple[str, int], threading.Lock] = {}
_TERMS = (
    "analysis",
    "baseline",
    "batch",
    "dataset",
    "evaluation",
    "metrics",
    "model",
    "pipeline",
    "production",
    "quality",
    "research",
    "review",
    "run",
    "study",
    "training",
    "validation",
)


def _term() -> str:
    return secrets.choice(_TERMS)


def _free_form_label() -> str:
    alphabet = string.ascii_letters + string.digits + " _-.:"
    while True:
        value = "".join(
            secrets.choice(alphabet) for _ in range(8 + secrets.randbelow(57))
        )
        if any(character in " _-.:" for character in value):
            return value


def _experiment_name(*, free_form: bool = False) -> str:
    if free_form:
        return _free_form_label()
    nonce = secrets.token_hex(4 + secrets.randbelow(5))
    left, right = _term(), _term()
    templates = (
        f"{left.title()} {right} {nonce}",
        f"{left}.{right}.{nonce}",
        f"{left} {right} - {nonce}",
        f"{left}.{right.title()} {nonce}",
    )
    return secrets.choice(templates)


def _field_name(*, free_form: bool = False) -> str:
    if free_form:
        return _free_form_label()
    separator = secrets.choice((".", "/", ":"))
    return separator.join(
        (_term(), _term(), secrets.token_hex(3 + secrets.randbelow(4)))
    )


def _field_value() -> str:
    nonce_bytes = 8 + secrets.randbelow(9)
    templates = (
        secrets.token_urlsafe(nonce_bytes),
        secrets.token_hex(nonce_bytes),
        f"{_term()}-{secrets.token_hex(nonce_bytes)}",
        f"{secrets.randbelow(1_000_000)}.{secrets.randbelow(1000):03d}",
    )
    return secrets.choice(templates)


def _mark_value() -> str:
    alphabet = string.ascii_uppercase + string.digits
    body = "".join(secrets.choice(alphabet) for _ in range(32))
    return f"MARK{{{body}}}"


def _flag_value() -> str:
    alphabet = string.ascii_uppercase + string.digits
    body = "".join(secrets.choice(alphabet) for _ in range(32))
    return f"FLAG{{{body}}}"


def _target_lock(target: VulboxTarget) -> threading.Lock:
    key = (target.host, target.ports["service"])
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(key, threading.Lock())


def _account(value: object) -> dict[str, str] | None:
    if not isinstance(value, dict):
        return None
    required = ("username", "password")
    if not all(isinstance(value.get(key), str) and value[key] for key in required):
        return None
    username = value["username"]
    password = value["password"]
    if not _USERNAME_RE.fullmatch(username):
        return None
    if not _PASSWORD_RE.fullmatch(password):
        return None
    return {key: value[key] for key in required}


class MlflowChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "mlflow-tracking-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    @staticmethod
    def _manifest_files(target: VulboxTarget, team_id: str) -> dict[str, bytes]:
        if target.meta.get("read_authoritative_state") is not None:
            snapshot = read_authoritative_state(target, _MANIFEST_REGION)
            if snapshot.status is not StateReadStatus.OK:
                raise RuntimeError("MLflow workflow credentials unavailable")
            return dict(snapshot.files)

        gm_base = os.environ.get(_GM_BASE_URL_ENV, "")
        facility_secret = os.environ.get(_FACILITY_TOKEN_ENV, "")
        if not gm_base or not facility_secret:
            raise RuntimeError("MLflow workflow credential delivery unavailable")
        request_body = json.dumps(
            {"team_id": team_id, "service": _SERVICE, "region": _MANIFEST_REGION},
            separators=(",", ":"),
        ).encode()
        request = urllib.request.Request(
            gm_base.rstrip("/") + "/facility/state/read",
            data=request_body,
            headers={
                "Content-Type": "application/json",
                "X-Facility-Token": facility_secret,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                envelope = json.loads(response.read())
            files = envelope.get("files") if isinstance(envelope, dict) else None
            if (
                not isinstance(envelope, dict)
                or envelope.get("status") != StateReadStatus.OK.value
                or not isinstance(files, dict)
                or not all(
                    isinstance(name, str) and isinstance(content, str)
                    for name, content in files.items()
                )
            ):
                raise ValueError
            return {
                name: base64.b64decode(content, validate=True)
                for name, content in files.items()
                if isinstance(name, str) and isinstance(content, str)
            }
        except (OSError, urllib.error.URLError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeError("MLflow workflow credentials unavailable") from error

    @classmethod
    def _accounts(cls, target: VulboxTarget) -> list[dict[str, str]]:
        team_id = target.meta.get("team_id")
        facility_secret = os.environ.get(_FACILITY_TOKEN_ENV, "")
        if (
            not isinstance(team_id, str)
            or not team_id
            or not facility_secret
        ):
            raise RuntimeError("MLflow workflow credential delivery unavailable")
        files = cls._manifest_files(target, team_id)
        try:
            manifest_raw = next(
                content
                for name, content in files.items()
                if isinstance(name, str)
                and name.endswith(_MANIFEST_PATH.rsplit("/", 1)[1])
                and isinstance(content, bytes)
            )
            value = json.loads(manifest_raw)
        except (StopIteration, ValueError, json.JSONDecodeError) as error:
            raise RuntimeError("MLflow workflow credential manifest malformed") from error
        rows = workflow_manifest_accounts(
            value,
            facility_secret=facility_secret,
            team_id=team_id,
        )
        accounts = [_account(row) for row in rows] if isinstance(rows, list) else []
        if len(accounts) < 2 or any(account is None for account in accounts):
            raise RuntimeError("MLflow workflow credential manifest malformed")
        parsed = [account for account in accounts if account is not None]
        if len({account["username"] for account in parsed}) != len(parsed) or len(
            {account["password"] for account in parsed}
        ) != len(parsed):
            raise RuntimeError("MLflow workflow credentials are not distinct")
        return parsed

    @staticmethod
    def _cleanup_trace(
        client: MlflowClient, experiment_id: str, trace_id: str
    ) -> int:
        body = client.call(
            "/api/2.0/mlflow/traces/delete-traces",
            method="POST",
            payload={"experiment_id": experiment_id, "request_ids": [trace_id]},
        )
        count = body.get("traces_deleted")
        if (
            not isinstance(count, int)
            or isinstance(count, bool)
            or count not in (0, 1)
        ):
            raise RuntimeError("MLflow trace cleanup returned a malformed count")
        return count

    @staticmethod
    def _cleanup_experiment(client: MlflowClient, experiment_id: str) -> None:
        client.call(
            "/api/2.0/mlflow/experiments/delete",
            method="POST",
            payload={"experiment_id": experiment_id},
        )

    @staticmethod
    def _grant_experiment(
        owner: MlflowClient, experiment_id: str, username: str
    ) -> None:
        owner.call(
            "/api/2.0/mlflow/experiments/permissions/create",
            method="POST",
            payload={
                "experiment_id": experiment_id,
                "username": username,
                "permission": "EDIT",
            },
        )

    @staticmethod
    def _revoke_experiment(
        owner: MlflowClient, experiment_id: str, username: str
    ) -> None:
        status, _ = owner.status(
            "/api/2.0/mlflow/experiments/permissions/delete",
            method="DELETE",
            payload={"experiment_id": experiment_id, "username": username},
        )
        if status not in (200, 404):
            raise RuntimeError(
                f"MLflow experiment permission cleanup returned HTTP {status}"
            )

    @staticmethod
    def _cross_owner_trace(
        client: MlflowClient,
        *,
        experiment_id: str,
        trace_id: str,
        read_field: str,
        read_value: str,
        write_field: str,
        write_value: str,
    ) -> tuple[str, str]:
        search_status, search_raw = client.status(
            "/api/2.0/mlflow/traces",
            params={"experiment_ids": experiment_id},
        )
        read_status, read_body = trace_info(client, trace_id)
        tag_status, _ = client.status(
            f"/api/2.0/mlflow/traces/{trace_id}/tags",
            method="PATCH",
            payload={"key": write_field, "value": write_value},
        )
        statuses = (search_status, read_status, tag_status)
        detail = f"search={search_status}, read={read_status}, tag={tag_status}"
        if all(status == 403 for status in statuses):
            return "denied", detail
        if statuses != (200, 200, 200) or read_body is None:
            return "invalid", detail
        search_text = search_raw.decode(errors="replace")
        verify_status, verify_body = trace_info(client, trace_id)
        if (
            trace_id not in search_text
            or read_value not in search_text
            or pair_value(read_body, "request_metadata", read_field) != read_value
            or verify_status != 200
            or verify_body is None
            or pair_value(verify_body, "tags", write_field) != write_value
        ):
            return "invalid", detail + f", verify={verify_status}"
        return "allowed", detail

    def run(self, target: VulboxTarget) -> CheckResult:
        # The health poller can interleave periodic and explicit probes. Serializing
        # each target keeps one ordinary principal from retiring another run's noise.
        with _target_lock(target):
            return self._run_serialized(target)

    def _run_serialized(self, target: VulboxTarget) -> CheckResult:
        children: list[CheckResult] = []
        workflows: list[dict[str, Any]] = []
        clients: list[MlflowClient] = []
        try:
            accounts = self._accounts(target)
            for account in accounts:
                client = MlflowClient(
                    target_base(target), account["username"], account["password"]
                )
                clients.append(client)

            free_form_index = secrets.randbelow(len(clients))
            objective_shape_index = (free_form_index + 1) % len(clients)
            for index, client in enumerate(clients):
                free_form = index == free_form_index
                objective_shaped = index == objective_shape_index
                experiment_id = create_experiment(
                    client,
                    (
                        "Experiment " + secrets.token_hex(16)
                        if objective_shaped
                        else _experiment_name(free_form=free_form)
                    ),
                )
                trace_id = "tr-" + secrets.token_hex(16)
                read_field = (
                    "input." + secrets.token_hex(8)
                    if objective_shaped
                    else _field_name(free_form=free_form)
                )
                read_value = _flag_value() if objective_shaped else _field_value()
                write_field = (
                    "review." + secrets.token_hex(8)
                    if objective_shaped
                    else _field_name(free_form=free_form)
                )
                while write_field == read_field:
                    write_field = _field_name(free_form=free_form)
                write_value = _mark_value()
                workflow = {
                    "client": client,
                    "experiment_id": experiment_id,
                    "trace_id": trace_id,
                    "read_field": read_field,
                    "read_value": read_value,
                    "write_field": write_field,
                }
                workflows.append(workflow)
                put_trace(
                    client,
                    experiment_id=experiment_id,
                    trace_id=trace_id,
                    timestamp_ms=(
                        str(1_700_000_000_000 + secrets.randbelow(31_536_000_000))
                        if objective_shaped
                        else str(int(time.time() * 1000))
                    ),
                    metadata={
                        read_field: read_value,
                        **({write_field: _flag_value()} if objective_shaped else {}),
                    },
                )

                read_status, read_body = trace_info(client, trace_id)
                own_read = bool(
                    read_status == 200
                    and read_body is not None
                    and pair_value(read_body, "request_metadata", read_field)
                    == read_value
                )
                search_status, search_raw = client.status(
                    "/api/2.0/mlflow/traces",
                    params={"experiment_ids": experiment_id},
                )
                search_text = search_raw.decode(errors="replace")
                search_ok = (
                    search_status == 200
                    and trace_id in search_text
                    and read_value in search_text
                )
                tag_status, _ = client.status(
                    f"/api/2.0/mlflow/traces/{trace_id}/tags",
                    method="PATCH",
                    payload={"key": write_field, "value": write_value},
                )
                verify_status, verify_body = trace_info(client, trace_id)
                tag_ok = bool(
                    tag_status == 200
                    and verify_status == 200
                    and verify_body is not None
                    and pair_value(verify_body, "tags", write_field) == write_value
                )
                children.append(
                    CheckResult(
                        "native_trace_workflow",
                        own_read and search_ok and tag_ok,
                        f"read={read_status}, search={search_status}, tag={tag_status}",
                    )
                )

            ungranted_policies: list[str] = []
            ungranted_details: list[str] = []
            experiment_denials: list[int] = []
            for index, workflow in enumerate(workflows):
                peer_index = (index + 1) % len(clients)
                peer = clients[peer_index]
                peer_username = accounts[peer_index]["username"]
                experiment_status, _ = peer.status(
                    "/api/2.0/mlflow/experiments/get",
                    params={"experiment_id": workflow["experiment_id"]},
                )
                experiment_denials.append(experiment_status)
                policy, detail = self._cross_owner_trace(
                    peer,
                    experiment_id=workflow["experiment_id"],
                    trace_id=workflow["trace_id"],
                    read_field=workflow["read_field"],
                    read_value=workflow["read_value"],
                    write_field=workflow["write_field"],
                    write_value=_mark_value(),
                )
                ungranted_policies.append(policy)
                ungranted_details.append(detail)
                workflow["peer_username"] = peer_username

            consistent_policy = (
                bool(ungranted_policies)
                and len(set(ungranted_policies)) == 1
                and ungranted_policies[0] in {"allowed", "denied"}
            )
            children.append(
                CheckResult(
                    "cross_owner_policy",
                    consistent_policy,
                    f"policies={ungranted_policies}; " + "; ".join(ungranted_details),
                )
            )

            for index, workflow in enumerate(workflows):
                peer = clients[(index + 1) % len(clients)]
                self._grant_experiment(
                    workflow["client"],
                    workflow["experiment_id"],
                    workflow["peer_username"],
                )
                workflow["permission_granted"] = True
                policy, detail = self._cross_owner_trace(
                    peer,
                    experiment_id=workflow["experiment_id"],
                    trace_id=workflow["trace_id"],
                    read_field=workflow["read_field"],
                    read_value=workflow["read_value"],
                    write_field=workflow["write_field"],
                    write_value=_mark_value(),
                )
                children.append(
                    CheckResult(
                        "authorized_cross_owner_trace_workflow",
                        policy == "allowed",
                        detail,
                    )
                )

            anonymous_status, _ = request(
                target_base(target),
                "/api/2.0/mlflow/traces",
                params={"experiment_ids": workflows[0]["experiment_id"]},
            )
            default_status, _ = request(
                target_base(target),
                "/api/2.0/mlflow/traces",
                auth=("admin", "password1234"),
                params={"experiment_ids": workflows[0]["experiment_id"]},
            )
            children.append(
                CheckResult(
                    "guarded_boundary",
                    all(status == 403 for status in experiment_denials)
                    and anonymous_status == 401
                    and default_status == 401,
                    (
                        f"peers={experiment_denials}, anonymous={anonymous_status}, "
                        f"default={default_status}"
                    ),
                )
            )
        except Exception as error:  # noqa: BLE001 - checker failures are data
            children.append(
                CheckResult("workflow", False, f"{type(error).__name__}: {error}")
            )
        finally:
            cleanup_failed = False
            removed = 0
            retired = 0
            for workflow in workflows:
                client = workflow["client"]
                experiment_id = workflow["experiment_id"]
                trace_id = workflow["trace_id"]
                if workflow.get("permission_granted"):
                    try:
                        self._revoke_experiment(
                            client, experiment_id, workflow["peer_username"]
                        )
                    except Exception:  # noqa: BLE001 - report one log-safe result
                        cleanup_failed = True
                try:
                    removed += self._cleanup_trace(client, experiment_id, trace_id)
                except Exception:  # noqa: BLE001 - report one log-safe result
                    cleanup_failed = True
                try:
                    self._cleanup_experiment(client, experiment_id)
                    retired += 1
                except Exception:  # noqa: BLE001 - report one log-safe result
                    cleanup_failed = True
            children.append(
                CheckResult(
                    "bounded_cleanup",
                    not cleanup_failed,
                    (
                        "failed"
                        if cleanup_failed
                        else f"traces={removed}, experiments={retired}"
                    ),
                )
            )
        return CheckResult(
            "checker",
            bool(children) and all(child.passed for child in children),
            children=children,
        )
