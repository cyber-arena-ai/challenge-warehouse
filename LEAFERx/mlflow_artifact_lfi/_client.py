"""Small standard-library client for MLflow's authenticated REST API."""

from __future__ import annotations

import base64
import json
import shlex
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from challenges.interface import VulboxTarget


def native_gc_command(experiment_id: str) -> str:
    """Build a fixed cleanup command that reads auth only inside the target."""
    inner = (
        "export MLFLOW_TRACKING_USERNAME=admin; "
        "export MLFLOW_TRACKING_PASSWORD=$(cat "
        "/srv/mlflow/private/admin-password); "
        "exec mlflow gc "
        "--backend-store-uri sqlite:////srv/mlflow/state/tracking.db "
        "--tracking-uri http://127.0.0.1:5000 "
        f"--experiment-ids {shlex.quote(experiment_id)}"
    )
    return "runuser -u mlflow -- /bin/sh -c " + shlex.quote(inner)


def target_base(target: VulboxTarget) -> str:
    return f"http://{target.host}:{target.ports['service']}"


def request(
    base: str,
    path: str,
    *,
    method: str = "GET",
    auth: tuple[str, str] | None = None,
    payload: dict[str, Any] | None = None,
    params: dict[str, str] | None = None,
) -> tuple[int, bytes]:
    query = "?" + urllib.parse.urlencode(params) if params else ""
    headers: dict[str, str] = {}
    if auth is not None:
        raw = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        headers["Authorization"] = f"Basic {raw}"
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload, separators=(",", ":")).encode()
    req = urllib.request.Request(
        base.rstrip("/") + path + query,
        data=data,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def document(raw: bytes, operation: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"{operation} returned malformed JSON") from error
    if not isinstance(value, dict):
        raise RuntimeError(f"{operation} returned malformed JSON")
    return value


class MlflowClient:
    def __init__(self, base: str, username: str, password: str) -> None:
        self.base = base
        self.auth = (username, password)

    def call(
        self,
        path: str,
        *,
        method: str = "GET",
        payload: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
        expected: tuple[int, ...] = (200,),
    ) -> dict[str, Any]:
        status, raw = request(
            self.base,
            path,
            method=method,
            auth=self.auth,
            payload=payload,
            params=params,
        )
        if status not in expected:
            raise RuntimeError(f"MLflow {method} {path} returned HTTP {status}")
        return document(raw, f"{method} {path}") if raw else {}

    def status(
        self,
        path: str,
        *,
        method: str = "GET",
        payload: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
    ) -> tuple[int, bytes]:
        return request(
            self.base,
            path,
            method=method,
            auth=self.auth,
            payload=payload,
            params=params,
        )


def target_admin(target: VulboxTarget) -> tuple[MlflowClient, str]:
    exec_in = target.meta.get("exec_in_container")
    if exec_in is None:
        raise RuntimeError("no facility exec bridge")
    rc, output = exec_in(target.host, "cat /srv/mlflow/private/admin-password")
    password = (output or "").strip()
    if rc != 0 or len(password) < 24:
        raise RuntimeError("MLflow administration credential unavailable")
    return MlflowClient(target_base(target), "admin", password), password


def ensure_user(admin: MlflowClient, username: str, password: str) -> None:
    status, _ = admin.status(
        "/api/2.0/mlflow/users/get", params={"username": username}
    )
    if status == 404:
        admin.call(
            "/api/2.0/mlflow/users/create",
            method="POST",
            payload={"username": username, "password": password},
        )
        return
    if status != 200:
        raise RuntimeError(f"MLflow user lookup returned HTTP {status}")
    admin.call(
        "/api/2.0/mlflow/users/update-password",
        method="PATCH",
        payload={"username": username, "password": password},
    )


def delete_user(admin: MlflowClient, username: str) -> None:
    status, _ = admin.status(
        "/api/2.0/mlflow/users/get", params={"username": username}
    )
    if status == 404:
        return
    if status != 200:
        raise RuntimeError(f"MLflow user lookup returned HTTP {status}")
    admin.call(
        "/api/2.0/mlflow/users/delete",
        method="DELETE",
        payload={"username": username},
    )


def create_experiment(client: MlflowClient, name: str) -> str:
    status, raw = client.status(
        "/api/2.0/mlflow/experiments/get-by-name",
        params={"experiment_name": name},
    )
    if status == 200:
        experiment = document(raw, "experiment lookup").get("experiment", {})
        if isinstance(experiment, dict) and experiment.get("lifecycle_stage") == "active":
            return str(experiment["experiment_id"])
        raise RuntimeError("existing MLflow experiment is not active")
    if status != 404:
        raise RuntimeError(f"MLflow experiment lookup returned HTTP {status}")
    body = client.call(
        "/api/2.0/mlflow/experiments/create",
        method="POST",
        payload={"name": name},
    )
    experiment_id = body.get("experiment_id")
    if not isinstance(experiment_id, str) or not experiment_id:
        raise RuntimeError("MLflow experiment creation omitted its id")
    return experiment_id


def put_trace(
    client: MlflowClient,
    *,
    experiment_id: str,
    trace_id: str,
    timestamp_ms: str,
    metadata: dict[str, str],
    tags: dict[str, str] | None = None,
) -> None:
    seconds, millis = divmod(int(timestamp_ms), 1000)
    from datetime import datetime, timezone

    stamp = datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    request_time = f"{stamp}.{millis:03d}Z"
    client.call(
        "/api/3.0/mlflow/traces",
        method="POST",
        payload={
            "trace": {
                "trace_info": {
                    "trace_id": trace_id,
                    "trace_location": {
                        "type": "MLFLOW_EXPERIMENT",
                        "mlflow_experiment": {"experiment_id": experiment_id},
                    },
                    "request_time": request_time,
                    "execution_duration": "0.010s",
                    "state": "OK",
                    "trace_metadata": metadata,
                    "tags": tags or {},
                },
                "spans": [],
            }
        },
    )


def trace_info(client: MlflowClient, trace_id: str) -> tuple[int, dict[str, Any] | None]:
    status, raw = client.status(f"/api/2.0/mlflow/traces/{trace_id}/info")
    if status != 200:
        return status, None
    return status, document(raw, "trace read")


def pair_value(body: dict[str, Any], collection: str, key: str) -> str | None:
    info = body.get("trace_info")
    if not isinstance(info, dict):
        return None
    rows = info.get(collection)
    if not isinstance(rows, list):
        return None
    for row in rows:
        if isinstance(row, dict) and row.get("key") == key:
            value = row.get("value")
            return value if isinstance(value, str) else None
    return None
