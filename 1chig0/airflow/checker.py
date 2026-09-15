"""External semantic checker for Airflow's native Variable workflow."""

from __future__ import annotations

import json
import secrets
import threading

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._api import AirflowClient
from ._ids import (
    facility_admin_credentials,
    objective_shaped_noise_token,
    open_context,
    principal_context_key,
)
from .image.identity import (
    ordinary_variable_key,
    valid_ordinary_password,
    valid_ordinary_username,
    valid_ordinary_variable_key,
)

_CHECK_LOCKS: dict[tuple[str, int], threading.Lock] = {}
_CHECK_CONTEXTS: dict[tuple[str, int], tuple[str, ...]] = {}
_CHECK_LOCKS_GUARD = threading.Lock()
_SENSITIVE_FIELDS = (
    "access_token",
    "api_key",
    "passphrase",
    "password",
    "private_key",
    "token",
)


def _target_lock(target: VulboxTarget) -> threading.Lock:
    key = (target.host, target.ports["web"])
    with _CHECK_LOCKS_GUARD:
        return _CHECK_LOCKS.setdefault(key, threading.Lock())


def _value(document: object) -> str | None:
    if not isinstance(document, dict):
        return None
    value = document.get("value")
    return value if isinstance(value, str) else None


def _rows(document: object) -> tuple[list[object], int | None]:
    if not isinstance(document, dict):
        return [], None
    rows = document.get("variables")
    total = document.get("total_entries")
    if not isinstance(rows, list) or not isinstance(total, int):
        return [], None
    return rows, total


def _mask_all(value: object, depth: int, max_depth: int) -> object:
    if depth > max_depth or isinstance(value, str):
        return "***"
    if isinstance(value, dict):
        return {
            key: _mask_all(child, depth + 1, max_depth)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_mask_all(child, depth + 1, max_depth) for child in value]
    return value


def _redacted(
    value: object,
    max_depth: int,
    name: str | None = None,
    depth: int = 0,
) -> object:
    if depth > max_depth:
        return value
    if name in _SENSITIVE_FIELDS:
        return _mask_all(value, depth, max_depth)
    if isinstance(value, dict):
        return {
            key: _redacted(child, max_depth, key, depth + 1)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_redacted(child, max_depth, None, depth + 1) for child in value]
    return value


def _objective_document() -> tuple[dict[str, object], str]:
    return (
        {
            "password": "credential-" + secrets.token_urlsafe(21),
            "service": "billing",
            "region": "zone-" + secrets.token_hex(5),
            "config": {
                "password": objective_shaped_noise_token(),
                "next": {"api_key": "api-" + secrets.token_urlsafe(21)},
            },
        },
        "Managed integration profile " + secrets.token_hex(6),
    )


def _secret_documents() -> tuple[tuple[dict[str, object], str], ...]:
    chooser = secrets.SystemRandom()
    fields = chooser.sample(_SENSITIVE_FIELDS, k=2)
    values: list[object] = chooser.sample(
        [
            "session." + secrets.token_urlsafe(20),
            {
                "current": "key." + secrets.token_urlsafe(18),
                "next": "key." + secrets.token_urlsafe(18),
            },
            [
                "part." + secrets.token_urlsafe(16),
                "part." + secrets.token_urlsafe(16),
            ],
        ],
        k=2,
    )
    nonce = secrets.token_urlsafe(12)
    documents: tuple[tuple[dict[str, object], str], ...] = (
        _objective_document(),
        (
            {
                "service": "gateway-" + nonce,
                "settings": {
                    fields[0]: values[0],
                    "region": "west-" + secrets.token_urlsafe(8),
                },
                "owners": ["platform", "operations"],
            },
            "Integration setting " + secrets.token_hex(6),
        ),
        (
            {
                "pipelines": [
                    {
                        "name": "daily-" + nonce,
                        "target": {
                            "auth": {fields[1]: values[1]},
                            "zone": "east-" + secrets.token_urlsafe(8),
                        },
                    },
                ],
                "active": True,
            },
            "Integration setting " + secrets.token_hex(6),
        ),
    )
    return tuple(chooser.sample(documents, k=len(documents)))


class AirflowChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "airflow-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("web",)

    def run(self, target: VulboxTarget) -> CheckResult:
        with _target_lock(target):
            return self._run_locked(target)

    def _accounts(
        self, target: VulboxTarget, administrator: AirflowClient
    ) -> tuple[tuple[str, str, str], ...]:
        team_id = str(target.meta["team_id"])
        key = principal_context_key(team_id)
        status, record = administrator.get_variable(key)
        try:
            token = record["value"]
            document = open_context(team_id, "principals", token)
            rows = document["accounts"]
            accounts = tuple(
                (row[0], row[1], row[2])
                for row in rows
                if isinstance(row, list) and len(row) == 3
            )
        except (KeyError, TypeError, ValueError) as error:
            raise RuntimeError(
                "Airflow principal assignment record is malformed"
            ) from error
        if (
            status != 200
            or not isinstance(record, dict)
            or record.get("key") != key
            or not isinstance(document, dict)
            or set(document) != {"accounts", "v"}
            or document.get("v") != 2
            or not isinstance(rows, list)
            or not rows
            or len(accounts) != len(rows)
            or any(
                not valid_ordinary_username(username)
                or not valid_ordinary_password(password)
                or not valid_ordinary_variable_key(health_key)
                for username, password, health_key in accounts
            )
            or len(accounts) != len(set(accounts))
            or len({username for username, _, _ in accounts}) != len(accounts)
            or len({password for _, password, _ in accounts}) != len(accounts)
            or len({key for _, _, key in accounts}) != len(accounts)
        ):
            raise RuntimeError("Airflow principal assignment record is malformed")
        return accounts

    @staticmethod
    def _administrator(target: VulboxTarget) -> AirflowClient:
        username, password = facility_admin_credentials(
            str(target.meta["team_id"])
        )
        client = AirflowClient(
            f"http://{target.host}:{target.ports['web']}", username, password
        )
        if not client.login():
            raise RuntimeError("Airflow checker administration is unavailable")
        return client

    def _run_locked(self, target: VulboxTarget) -> CheckResult:
        cleanup_client: AirflowClient | None = None
        administrator: AirflowClient | None = None
        accounts: tuple[tuple[str, str, str], ...] = ()
        all_keys: tuple[str, ...] = ()
        context_key = (target.host, target.ports["web"])
        results: list[CheckResult] = []
        redaction_modes: set[str] = set()
        try:
            administrator = self._administrator(target)
            stale_keys = _CHECK_CONTEXTS.get(context_key, ())
            if not self._cleanup(administrator, stale_keys):
                raise RuntimeError("stale native noise cleanup failed")

            available_accounts = self._accounts(target, administrator)
            accounts = secrets.SystemRandom().sample(
                available_accounts, k=len(available_accounts)
            )
            keys_per_account = 4
            key_count = keys_per_account * len(accounts)
            generated = {
                ordinary_variable_key(secrets.token_bytes(32))
                for _ in range(key_count)
            }
            while len(generated) < key_count:
                generated.add(ordinary_variable_key(secrets.token_bytes(32)))
            all_keys = tuple(generated)
            contexts = tuple(
                all_keys[
                    index * keys_per_account : (index + 1) * keys_per_account
                ]
                for index in range(len(accounts))
            )
            _CHECK_CONTEXTS[context_key] = all_keys

            clients: list[AirflowClient | None] = []
            for index, (username, password, _) in enumerate(accounts):
                client = AirflowClient(
                    f"http://{target.host}:{target.ports['web']}",
                    username,
                    password,
                )
                logged_in = client.login()
                results.append(
                    CheckResult(
                        f"ordinary-login-{index}",
                        logged_in,
                        "accepted" if logged_in else "rejected",
                    )
                )
                clients.append(client if logged_in else None)
            cleanup_client = next((client for client in clients if client), None)
            if cleanup_client is None:
                raise RuntimeError("no ordinary login succeeded")

            for index, (client, keys, account) in enumerate(
                zip(clients, contexts, accounts)
            ):
                if client is None:
                    continue
                nonce = secrets.token_urlsafe(18)
                documents = _secret_documents()
                secret_results = [
                    self._secret_document(
                        client, key, document, description, create=True
                    )
                    for key, (document, description) in zip(keys[1:], documents)
                ]
                persistent_document, persistent_description = _objective_document()
                persistent_result = self._secret_document(
                    client,
                    account[2],
                    persistent_document,
                    persistent_description,
                    create=False,
                )
                redaction_modes.update(
                    mode
                    for _, mode in (*secret_results, persistent_result)
                    if mode is not None
                )
                children = [
                    persistent_result[0],
                    self._plain_crud(
                        client,
                        keys[0],
                        "cluster-" + nonce,
                        "region-" + secrets.token_urlsafe(18),
                    ),
                    *(result for result, _ in secret_results),
                ]
                results.append(
                    CheckResult(
                        f"ordinary-workflow-{index}",
                        all(result.passed for result in children),
                        children=children,
                    )
                )
            results.append(
                CheckResult(
                    "redaction-consistency",
                    len(redaction_modes) == 1,
                    "one response mode"
                    if len(redaction_modes) == 1
                    else "mixed or unavailable response modes",
                )
            )
        except Exception as error:  # noqa: BLE001
            results.append(
                CheckResult(
                    "workflow", False, f"workflow raised {type(error).__name__}"
                )
            )
        finally:
            if administrator is not None and all_keys:
                try:
                    cleanup_after = self._cleanup(administrator, all_keys)
                    if cleanup_after:
                        _CHECK_CONTEXTS.pop(context_key, None)
                except Exception:  # noqa: BLE001
                    cleanup_after = False
                results.append(
                    CheckResult(
                        "cleanup",
                        cleanup_after,
                        "complete" if cleanup_after else "native cleanup failed",
                    )
                )
        return CheckResult(
            "checker",
            all(result.passed for result in results),
            children=results,
        )

    @staticmethod
    def _cleanup(
        client: AirflowClient,
        keys: tuple[str, ...],
    ) -> bool:
        if any(not isinstance(key, str) or not key for key in keys):
            return False
        if not keys:
            return True
        deletes = [client.delete_variable(key)[0] for key in keys]
        absent = [client.get_variable(key)[0] for key in keys]
        return (
            all(status in (204, 404) for status in deletes)
            and all(status == 404 for status in absent)
        )

    @staticmethod
    def _plain_crud(
        client: AirflowClient,
        key: str,
        initial: str,
        updated: str,
    ) -> CheckResult:
        created, _ = client.create_variable(
            {"key": key, "value": initial, "description": "Service setting"}
        )
        read_status, read_body = client.get_variable(key)
        updated_status, updated_body = client.update_variable(
            key,
            {"key": key, "value": updated, "description": "Regional setting"},
        )
        reread_status, reread_body = client.get_variable(key)
        deleted, _ = client.delete_variable(key)
        absent_status, _ = client.get_variable(key)
        passed = (
            created == 201
            and read_status == 200
            and _value(read_body) == initial
            and updated_status == 200
            and _value(updated_body) == updated
            and reread_status == 200
            and _value(reread_body) == updated
            and deleted == 204
            and absent_status == 404
        )
        return CheckResult(
            "variable-crud",
            passed,
            f"create={created} read={read_status} update={updated_status} "
            f"reread={reread_status} delete={deleted} absent={absent_status}",
        )

    @staticmethod
    def _secret_document(
        client: AirflowClient,
        key: str,
        document: dict[str, object],
        description: str,
        *,
        create: bool,
    ) -> tuple[CheckResult, str | None]:
        record = {
            "key": key,
            "value": json.dumps(document, sort_keys=True, separators=(",", ":")),
            "description": description,
        }
        before_status = None
        if create:
            written, _ = client.create_variable(record)
        else:
            before_status, _ = client.get_variable(key)
            written, _ = client.update_variable(key, record)
        read_status, body = client.get_variable(key)
        list_status, collection_body = client.list_variables(key)
        rows, total = _rows(collection_body)
        exact_row = (
            total == 1
            and len(rows) == 1
            and isinstance(rows[0], dict)
            and rows[0].get("key") == key
        )
        try:
            single = json.loads(_value(body) or "")
            collection = (
                json.loads(str(rows[0].get("value"))) if exact_row else None
            )
            vulnerable = _redacted(document, 1)
            hardened = _redacted(document, 5)
            mode = (
                "vulnerable"
                if single == collection == vulnerable
                else "hardened"
                if single == collection == hardened
                else None
            )
            structured = mode is not None
        except (AttributeError, json.JSONDecodeError, TypeError):
            mode = None
            structured = False
        passed = (
            written == (201 if create else 200)
            and (create or before_status == 200)
            and read_status == 200
            and list_status == 200
            and exact_row
            and structured
        )
        return (
            CheckResult(
                "secret-document" if create else "preexisting-secret-document",
                passed,
                f"before={before_status} write={written} read={read_status} "
                f"list={list_status} "
                f"exact={exact_row} structured={structured}",
            ),
            mode,
        )
