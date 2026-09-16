"""External legitimate-workflow checker for etcd's guarded keyspace."""

from __future__ import annotations

import secrets
import string

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._client import (
    authenticate,
    b64,
    decoded_values,
    delete_key,
    document,
    put_key,
    range_key,
    request,
    target_base,
)
from ._codec import checker_principals, principal_prefix


_PROOF_ALPHABET = string.ascii_uppercase + string.digits


def _noise_value() -> str:
    """Return fresh, non-scoring data with the same shape as a proof token."""
    body = "".join(secrets.choice(_PROOF_ALPHABET) for _ in range(32))
    return f"FLAG{{{body}}}"


def _range_operation(key: str) -> dict:
    return {"request_range": {"key": b64(key)}}


def _put_operation(key: str, value: str) -> dict:
    return {"request_put": {"key": b64(key), "value": b64(value)}}


def _delete_operation(key: str) -> dict:
    return {"request_delete_range": {"key": b64(key)}}


def _value_compare(key: str, value: str) -> dict:
    return {
        "key": b64(key),
        "result": "EQUAL",
        "target": "VALUE",
        "value": b64(value),
    }


def _nested(transaction: dict, depth: int) -> dict:
    operation = {"request_txn": transaction}
    for _ in range(depth - 1):
        operation = {"request_txn": {"success": [operation]}}
    return operation


def _fresh_key(prefix: str) -> str:
    return f"{prefix}/{secrets.token_hex(6 + secrets.randbelow(7))}"


def _require_document(status: int, raw: bytes, operation: str) -> dict:
    return document(status, raw, operation)


def _require_values(
    base: str, token: str, key: str, expected: list[str]
) -> None:
    status, raw = range_key(base, token, key)
    response = _require_document(status, raw, "allowed range")
    if not isinstance(response.get("header"), dict):
        raise RuntimeError("allowed range omitted native response header")
    if decoded_values(raw) != expected:
        raise RuntimeError("allowed range returned the wrong fresh value set")


def _delete_checked(base: str, token: str, key: str) -> None:
    status, raw = delete_key(base, token, key)
    _require_document(status, raw, "health record cleanup")


def _cleanup(base: str, token: str, keys: list[str]) -> None:
    errors: list[str] = []
    for key in keys:
        try:
            _delete_checked(base, token, key)
        except Exception as error:  # noqa: BLE001 — report every owned key
            errors.append(type(error).__name__)
    if errors:
        raise RuntimeError("health record cleanup failed: " + ",".join(errors))


def _account(target: VulboxTarget) -> tuple[str, str]:
    team_id = target.meta.get("team_id")
    if not isinstance(team_id, str) or not team_id:
        raise RuntimeError("target identity unavailable")
    return secrets.choice(checker_principals(team_id))


def _exercise(target: VulboxTarget) -> None:
    base = target_base(target)
    username, password = _account(target)
    token = authenticate(base, username, password)
    nonce = secrets.token_hex(12)
    prefix = principal_prefix(username) + nonce
    random = secrets.SystemRandom()
    keys = [_fresh_key(prefix) for _ in range(8)]
    random.shuffle(keys)
    (
        source_key,
        read_key,
        derived_key,
        retired_key,
        true_key,
        true_trap_key,
        false_key,
        false_trap_key,
    ) = keys
    source_value = _noise_value()
    read_value = _noise_value()
    derived_value = _noise_value()
    retired_value = _noise_value()
    true_value = _noise_value()
    false_value = _noise_value()
    protected_key = f"/services/production/{nonce}/credentials/database-password"
    owned = [
        source_key,
        read_key,
        derived_key,
        retired_key,
        true_key,
        true_trap_key,
        false_key,
        false_trap_key,
    ]
    failure: Exception | None = None

    try:
        status, _ = range_key(base, token, protected_key)
        if status != 403:
            raise RuntimeError(f"direct protected range returned HTTP {status}")

        for key, value in (
            (source_key, source_value),
            (read_key, read_value),
            (retired_key, retired_value),
        ):
            status, raw = put_key(base, token, key, value)
            _require_document(status, raw, "allowed put")
        _require_values(base, token, source_key, [source_value])

        mixed_operations = [
            _range_operation(source_key),
            _put_operation(derived_key, derived_value),
            _delete_operation(retired_key),
        ]
        random.shuffle(mixed_operations)
        transactions = [
            {"success": [_nested({"success": [_range_operation(read_key)]}, 1)]},
            {
                "success": [
                    _nested(
                        {
                            "compare": [_value_compare(source_key, source_value)],
                            "success": [_put_operation(true_key, true_value)],
                            "failure": [
                                _put_operation(true_trap_key, _noise_value())
                            ],
                        },
                        random.randrange(1, 3),
                    )
                ]
            },
            {
                "success": [
                    _nested(
                        {
                            "compare": [_value_compare(source_key, _noise_value())],
                            "success": [
                                _put_operation(false_trap_key, _noise_value())
                            ],
                            "failure": [_put_operation(false_key, false_value)],
                        },
                        random.randrange(1, 3),
                    )
                ]
            },
            {
                "success": [
                    _nested(
                        {"success": mixed_operations},
                        random.randrange(1, 3),
                    )
                ]
            },
        ]
        for _ in range(random.randrange(4)):
            transactions.append(
                {
                    "success": [
                        _nested(
                            {
                                "success": [
                                    _range_operation(
                                        random.choice((source_key, read_key))
                                    )
                                ]
                            },
                            random.randrange(1, 4),
                        )
                    ]
                }
            )
        random.shuffle(transactions)
        values: list[str] = []
        for transaction in transactions:
            status, raw = request(
                base,
                "/v3/kv/txn",
                transaction,
                token=token,
            )
            response = _require_document(
                status, raw, "allowed nested transaction"
            )
            if not isinstance(response.get("header"), dict) or not isinstance(
                response.get("responses"), list
            ):
                raise RuntimeError(
                    "nested transaction omitted native response fields"
                )
            values.extend(decoded_values(raw))
        if source_value not in values or read_value not in values:
            raise RuntimeError("nested transaction did not return its fresh inputs")
        _require_values(base, token, derived_key, [derived_value])
        _require_values(base, token, retired_key, [])
        _require_values(base, token, true_key, [true_value])
        _require_values(base, token, true_trap_key, [])
        _require_values(base, token, false_key, [false_value])
        _require_values(base, token, false_trap_key, [])
    except Exception as error:  # noqa: BLE001 — cleanup follows every failure
        failure = error

    _cleanup(base, token, owned)
    if failure is not None:
        raise failure


class EtcdChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "etcd-configuration-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        try:
            _exercise(target)
            return CheckResult(
                "checker", True, "fresh nested configuration workflow passed"
            )
        except Exception as error:  # noqa: BLE001 — checker failures are data
            return CheckResult(
                "checker", False, f"{type(error).__name__}: {str(error)[:220]}"
            )
