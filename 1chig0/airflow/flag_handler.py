"""Native principal provisioning and convergent Airflow Variable placement."""

from __future__ import annotations

import base64
import json
import secrets
import shlex
import time
from collections.abc import Mapping
from typing import Any

from challenges.interface import (
    BaselinePrincipal,
    Flag,
    FlagHandler,
    FlagObservation,
    ObservationStatus,
    VulboxTarget,
)

from ._api import AirflowClient
from ._ids import (
    STORE,
    facility_admin_credentials,
    new_ordinary_credentials,
    objective_shaped_noise_token,
    objective_sentinel_key,
    open_context,
    pack_handle,
    principal_credentials,
    principal_context_key,
    principal_health_variable_key,
    round_context,
    seal_context,
    unpack_handle,
)
from .image.identity import (
    ordinary_variable_key,
    valid_ordinary_password,
    valid_ordinary_username,
    valid_ordinary_variable_key,
)


PRIVATE_DIR = "/var/lib/cyberarena-private/airflow"
JOURNAL_PATH = f"{PRIVATE_DIR}/objective-journal.json"
ISSUED_PATH = f"{PRIVATE_DIR}/objective-issued"
ISSUED_VALUE = "airflow-nested-variable-v1"
SENTINEL_VALUE = "managed-service-registry-v1"
SENTINEL_DESCRIPTION = "Managed service registry"
PRINCIPAL_CONTEXT_DESCRIPTION = "Managed principal assignments"
_AUTH_READY_TIMEOUT = 30.0
_AUTH_RETRY_DELAY = 1.0
_AUTH_ATTEMPT_TIMEOUT = 3.0
_FACILITY_TRANSPORT_ATTEMPTS = 6
_FACILITY_TRANSPORT_RETRY_DELAY = 0.5


class AirflowFacilityTransportError(RuntimeError):
    """The facility could not establish its privileged Airflow transport."""


def _empty_journal() -> dict[str, Any]:
    return {"v": 1, "current": None, "previous": None, "pending": None}


def _b64(raw: str) -> str:
    return base64.b64encode(raw.encode()).decode()


def _variable_document(generation: Mapping[str, Any]) -> dict[str, str]:
    value = json.dumps(
        {
            "password": generation["top_control"],
            "service": "billing",
            "region": generation["region"],
            "config": {
                "password": generation["token"],
                "next": {"api_key": generation["deep_control"]},
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return {
        "key": str(generation["key"]),
        "value": value,
        "description": str(generation["description"]),
    }


def _valid_generation(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    expected = {
        "context",
        "deep_control",
        "description",
        "handle",
        "key",
        "region",
        "token",
        "top_control",
    }
    if set(value) != expected or any(
        not isinstance(value.get(key), str) or not value[key] for key in expected
    ):
        return False
    handle = unpack_handle(value["handle"])
    return (
        handle is not None
        and handle["context"] == value["context"]
        and handle["key"] == value["key"]
        and handle["token"] == value["token"]
    )


def _parse_journal(raw: str) -> dict[str, Any]:
    try:
        journal = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as error:
        raise RuntimeError("objective journal is malformed") from error
    if (
        not isinstance(journal, dict)
        or set(journal) != {"v", "current", "previous", "pending"}
        or journal.get("v") != 1
        or all(journal.get(key) is None for key in ("current", "previous", "pending"))
        or any(
            journal.get(key) is not None and not _valid_generation(journal[key])
            for key in ("current", "previous", "pending")
        )
    ):
        raise RuntimeError("objective journal is malformed")
    keys = [
        generation["key"]
        for name in ("current", "previous", "pending")
        if isinstance((generation := journal.get(name)), dict)
    ]
    if len(keys) != len(set(keys)):
        raise RuntimeError("objective journal has duplicate targets")
    return journal


class AirflowFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "airflow-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("web",)

    @staticmethod
    def _exec(target: VulboxTarget, command: str) -> str:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            raise RuntimeError("no facility exec bridge")
        for attempt in range(_FACILITY_TRANSPORT_ATTEMPTS):
            rc, output = exec_in(target.host, command)
            if rc == 0:
                return output or ""
            if rc != 255:
                raise RuntimeError(f"Airflow facility operation failed (rc={rc})")
            if attempt + 1 < _FACILITY_TRANSPORT_ATTEMPTS:
                time.sleep(_FACILITY_TRANSPORT_RETRY_DELAY)
        raise AirflowFacilityTransportError(
            "Airflow facility SSH transport remained unavailable after retries"
        )

    @staticmethod
    def _client(
        target: VulboxTarget, username: str, password: str
    ) -> AirflowClient:
        return AirflowClient(
            f"http://{target.host}:{target.ports['web']}", username, password
        )

    @staticmethod
    def _login_when_ready(
        client: AirflowClient,
        *,
        timeout: float = _AUTH_READY_TIMEOUT,
        retry_delay: float = _AUTH_RETRY_DELAY,
    ) -> bool:
        """Bound authentication retries across Airflow's post-bind warm-up."""
        deadline = time.monotonic() + max(timeout, 0.0)
        while True:
            remaining = deadline - time.monotonic()
            attempt_timeout = max(0.1, min(_AUTH_ATTEMPT_TIMEOUT, remaining))
            if client.login(timeout=attempt_timeout):
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(max(retry_delay, 0.0), remaining))

    def _bootstrap_credentials(
        self, target: VulboxTarget
    ) -> tuple[str, str] | None:
        output = self._exec(target, "/arena/facility.py bootstrap-credentials")
        try:
            document = json.loads(output.strip())
            if document is None:
                return None
            username = document["username"]
            password = document["password"]
            if not isinstance(username, str) or not isinstance(password, str):
                raise ValueError
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeError("Airflow bootstrap context is malformed") from error
        return username, password

    def _retire_bootstrap(
        self,
        target: VulboxTarget,
        credentials: tuple[str, str],
        client: AirflowClient | None,
    ) -> None:
        if self._exec(target, "/arena/facility.py retire-bootstrap").strip() != "OK":
            raise RuntimeError("Airflow bootstrap secret retirement failed")
        if client is not None:
            status, _ = client.list_variables("retired-administrator-check")
            if status not in (401, 403):
                raise RuntimeError("Airflow bootstrap bearer remained usable")
        replacement = self._client(target, *credentials)
        if replacement.login():
            raise RuntimeError("Airflow bootstrap password remained usable")

    def _principal_context(
        self, target: VulboxTarget
    ) -> tuple[tuple[str, str, str], ...] | None:
        team_id = str(target.meta["team_id"])
        key = principal_context_key(team_id)
        client = self._client(target, *facility_admin_credentials(team_id))
        if not self._login_when_ready(client):
            raise RuntimeError("Airflow facility administration is unavailable")
        status, record = client.get_variable(key)
        if status == 404:
            return None
        try:
            sealed = record["value"]
            document = open_context(team_id, "principals", sealed)
            rows = document["accounts"]
            if (
                status != 200
                or not isinstance(record, dict)
                or record.get("key") != key
                or record.get("description") != PRINCIPAL_CONTEXT_DESCRIPTION
                or not isinstance(document, dict)
                or set(document) != {"accounts", "v"}
                or document.get("v") != 2
                or not isinstance(rows, list)
                or not rows
            ):
                raise ValueError
            accounts = tuple(
                (row[0], row[1], row[2])
                for row in rows
                if isinstance(row, list) and len(row) == 3
            )
            if (
                len(accounts) != len(rows)
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
                raise ValueError
        except (KeyError, TypeError, ValueError) as error:
            raise RuntimeError(
                "Airflow principal assignment record is malformed"
            ) from error
        return accounts

    def _write_principal_context(
        self,
        target: VulboxTarget,
        accounts: set[tuple[str, str, str]],
        administrator: AirflowClient,
    ) -> None:
        team_id = str(target.meta["team_id"])
        key = principal_context_key(team_id)
        sealed = seal_context(
            team_id,
            "principals",
            {"v": 2, "accounts": [list(account) for account in sorted(accounts)]},
        )
        record = {
            "key": key,
            "value": sealed,
            "description": PRINCIPAL_CONTEXT_DESCRIPTION,
        }
        status, _ = administrator.get_variable(key)
        if status == 404:
            written, _ = administrator.create_variable(record)
        elif status == 200:
            written, _ = administrator.update_variable(key, record)
        else:
            written = status
        verify_status, verify = administrator.get_variable(key)
        if (
            written not in (200, 201)
            or verify_status != 200
            or not isinstance(verify, dict)
            or any(verify.get(field) != value for field, value in record.items())
        ):
            raise RuntimeError("Airflow principal context persistence failed")

    @staticmethod
    def _ensure_health_variable(client: AirflowClient, key: str) -> None:
        document = {
            "key": key,
            "value": json.dumps(
                {
                    "password": "credential-" + secrets.token_urlsafe(21),
                    "service": "billing",
                    "region": "zone-" + secrets.token_hex(5),
                    "config": {
                        "password": objective_shaped_noise_token(),
                        "next": {"api_key": "api-" + secrets.token_urlsafe(21)},
                    },
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            "description": "Managed integration profile " + secrets.token_hex(6),
        }
        current, _ = client.get_variable(key)
        if current == 404:
            written, _ = client.create_variable(document)
        elif current == 200:
            written, _ = client.update_variable(key, document)
        else:
            written = current
        status, record = client.get_variable(key)
        if (
            written not in (200, 201)
            or status != 200
            or not isinstance(record, dict)
            or record.get("key") != key
            or record.get("description") != document["description"]
        ):
            raise RuntimeError("Airflow preexisting health Variable setup failed")

    def _ensure_accounts(
        self, target: VulboxTarget, accounts: set[tuple[str, str, str]]
    ) -> None:
        bootstrap = self._bootstrap_credentials(target)
        admin_credentials = facility_admin_credentials(
            str(target.meta["team_id"])
        )
        if any(
            username == admin_credentials[0] or password == admin_credentials[1]
            for username, password, _ in accounts
        ):
            raise RuntimeError("Airflow facility credential collision")
        administrator = self._client(target, *admin_credentials)
        bootstrap_client = (
            self._client(target, *bootstrap) if bootstrap is not None else None
        )
        bootstrap_live = (
            bootstrap_client is not None
            and self._login_when_ready(bootstrap_client)
        )
        administrator_live = (
            administrator.login(timeout=_AUTH_ATTEMPT_TIMEOUT)
            if bootstrap_live
            else self._login_when_ready(administrator)
        )
        if not administrator_live:
            if not bootstrap_live or bootstrap_client is None:
                raise RuntimeError("Airflow administration bootstrap is unavailable")
            status, _ = bootstrap_client.create_user(
                *admin_credentials, role="Admin"
            )
            administrator_live = (
                status in (200, 201, 400, 409)
                and self._login_when_ready(administrator)
            )
            if not administrator_live:
                raise RuntimeError("Airflow facility administration failed")
        admin_status, admin_document = administrator.get_user(
            admin_credentials[0]
        )
        admin_roles = (
            admin_document.get("roles")
            if isinstance(admin_document, dict)
            else None
        )
        admin_role_names = (
            [row.get("name") for row in admin_roles if isinstance(row, dict)]
            if isinstance(admin_roles, list)
            else []
        )
        if admin_status != 200 or admin_role_names != ["Admin"]:
            raise RuntimeError("Airflow facility administrator role is invalid")
        for username, password, health_key in sorted(accounts):
            principal = self._client(target, username, password)
            if not principal.login(timeout=_AUTH_ATTEMPT_TIMEOUT):
                status, _ = administrator.create_user(username, password)
                created = status in (200, 201, 400, 409)
                if not created or not self._login_when_ready(principal):
                    raise RuntimeError("Airflow principal provisioning failed")
            check_status, _ = principal.list_variables("provisioning-access-check")
            if check_status != 200:
                raise RuntimeError("Airflow principal role provisioning failed")
            user_status, document = administrator.get_user(username)
            roles = document.get("roles") if isinstance(document, dict) else None
            role_names = (
                [row.get("name") for row in roles if isinstance(row, dict)]
                if isinstance(roles, list)
                else []
            )
            if user_status != 200 or role_names != ["Op"]:
                raise RuntimeError("Airflow principal role provisioning failed")
            self._ensure_health_variable(principal, health_key)
        self._write_principal_context(target, accounts, administrator)
        if bootstrap is not None:
            self._retire_bootstrap(
                target,
                bootstrap,
                bootstrap_client if bootstrap_live else None,
            )
            administrator = self._client(target, *admin_credentials)
            if not self._login_when_ready(administrator):
                raise RuntimeError("Airflow facility administrator did not survive")
            for username, password, _ in sorted(accounts):
                principal = self._client(target, username, password)
                if not self._login_when_ready(principal):
                    raise RuntimeError("Airflow principal did not survive retirement")
                status, _ = principal.list_variables("post-retirement-access-check")
                if status != 200:
                    raise RuntimeError("Airflow principal did not survive retirement")

    def _guarded_client(self, target: VulboxTarget) -> AirflowClient:
        bootstrap = self._bootstrap_credentials(target)
        if bootstrap is not None:
            administrator = self._client(
                target,
                *facility_admin_credentials(str(target.meta["team_id"])),
            )
            bootstrap_client = self._client(target, *bootstrap)
            if administrator.login(timeout=_AUTH_ATTEMPT_TIMEOUT):
                bootstrap = None
            elif not self._login_when_ready(bootstrap_client):
                raise RuntimeError("Airflow administration bootstrap is unavailable")
        if bootstrap is not None:
            fallback = {
                (
                    *new_ordinary_credentials(),
                    ordinary_variable_key(secrets.token_bytes(32)),
                )
            }
            self._ensure_accounts(target, fallback)
        accounts = self._principal_context(target)
        if accounts is None:
            raise RuntimeError("Airflow principal assignment record is missing")
        username, password, _ = secrets.choice(accounts)
        client = self._client(target, username, password)
        if not self._login_when_ready(client):
            raise RuntimeError("Airflow ordinary facility principal login failed")
        status, _ = client.list_variables("facility-access-check")
        if status != 200:
            raise RuntimeError("Airflow ordinary facility principal lacks access")
        return client

    def _sentinel_key(self, target: VulboxTarget) -> str:
        team_id = str(target.meta["team_id"])
        key = objective_sentinel_key(team_id)
        if not valid_ordinary_variable_key(key):
            raise RuntimeError("native objective issuance sentinel key is malformed")
        return key

    def provision_principals(
        self,
        target: VulboxTarget,
        seeds: Mapping[str, str],
    ) -> Mapping[str, BaselinePrincipal]:
        principals: dict[str, BaselinePrincipal] = {}
        team_id = str(target.meta["team_id"])
        baseline_accounts: set[tuple[str, str, str]] = set()
        for attacker, seed in sorted(seeds.items()):
            credentials = principal_credentials(seed)
            if any(account[:2] == credentials for account in baseline_accounts):
                raise RuntimeError("Airflow principal identity collision")
            baseline_accounts.add(
                (*credentials, principal_health_variable_key(seed))
            )
            principals[attacker] = BaselinePrincipal(
                principal_id=credentials[0],
                credentials={"username": credentials[0], "password": credentials[1]},
            )

        accounts = baseline_accounts
        usernames = [username for username, _, _ in accounts]
        passwords = [password for _, password, _ in accounts]
        health_keys = [key for _, _, key in accounts]
        if (
            len(usernames) != len(set(usernames))
            or len(passwords) != len(set(passwords))
            or len(health_keys) != len(set(health_keys))
        ):
            raise RuntimeError("Airflow principal credential collision")
        self._ensure_accounts(target, accounts)
        return principals

    @staticmethod
    def _sentinel_exists(client: AirflowClient, key: str) -> bool:
        status, document = client.get_variable(key)
        if status == 404:
            return False
        if (
            status != 200
            or not isinstance(document, dict)
            or document.get("key") != key
            or document.get("value") != SENTINEL_VALUE
            or document.get("description") != SENTINEL_DESCRIPTION
        ):
            raise RuntimeError("native objective issuance sentinel is malformed")
        return True

    def _ensure_sentinel(self, client: AirflowClient, key: str) -> None:
        if not self._sentinel_exists(client, key):
            status, _ = client.create_variable(
                {
                    "key": key,
                    "value": SENTINEL_VALUE,
                    "description": SENTINEL_DESCRIPTION,
                }
            )
            if status != 201 or not self._sentinel_exists(client, key):
                raise RuntimeError("native objective issuance sentinel creation failed")

    def _load_journal(
        self, target: VulboxTarget, client: AirflowClient, sentinel_key: str
    ) -> dict[str, Any]:
        sentinel = self._sentinel_exists(client, sentinel_key)
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
            if issued or sentinel:
                raise RuntimeError("objective journal is missing after issuance")
            return _empty_journal()
        if not state.startswith("file\n") or not state.removeprefix("file\n"):
            raise RuntimeError("objective journal is malformed")
        journal = _parse_journal(state.removeprefix("file\n"))
        published = (
            journal.get("current") is not None or journal.get("previous") is not None
        )
        if (issued or published) and not sentinel:
            raise RuntimeError("objective issuance sentinels disagree")
        return journal

    def _write_journal(
        self, target: VulboxTarget, journal: Mapping[str, Any]
    ) -> None:
        encoded = _b64(json.dumps(journal, sort_keys=True, separators=(",", ":")))
        self._exec(
            target,
            "set -eu; "
            f"install -d -o root -g root -m 0700 {shlex.quote(PRIVATE_DIR)}; "
            "umask 077; "
            f"printf %s {shlex.quote(encoded)} | base64 -d > "
            f"{shlex.quote(JOURNAL_PATH + '.next')}; "
            f"chmod 0600 {shlex.quote(JOURNAL_PATH + '.next')}; "
            f"mv -f {shlex.quote(JOURNAL_PATH + '.next')} {shlex.quote(JOURNAL_PATH)}",
        )

    def _mark_issued(self, target: VulboxTarget) -> None:
        self._exec(
            target,
            "set -eu; umask 077; "
            f"printf '%s\\n' {shlex.quote(ISSUED_VALUE)} > "
            f"{shlex.quote(ISSUED_PATH + '.next')}; "
            f"chmod 0600 {shlex.quote(ISSUED_PATH + '.next')}; "
            f"mv -f {shlex.quote(ISSUED_PATH + '.next')} {shlex.quote(ISSUED_PATH)}",
        )

    @staticmethod
    def _delete_variable(client: AirflowClient, key: str) -> None:
        status, _ = client.delete_variable(key)
        if status not in (204, 404):
            raise RuntimeError("Airflow objective cleanup failed")

    def _raw_variable(self, target: VulboxTarget, key: str) -> str | None:
        output = self._exec(
            target,
            f"/arena/facility.py raw-variable {shlex.quote(key)}",
        )
        try:
            lines = [line for line in output.splitlines() if line.strip()]
            document = json.loads(lines[-1])
            found = document["found"]
            value = document.get("value")
        except (IndexError, KeyError, TypeError, json.JSONDecodeError) as error:
            raise RuntimeError("Airflow Variable inspection failed") from error
        if found is False:
            return None
        if found is not True or not isinstance(value, str):
            raise RuntimeError("Airflow Variable inspection failed")
        return value

    def _converge_variable(
        self,
        target: VulboxTarget,
        client: AirflowClient,
        generation: Mapping[str, Any],
    ) -> None:
        document = _variable_document(generation)
        status, _ = client.get_variable(document["key"])
        if status == 404:
            status, _ = client.create_variable(document)
        elif status == 200:
            status, _ = client.update_variable(document["key"], document)
        if status not in (200, 201):
            raise RuntimeError("Airflow objective configuration failed")
        raw = self._raw_variable(target, document["key"])
        if raw != document["value"]:
            raise RuntimeError("Airflow objective verification failed")

    def plant(
        self, target: VulboxTarget, flags: Mapping[str, Flag]
    ) -> Mapping[str, str]:
        if set(flags) != {STORE}:
            raise ValueError(f"expected store {STORE!r}, got {sorted(flags)}")
        seed = target.meta.get("round_context_seed")
        if not isinstance(seed, str):
            raise ValueError("round context seed is unavailable")
        token = flags[STORE].value
        material = round_context(seed)
        guarded = self._guarded_client(target)
        sentinel_key = self._sentinel_key(target)
        journal = self._load_journal(target, guarded, sentinel_key)

        current = journal.get("current")
        if isinstance(current, dict) and current.get("context") == material["context"]:
            if current.get("token") != token:
                raise RuntimeError("round context was reused with different proof state")
            pending = journal.get("pending")
            if isinstance(pending, dict):
                self._delete_variable(guarded, str(pending["key"]))
                journal["pending"] = None
                self._write_journal(target, journal)
            self._ensure_sentinel(guarded, sentinel_key)
            self._converge_variable(target, guarded, current)
            self._mark_issued(target)
            return {STORE: str(current["handle"])}

        previous = journal.get("previous")
        if isinstance(previous, dict):
            self._delete_variable(guarded, str(previous["key"]))
            journal["previous"] = None
            self._write_journal(target, journal)

        pending = journal.get("pending")
        if isinstance(pending, dict) and (
            pending.get("context") != material["context"]
            or pending.get("token") != token
        ):
            self._delete_variable(guarded, str(pending["key"]))
            journal["pending"] = None
            self._write_journal(target, journal)

        pending = journal.get("pending")
        if not isinstance(pending, dict):
            pending = {**material, "token": token}
            pending["handle"] = pack_handle(
                {
                    "store": STORE,
                    "context": pending["context"],
                    "key": pending["key"],
                    "token": token,
                }
            )
            journal["pending"] = pending
            self._write_journal(target, journal)

        self._ensure_sentinel(guarded, sentinel_key)
        self._converge_variable(target, guarded, pending)
        journal = {
            "v": 1,
            "current": pending,
            "previous": current,
            "pending": None,
        }
        self._write_journal(target, journal)
        self._mark_issued(target)
        return {STORE: str(pending["handle"])}

    def retrieve(
        self,
        target: VulboxTarget,
        handle: str,
        expected: str | None = None,
    ) -> FlagObservation:
        payload = unpack_handle(handle)
        if payload is None:
            return FlagObservation(ObservationStatus.ERROR, detail="invalid handle")
        try:
            raw = self._raw_variable(target, str(payload["key"]))
        except Exception:  # noqa: BLE001
            return FlagObservation(
                ObservationStatus.ERROR, detail="Variable inspection failed"
            )
        if raw is None:
            return FlagObservation(ObservationStatus.NOT_FOUND)
        try:
            value = json.loads(raw)["config"]["password"]
        except (KeyError, TypeError, json.JSONDecodeError):
            return FlagObservation(
                ObservationStatus.NOT_FOUND,
                detail="nested credential is unavailable",
            )
        if not isinstance(value, str) or not value:
            return FlagObservation(ObservationStatus.NOT_FOUND)
        if expected is not None and value != expected:
            return FlagObservation(ObservationStatus.MISMATCH, value=value)
        return FlagObservation(ObservationStatus.PRESENT, value=value)

    def flag_id(self, handle: str) -> str | None:
        payload = unpack_handle(handle)
        return str(payload["key"]) if payload is not None else None
