#!/usr/bin/env python3
"""Root-only Caddy identity, Nextcloud setup, and guarded-file operations."""

from __future__ import annotations

import base64
import hashlib
import html
import http.cookiejar
import json
import os
import re
import secrets
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

STATE = Path("/arena/secrets/facility.json")
OBJECTIVE_GROUPS_ISSUED = Path("/arena/secrets/objective-groups.issued")
NEXTCLOUD_ENV = Path("/arena/secrets/nextcloud.env")
CONFIG = Path("/etc/caddy/Caddyfile")
PIDFILE = Path("/run/caddy/caddy.pid")
OBJECTIVE_DIR = Path("/opt/arena/objective")
CACHE_DIR = Path("/arena/state/plants")
ISSUED_COHORT = Path("/arena/secrets/issued-cohort")
BASE = "http://127.0.0.1:8080"
CADDY = "/srv/runtime/caddy"
OCC = "/var/www/html/occ"
USERNAME = re.compile(r"user[0-9a-f]{16}")
READ_TARGET = re.compile(
    r"Guarded/[a-z]+(?P<sep>[-_ ])(?:[a-z]+(?P=sep)){0,3}"
    r"[0-9a-f]{32}\.txt"
)
GUARDED_OWNER_COUNT = 4
REQUEST_TOKEN = re.compile(rb'data-requesttoken="([^"]+)"')
HEX64 = re.compile(r"[0-9a-f]{64}")
OPERATION = re.compile(r"[0-9a-f]{32}")
GROUP_FIELDS = {
    "group", "target", "cover", "owner", "cover_after", "operation",
    "read_digest", "command_digest", "read_cache", "command_cache",
}
GROUP_SLOTS = ("current", "previous", "pending", "retiring")
OBJECTIVE_GROUPS_ISSUED_VALUE = "caddy-nextcloud-sso-objective-groups-v1\n"
SEALED_COHORT = re.compile(r"[A-Za-z0-9_-]{1,32768}\.[0-9a-f]{64}")
PRINCIPAL_CONVERGENCE_SECONDS = 45.0
PRINCIPAL_REQUEST_TIMEOUT_SECONDS = 12.0
PRINCIPAL_BACKOFF_MAX_SECONDS = 4.0


class AuthRejected(RuntimeError):
    pass


class PrincipalProvisioningError(RuntimeError):
    def __init__(self, stage: str, *, retryable: bool):
        super().__init__(stage)
        self.stage = stage
        self.retryable = retryable


def run(command: list[str], *, timeout: float = 30,
        check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command, capture_output=True, text=True, timeout=timeout, check=False)
    if check and result.returncode != 0:
        raise RuntimeError("application operation failed")
    return result


def occ(*arguments: str, check: bool = True, timeout: float = 60.0) -> str:
    result = run(
        ["su-exec", "service:service", "php", OCC, *arguments],
        timeout=timeout, check=check)
    return result.stdout.strip()


def occ_json(*arguments: str, timeout: float = 60.0) -> dict:
    output = occ(*arguments, timeout=timeout)
    try:
        value = json.loads(output.splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as error:
        raise RuntimeError("application JSON unavailable") from error
    if not isinstance(value, dict):
        raise RuntimeError("application JSON malformed")
    return value


def hash_password(password: str) -> str:
    output = run([CADDY, "hash-password", "--plaintext", password]).stdout.strip()
    if not output.startswith("$2"):
        raise RuntimeError("Caddy password hash failed")
    return output


def bootstrap_credentials() -> dict[str, str]:
    values = {}
    for line in NEXTCLOUD_ENV.read_text().splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    password = values.get("NEXTCLOUD_ADMIN_PASSWORD", "")
    if not password:
        raise RuntimeError("bootstrap credential unavailable")
    material = hashlib.sha256(password.encode()).hexdigest()
    return {
        "username": "user" + material[:16],
        "password": password,
    }


def save_state(data: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    temporary = STATE.with_suffix(".new")
    temporary.write_text(json.dumps(data, separators=(",", ":"), sort_keys=True))
    os.chmod(temporary, 0o600)
    os.replace(temporary, STATE)


def objective_groups_issued() -> bool:
    if not OBJECTIVE_GROUPS_ISSUED.exists():
        return False
    if (OBJECTIVE_GROUPS_ISSUED.is_symlink()
            or not OBJECTIVE_GROUPS_ISSUED.is_file()
            or OBJECTIVE_GROUPS_ISSUED.read_text()
            != OBJECTIVE_GROUPS_ISSUED_VALUE):
        raise RuntimeError("objective-group issuance marker malformed")
    return True


def mark_objective_groups_issued() -> None:
    if objective_groups_issued():
        return
    temporary = OBJECTIVE_GROUPS_ISSUED.with_suffix(".new")
    temporary.write_text(OBJECTIVE_GROUPS_ISSUED_VALUE)
    os.chmod(temporary, 0o400)
    os.replace(temporary, OBJECTIVE_GROUPS_ISSUED)


def load_state() -> dict:
    if not STATE.exists():
        if objective_groups_issued():
            raise RuntimeError("facility state missing after objective issuance")
        credentials = bootstrap_credentials()
        data = {
            "accounts": [{
                "username": credentials["username"],
                "hash": hash_password(credentials["password"]),
                "guarded": True,
            }],
            "provider": None,
            "folder": None,
            "objective_groups": {slot: None for slot in GROUP_SLOTS},
        }
        save_state(data)
    value = json.loads(STATE.read_text())
    if not isinstance(value, dict):
        raise RuntimeError("facility state malformed")
    return value


def normalize_principals(
    raw: object, existing: list[dict],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    if not isinstance(raw, list):
        raise ValueError("principal batch must be a list")
    prior = {row.get("username"): row for row in existing if isinstance(row, dict)}
    persisted = []
    transient = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("principal must be an object")
        username = item.get("username")
        password = item.get("password")
        guarded = item.get("guarded")
        verify = item.get("verify", False)
        if not isinstance(username, str) or not USERNAME.fullmatch(username):
            raise ValueError("invalid principal username")
        if not isinstance(password, str) or len(password) < 32:
            raise ValueError("invalid principal password")
        if not isinstance(guarded, bool):
            raise ValueError("invalid principal role")
        if not isinstance(verify, bool):
            raise ValueError("invalid principal verification marker")
        previous = prior.get(username)
        if previous and previous.get("guarded") is not guarded:
            raise ValueError("principal role changed")
        password_hash = previous.get("hash") if previous else None
        if not isinstance(password_hash, str):
            password_hash = hash_password(password)
        persisted.append({
            "username": username, "hash": password_hash, "guarded": guarded,
        })
        transient.append({
            "username": username, "password": password, "guarded": guarded,
            "verify": verify,
        })
    if len({row["username"] for row in persisted}) != len(persisted):
        raise ValueError("duplicate principal")
    return (
        sorted(persisted, key=lambda row: str(row["username"])),
        sorted(transient, key=lambda row: str(row["username"])),
    )


def render_caddyfile(data: dict) -> str:
    accounts = sorted(data.get("accounts", []), key=lambda row: row["username"])
    if not accounts or not any(row.get("guarded") is True for row in accounts):
        raise RuntimeError("Caddy identity set is incomplete")
    auth_lines = "\n".join(
        f"\t\t\t{row['username']} {row['hash']}" for row in accounts)
    guarded = " || ".join(
        f'{{http.auth.user.id}} == "{row["username"]}"'
        for row in accounts if row.get("guarded") is True
    )
    return f"""{{
\tauto_https off
\tadmin 127.0.0.1:2019
}}

:9080 {{
\tbind 127.0.0.1
\troute {{
\t\tbasic_auth {{
{auth_lines}
\t\t}}
\t\theader Remote-User {{http.auth.user.id}}
\t\t@guarded expression `{guarded}`
\t\theader @guarded Remote-Groups guarded
\t\trespond 204
\t}}
}}

:8080 {{
\t@forbidden path /.htaccess /data/* /config/* /db_structure /README /3rdparty/* /lib/* /templates/* /occ /console.php
\troute {{
\t\tforward_auth 127.0.0.1:9080 {{
\t\t\turi /
\t\t\tcopy_headers Remote-User Remote-Groups
\t\t}}
\t\trequest_header -Authorization
\t\trespond @forbidden 404
\t\troot * /var/www/html
\t\tphp_fastcgi 127.0.0.1:9000
\t\tfile_server
\t}}
}}
"""


def server_running() -> bool:
    if not PIDFILE.exists():
        return False
    try:
        os.kill(int(PIDFILE.read_text().strip()), 0)
        return True
    except (OSError, ValueError):
        return False


def install_config(data: dict) -> None:
    temporary = CONFIG.with_suffix(".new")
    temporary.write_text(render_caddyfile(data))
    os.chmod(temporary, 0o444)
    run([CADDY, "validate", "--config", str(temporary), "--adapter", "caddyfile"])
    if server_running():
        run([
            CADDY, "reload", "--config", str(temporary), "--adapter", "caddyfile",
            "--address", "127.0.0.1:2019",
        ])
    os.replace(temporary, CONFIG)


class PublicClient:
    def __init__(self, account: dict[str, str], *, timeout: float = 30.0):
        self.account = account
        self.timeout = timeout
        self.token = ""
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(self, method: str, path: str,
                data: bytes | None = None) -> tuple[int, bytes, str]:
        credentials = base64.b64encode(
            f"{self.account['username']}:{self.account['password']}".encode()).decode()
        headers = {"Authorization": "Basic " + credentials}
        if self.token:
            headers["requesttoken"] = self.token
        request = urllib.request.Request(
            BASE + path, data=data, method=method, headers=headers)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                return response.status, response.read(), response.geturl()
        except urllib.error.HTTPError as error:
            return error.code, error.read(), error.geturl()

    def login(self) -> None:
        status, raw, url = self.request("GET", "/index.php/login")
        match = REQUEST_TOKEN.search(raw)
        if status != 200 or "/apps/dashboard/" not in url or match is None:
            raise AuthRejected("SSO login rejected")
        self.token = html.unescape(match.group(1).decode())

    def webdav(self, method: str, target: str,
               data: bytes | None = None) -> tuple[int, bytes]:
        user = urllib.parse.quote(self.account["username"], safe="")
        path = "/".join(urllib.parse.quote(part, safe="")
                        for part in target.split("/"))
        status, raw, _ = self.request(
            method, f"/remote.php/dav/files/{user}/{path}", data)
        return status, raw


def user_info(
    account: dict[str, str], *, deadline: float | None = None,
) -> dict:
    if deadline is None:
        deadline = time.monotonic() + PRINCIPAL_CONVERGENCE_SECONDS
    delay = 0.25
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("principal login did not converge")
        try:
            PublicClient(
                account,
                timeout=min(PRINCIPAL_REQUEST_TIMEOUT_SECONDS, remaining),
            ).login()
            break
        except (AuthRejected, TimeoutError, urllib.error.URLError) as error:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("principal login did not converge") from error
            time.sleep(min(delay, remaining))
            delay = min(delay * 2, PRINCIPAL_BACKOFF_MAX_SECONDS)

    delay = 0.25
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("principal user information did not converge")
        try:
            return occ_json(
                "user:info", account["username"], "--output=json",
                timeout=min(60.0, remaining),
            )
        except (RuntimeError, subprocess.TimeoutExpired) as error:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError(
                    "principal user information did not converge") from error
            time.sleep(min(delay, remaining))
            delay = min(delay * 2, PRINCIPAL_BACKOFF_MAX_SECONDS)


def initialize() -> None:
    install_config(load_state())
    print("OK")


def trusted_domains() -> tuple[str, ...]:
    hostname = socket.gethostname().strip().lower()
    if not hostname or re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,252}", hostname) is None:
        raise RuntimeError("container hostname is unavailable")
    domains = [hostname]
    if hostname.endswith("_prod"):
        domains.append(hostname.removesuffix("_prod") + "_ingress")
    try:
        domains.append(socket.gethostbyname(hostname))
    except OSError as error:
        raise RuntimeError("container address is unavailable") from error
    domains.append("127.0.0.1")
    return tuple(dict.fromkeys(domains))


def configure_apps() -> None:
    data = load_state()
    occ("app:enable", "user_saml")
    occ("app:enable", "groupfolders")
    occ("config:system:set", "skeletondirectory", "--value=")
    occ("config:app:set", "user_saml", "type", "--value=environment-variable")
    provider = data.get("provider")
    if provider is None:
        provider = occ("saml:config:create").splitlines()[-1]
        if not provider.isdigit():
            raise RuntimeError("SAML provider creation failed")
        data["provider"] = provider
    occ(
        "saml:config:set", str(provider),
        "--general-uid_mapping=HTTP_REMOTE_USER",
        "--saml-attribute-mapping-group_mapping=HTTP_REMOTE_GROUPS",
    )
    occ(
        "config:app:set", "user_saml", "general-require_provisioned_account",
        "--value=0", "--type=integer",
    )
    occ(
        "config:app:set", "user_saml", "general-keep_groups",
        "--value=1", "--type=integer",
    )
    occ("config:system:delete", "trusted_domains")
    for index, domain in enumerate(trusted_domains()):
        occ(
            "config:system:set", "trusted_domains", str(index),
            f"--value={domain}",
        )
    save_state(data)
    print("OK")


def setup() -> None:
    data = load_state()
    guarded_info = user_info(bootstrap_credentials())
    if "SAML_guarded" not in (guarded_info.get("groups") or []):
        raise RuntimeError("guarded SSO group missing")
    folder = data.get("folder")
    if folder is None:
        folder = occ("groupfolders:create", "Guarded").splitlines()[-1]
        if not folder.isdigit():
            raise RuntimeError("Team Folder creation failed")
        data["folder"] = folder
    occ(
        "groupfolders:group", str(folder), "SAML_guarded",
        "read", "write", "delete",
    )
    save_state(data)
    print("OK")


def principals(encoded: str) -> None:
    data = load_state()
    try:
        raw = json.loads(base64.b64decode(encoded, validate=True))
        normalized, transient = normalize_principals(
            raw, data.get("accounts", []))
    except (ValueError, json.JSONDecodeError) as error:
        raise PrincipalProvisioningError(
            "input", retryable=False) from error
    accounts = {
        row["username"]: row for row in data.get("accounts", [])
        if isinstance(row, dict) and isinstance(row.get("username"), str)
    }
    accounts.update({row["username"]: row for row in normalized})
    pending = {
        **data,
        "accounts": sorted(accounts.values(), key=lambda row: row["username"]),
    }
    try:
        install_config(pending)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        raise PrincipalProvisioningError(
            "caddy-config", retryable=True) from error
    representatives = []
    ordinary = [account for account in transient if not account["guarded"]]
    guarded = [account for account in transient if account["guarded"]]
    if ordinary:
        representatives.append(next(
            (account for account in ordinary if account["verify"]), ordinary[0]))
    if guarded:
        representatives.append(guarded[0])
    deadline = time.monotonic() + PRINCIPAL_CONVERGENCE_SECONDS
    for account in representatives:
        try:
            info = user_info(account, deadline=deadline)
        except (OSError, RuntimeError, subprocess.TimeoutExpired,
                urllib.error.URLError) as error:
            raise PrincipalProvisioningError(
                "application-convergence", retryable=True) from error
        groups = info.get("groups")
        if (not isinstance(groups, list)
                or any(not isinstance(group, str) for group in groups)):
            raise PrincipalProvisioningError(
                "user-info", retryable=False)
        is_guarded = "SAML_guarded" in groups
        if is_guarded is not account["guarded"]:
            raise PrincipalProvisioningError(
                "role-mismatch", retryable=False)
    try:
        save_state(pending)
    except OSError as error:
        raise PrincipalProvisioningError(
            "state-publication", retryable=True) from error
    print(f"OK {len(transient)}")


def store_issued_cohort(sealed: str) -> None:
    if not isinstance(sealed, str) or SEALED_COHORT.fullmatch(sealed) is None:
        raise RuntimeError("invalid issued principal cohort")
    destination = ISSUED_COHORT
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.parent / (
        f".{destination.name}.{secrets.token_hex(8)}.tmp")
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(sealed)
            stream.flush()
            os.fchmod(stream.fileno(), 0o400)
            os.fchown(stream.fileno(), 0, 0)
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)
    print("OK")


def read_issued_cohort() -> None:
    try:
        metadata = ISSUED_COHORT.lstat()
        sealed = ISSUED_COHORT.read_text()
    except OSError as error:
        raise RuntimeError("issued principal cohort is unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o400
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or SEALED_COHORT.fullmatch(sealed) is None
    ):
        raise RuntimeError("issued principal cohort is unsafe")
    print(sealed)


def valid_group(value: object) -> bool:
    if (not isinstance(value, dict) or set(value) != GROUP_FIELDS
            or not isinstance(value.get("group"), str)
            or HEX64.fullmatch(value["group"]) is None
            or not isinstance(value.get("target"), str)
            or READ_TARGET.fullmatch(value["target"]) is None
            or not isinstance(value.get("cover"), str)
            or READ_TARGET.fullmatch(value["cover"]) is None
            or value["target"] == value["cover"]
            or isinstance(value.get("owner"), bool)
            or not isinstance(value.get("owner"), int)
            or not 0 <= value["owner"] < GUARDED_OWNER_COUNT
            or not isinstance(value.get("cover_after"), bool)
            or not isinstance(value.get("operation"), str)
            or OPERATION.fullmatch(value["operation"]) is None):
        return False
    return all(
        isinstance(value.get(key), str) and HEX64.fullmatch(value[key])
        for key in ("read_digest", "command_digest", "read_cache", "command_cache")
    )


def objective_groups(data: dict) -> dict[str, dict | None]:
    groups = data.get("objective_groups")
    if groups is None:
        if objective_groups_issued():
            raise RuntimeError("objective-group state missing after issuance")
        return {slot: None for slot in GROUP_SLOTS}
    if (not isinstance(groups, dict) or set(groups) != set(GROUP_SLOTS)
            or any(group is not None and not valid_group(group)
                   for group in groups.values())
            or (groups["pending"] is not None
                and (groups["previous"] is not None
                     or groups["retiring"] is not None))
            or (groups["retiring"] is not None
                and (groups["previous"] is not None
                     or groups["pending"] is not None))
            or (groups["current"] is None
                and (groups["previous"] is not None
                     or groups["retiring"] is not None))):
        raise RuntimeError("objective-group state malformed")
    concrete = [group for group in groups.values() if group is not None]
    if bool(concrete) != objective_groups_issued():
        raise RuntimeError("objective-group issuance state malformed")
    for keys in (
        ("group",), ("target",), ("cover",), ("operation",),
        ("read_cache", "command_cache"),
    ):
        values = [group[key] for group in concrete for key in keys]
        if len(values) != len(set(values)):
            raise RuntimeError("objective-group state malformed")
    return groups


def decode_group(raw: str, *, nullable: bool = False) -> dict | None:
    value = json.loads(base64.b64decode(raw, validate=True))
    if value is None and nullable:
        return None
    if not valid_group(value):
        raise ValueError("invalid objective group")
    return value


def read_group_state() -> None:
    groups = objective_groups(load_state())
    print(json.dumps(groups, separators=(",", ":"), sort_keys=True))


def record_pending(raw: str, current_raw: str) -> None:
    group = decode_group(raw)
    expected_current = decode_group(current_raw, nullable=True)
    data = load_state()
    groups = objective_groups(data)
    if (groups["retiring"] is not None or groups["previous"] is not None
            or groups["current"] != expected_current
            or groups["pending"] not in (None, group)):
        raise RuntimeError("objective group changed before staging")
    mark_objective_groups_issued()
    groups["pending"] = group
    data["objective_groups"] = groups
    save_state(data)
    print("OK")


def promote_pending(raw: str) -> None:
    group = decode_group(raw)
    data = load_state()
    groups = objective_groups(data)
    if (groups["pending"] != group or groups["previous"] is not None
            or groups["retiring"] is not None):
        raise RuntimeError("objective group changed before promotion")
    groups["previous"] = groups["current"]
    groups["current"] = group
    groups["pending"] = None
    data["objective_groups"] = groups
    save_state(data)
    print("OK")


def begin_retirement(raw: str) -> None:
    group = decode_group(raw)
    data = load_state()
    groups = objective_groups(data)
    if groups["retiring"] == group and groups["previous"] is None:
        print("OK")
        return
    if (groups["previous"] != group or groups["pending"] is not None
            or groups["retiring"] is not None):
        raise RuntimeError("objective group changed before retirement")
    groups["retiring"] = group
    groups["previous"] = None
    data["objective_groups"] = groups
    save_state(data)
    print("OK")


def finish_retirement(raw: str) -> None:
    group = decode_group(raw)
    data = load_state()
    groups = objective_groups(data)
    if groups["retiring"] != group:
        raise RuntimeError("objective group changed during retirement")
    for path in (
        OBJECTIVE_DIR / group["operation"],
        CACHE_DIR / group["read_cache"],
        CACHE_DIR / group["command_cache"],
    ):
        path.unlink(missing_ok=True)
    groups["retiring"] = None
    data["objective_groups"] = groups
    save_state(data)
    print("OK")


def prune_caches(raw: str) -> None:
    allowed = json.loads(base64.b64decode(raw, validate=True))
    if (not isinstance(allowed, list) or len(allowed) > 10
            or len(allowed) != len(set(allowed))
            or any(not isinstance(key, str) or HEX64.fullmatch(key) is None
                   for key in allowed)):
        raise ValueError("invalid plant cache allowlist")
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    for path in CACHE_DIR.iterdir():
        if path.is_file() and path.name not in allowed:
            path.unlink()
    print("OK")


def status() -> None:
    nextcloud = occ_json("status", "--output=json")
    apps = occ_json("app:list", "--output=json").get("enabled", {})
    caddy = run([CADDY, "version"]).stdout.strip().split()[0]
    print(json.dumps({
        "caddy": caddy,
        "nextcloud": nextcloud.get("versionstring"),
        "user_saml": apps.get("user_saml"),
        "groupfolders": apps.get("groupfolders"),
    }, separators=(",", ":"), sort_keys=True))


def main() -> int:
    try:
        command = sys.argv[1] if len(sys.argv) > 1 else ""
        if command == "initialize" and len(sys.argv) == 2:
            initialize()
        elif command == "configure-apps" and len(sys.argv) == 2:
            configure_apps()
        elif command == "setup" and len(sys.argv) == 2:
            setup()
        elif command == "principals" and len(sys.argv) == 3:
            principals(sys.argv[2])
        elif command == "store-issued-cohort" and len(sys.argv) == 3:
            store_issued_cohort(sys.argv[2])
        elif command == "read-issued-cohort" and len(sys.argv) == 2:
            read_issued_cohort()
        elif command == "read-group-state" and len(sys.argv) == 2:
            read_group_state()
        elif command == "record-pending" and len(sys.argv) == 4:
            record_pending(sys.argv[2], sys.argv[3])
        elif command == "promote-pending" and len(sys.argv) == 3:
            promote_pending(sys.argv[2])
        elif command == "begin-retirement" and len(sys.argv) == 3:
            begin_retirement(sys.argv[2])
        elif command == "finish-retirement" and len(sys.argv) == 3:
            finish_retirement(sys.argv[2])
        elif command == "prune-caches" and len(sys.argv) == 3:
            prune_caches(sys.argv[2])
        elif command == "status" and len(sys.argv) == 2:
            status()
        else:
            return 2
        return 0
    except PrincipalProvisioningError as error:
        print(
            f"ERROR stage={error.stage} retryable={int(error.retryable)}")
        return 75 if error.retryable else 64
    except AuthRejected:
        return 3
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError,
            json.JSONDecodeError, urllib.error.URLError):
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
