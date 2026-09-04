#!/usr/bin/env python3
"""Root-only Caddy identity, Nextcloud setup, and guarded-file operations."""

from __future__ import annotations

import base64
import html
import http.cookiejar
import json
import os
import re
import secrets
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

STATE = Path("/arena/secrets/facility.json")
CONFIG = Path("/etc/caddy/Caddyfile")
PIDFILE = Path("/run/caddy/caddy.pid")
BASE = "http://127.0.0.1:8080"
CADDY = "/srv/runtime/caddy"
OCC = "/var/www/html/occ"
READ_TARGET = re.compile(r"Guarded/[0-9a-z-]{8,80}\.txt")
REQUEST_TOKEN = re.compile(rb'data-requesttoken="([^"]+)"')
PUBLIC_USERNAME = "arena-player"
PUBLIC_PASSWORD = "CaddyNextcloudArena2026!"


class AuthRejected(RuntimeError):
    pass


class NotFound(RuntimeError):
    pass


def run(command: list[str], *, timeout: int = 30,
        check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command, capture_output=True, text=True, timeout=timeout, check=False)
    if check and result.returncode != 0:
        raise RuntimeError("application operation failed")
    return result


def occ(*arguments: str, check: bool = True) -> str:
    result = run(
        ["su-exec", "service:service", "php", OCC, *arguments],
        timeout=60, check=check)
    return result.stdout.strip()


def occ_json(*arguments: str) -> dict:
    output = occ(*arguments)
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


def random_account(prefix: str) -> dict[str, str]:
    password = "C1!" + secrets.token_hex(24)
    return {
        "username": prefix + secrets.token_hex(8),
        "password": password,
        "hash": hash_password(password),
    }


def public_account() -> dict[str, str]:
    return {
        "username": PUBLIC_USERNAME,
        "password": PUBLIC_PASSWORD,
        "hash": hash_password(PUBLIC_PASSWORD),
    }


def save_state(data: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    temporary = STATE.with_suffix(".new")
    temporary.write_text(json.dumps(data, separators=(",", ":"), sort_keys=True))
    os.chmod(temporary, 0o600)
    os.replace(temporary, STATE)


def load_state() -> dict:
    if not STATE.exists():
        data = {
            # Only the authorized checker identity is private.  The checker's
            # ordinary workflow uses the same public account as players.
            "guarded": random_account("user"),
            "public": public_account(),
            "provider": None,
            "folder": None,
            "last_read_target": None,
        }
        save_state(data)
    value = json.loads(STATE.read_text())
    if not isinstance(value, dict):
        raise RuntimeError("facility state malformed")
    return value


def render_caddyfile(data: dict) -> str:
    accounts = [data["guarded"], data["public"]]
    auth_lines = "\n".join(
        f"\t\t\t{row['username']} {row['hash']}" for row in accounts)
    guarded = data["guarded"]["username"]
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
\t\t@guarded expression `{{http.auth.user.id}} == \"{guarded}\"`
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
    def __init__(self, account: dict[str, str]):
        self.account = account
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
            with self.opener.open(request, timeout=30) as response:
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


def user_info(account: dict[str, str]) -> dict:
    client = PublicClient(account)
    client.login()
    return occ_json("user:info", account["username"], "--output=json")


def initialize() -> None:
    install_config(load_state())
    print("OK")


def configure_apps() -> None:
    data = load_state()
    occ("app:enable", "user_saml")
    occ("app:enable", "groupfolders")
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
    occ("config:system:set", "trusted_domains", "1", "--value=*")
    occ("config:system:set", "trusted_domains", "2", "--value=*_prod")
    save_state(data)
    print("OK")


def setup() -> None:
    data = load_state()
    guarded_info = user_info(data["guarded"])
    public_info = user_info(data["public"])
    if "SAML_guarded" not in (guarded_info.get("groups") or []):
        raise RuntimeError("guarded SSO group missing")
    if "SAML_guarded" in (public_info.get("groups") or []):
        raise RuntimeError("public account is guarded")
    folder = data.get("folder")
    if folder is None:
        folder = occ("groupfolders:create", "Guarded").splitlines()[-1]
        if not folder.isdigit():
            raise RuntimeError("Team Folder creation failed")
        occ("groupfolders:group", str(folder), "SAML_guarded", "read", "write")
        data["folder"] = folder
    save_state(data)
    print("OK")


def plant(target: str, encoded: str) -> None:
    if not READ_TARGET.fullmatch(target):
        raise ValueError("invalid guarded target")
    value = base64.b64decode(encoded, validate=True)
    if not value:
        raise ValueError("empty proof")
    data = load_state()
    client = PublicClient(data["guarded"])
    client.login()
    previous = data.get("last_read_target")
    if isinstance(previous, str) and previous != target:
        client.webdav("DELETE", previous)
    status, _ = client.webdav("PUT", target, value)
    read_status, actual = client.webdav("GET", target)
    if status not in (201, 204) or read_status != 200 or actual != value:
        raise RuntimeError("guarded placement failed")
    data["last_read_target"] = target
    save_state(data)
    print("OK")


def read(target: str) -> None:
    if not READ_TARGET.fullmatch(target):
        raise ValueError("invalid guarded target")
    data = load_state()
    client = PublicClient(data["guarded"])
    client.login()
    status, raw = client.webdav("GET", target)
    if status == 404:
        raise NotFound("guarded file absent")
    if status != 200:
        raise RuntimeError("guarded read failed")
    sys.stdout.buffer.write(raw + b"\n")


def checker_bundle() -> None:
    data = load_state()
    bundle = {
        "ordinary": {
            "username": data["public"]["username"],
            "password": data["public"]["password"],
        },
        "guarded": {
            "username": data["guarded"]["username"],
            "password": data["guarded"]["password"],
        },
    }
    print(json.dumps(bundle, separators=(",", ":"), sort_keys=True))


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
        elif command == "plant" and len(sys.argv) == 4:
            plant(sys.argv[2], sys.argv[3])
        elif command == "read" and len(sys.argv) == 3:
            read(sys.argv[2])
        elif command == "checker-bundle" and len(sys.argv) == 2:
            checker_bundle()
        elif command == "status" and len(sys.argv) == 2:
            status()
        else:
            return 2
        return 0
    except AuthRejected:
        return 3
    except NotFound:
        return 4
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError,
            json.JSONDecodeError, urllib.error.URLError):
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
