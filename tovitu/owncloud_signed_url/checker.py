"""Defender-independent network checker for ownCloud's declared workflow."""

from __future__ import annotations

import base64
import datetime
import hashlib
import http.client
import json
import secrets
import urllib.parse

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._health_identity import checker_credentials


def _request(
    host: str,
    port: int,
    method: str,
    path: str,
    body: bytes | None = None,
    *,
    username: str | None = None,
    password: str | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes]:
    final_headers = {"Connection": "close"}
    if username is not None:
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        final_headers["Authorization"] = f"Basic {token}"
    final_headers.update(headers or {})
    connection = http.client.HTTPConnection(host, port, timeout=5)
    try:
        connection.request(method, path, body=body, headers=final_headers)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def _signed_path(
    host: str, port: int, path: str, username: str, key: str
) -> str:
    params = [
        ("OC-Credential", username),
        ("OC-Date", datetime.datetime.now(datetime.timezone.utc).isoformat()),
        ("OC-Expires", "300"),
        ("OC-Verb", "GET"),
    ]
    query = urllib.parse.urlencode(params)
    unsigned = f"http://{host}:{port}{path}?{query}"
    signature = hashlib.pbkdf2_hmac(
        "sha512", unsigned.encode(), key.encode(), 10000, dklen=32
    ).hex()
    return f"{path}?{query}&OC-Signature={signature}"


class OwnCloudNetworkChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "owncloud-signed-url-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        host = target.host
        port = target.ports["service"]
        checks: list[tuple[str, bool, str]] = []
        try:
            primary, peer = checker_credentials(target)
            primary_user, primary_password = primary
            peer_user, peer_password = peer

            status, body = _request(host, port, "GET", "/status.php")
            installed = status == 200 and json.loads(body).get("installed") is True
            checks.append(("protocol", installed, f"status={status}"))

            path = (
                f"/remote.php/dav/files/{primary_user}/"
                "arena-health-check.txt"
            )
            content = ("cyber-arena-owncloud-" + secrets.token_hex(20)).encode()
            put_status, _ = _request(
                host,
                port,
                "PUT",
                path,
                content,
                username=primary_user,
                password=primary_password,
            )
            get_status, get_body = _request(
                host,
                port,
                "GET",
                path,
                username=primary_user,
                password=primary_password,
            )
            ordinary = (
                put_status in {201, 204}
                and get_status == 200
                and get_body == content
            )
            checks.append(
                ("ordinary-dav", ordinary, f"put={put_status},get={get_status}")
            )

            cross_status, cross_body = _request(
                host,
                port,
                "GET",
                path,
                username=peer_user,
                password=peer_password,
            )
            isolated = cross_status in {401, 403, 404} and cross_body != content
            checks.append(("peer-isolation", isolated, f"status={cross_status}"))

            key_status, key_body = _request(
                host,
                port,
                "GET",
                "/ocs/v1.php/cloud/user/signing-key?format=json",
                username=primary_user,
                password=primary_password,
                headers={"OCS-APIRequest": "true", "Accept": "application/json"},
            )
            key = json.loads(key_body).get("ocs", {}).get("data", {}).get(
                "signing-key"
            )
            if key_status == 200 and isinstance(key, str) and len(key) == 64:
                signed_status, signed_body = _request(
                    host,
                    port,
                    "GET",
                    _signed_path(host, port, path, primary_user, key),
                )
            else:
                signed_status, signed_body = 0, b""
            signed_ok = signed_status == 200 and signed_body == content
            checks.append(("signed-url", signed_ok, f"status={signed_status}"))
        except Exception as error:
            return CheckResult(
                name="checker", passed=False, detail=f"{type(error).__name__}"
            )

        failures = [f"{name}({detail})" for name, passed, detail in checks if not passed]
        return CheckResult(
            name="checker",
            passed=not failures,
            detail=(
                "; ".join(failures)
                if failures
                else "randomized DAV and signed URL workflow passed"
            ),
        )
