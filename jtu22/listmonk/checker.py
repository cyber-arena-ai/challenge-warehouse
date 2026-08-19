"""External Listmonk gameplay checker.

Fresh fixtures are provisioned through the facility's privileged exec bridge;
all authoritative behavior is then exercised from this process over the public
Listmonk HTTP service as the restricted subscriber-data analyst.
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import ipaddress
import json
import random
import secrets
import socket
import subprocess
import urllib.error
import urllib.parse
import urllib.request

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

PROVISION_COMMAND = "/arena/checker.py --provision"
USER = "ops-analyst"
TOKEN = "ops-analyst-token-a7f3e9c15b4d"
TIMEOUT = 15


def _connectable(host: str, port: int) -> bool:
    try:
        socket.create_connection((host, port), 3).close()
        return True
    except OSError:
        return False


def resolve_host(target: VulboxTarget) -> str | None:
    """Return an address reachable from the external poller process."""
    host = target.host
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return host if _connectable(host, target.ports["service"]) else None

    # Docker Compose service aliases used by games contain underscores (for
    # example ``team1_prod``).  They are resolvable on the game network, but
    # MinIO rejects them as HTTP Host values when verifying an S3 signature.
    # Prefer the alias's numeric IPv4 address so the same host works for both
    # listmonk and the signed private-object health check.
    try:
        address = socket.gethostbyname(host)
    except OSError:
        address = None
    if address is not None and _connectable(address, target.ports["service"]):
        return address

    if _connectable(host, target.ports["service"]):
        return host
    try:
        output = subprocess.run(
            [
                "docker",
                "inspect",
                "-f",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
                host,
            ],
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.split()
        return next(
            (address for address in output if _connectable(address, target.ports["service"])),
            None,
        )
    except Exception:  # noqa: BLE001 - Docker is absent in facility pollers
        return None


def _headers() -> dict[str, str]:
    headers = {"Authorization": f"token {USER}:{TOKEN}"}
    accept = random.choice((None, "application/json", "*/*", "text/csv, */*"))
    agent = random.choice(
        (None, "curl/8.5.0", "listmonk-ops/1.2", "python-requests/2.32")
    )
    if accept:
        headers["Accept"] = accept
    if agent:
        headers["User-Agent"] = agent
    if random.random() < 0.5:
        headers["X-Request-ID"] = secrets.token_hex(8)
    return headers


def _request(base: str, path: str, *, raw: bool = False):
    request = urllib.request.Request(base + path, headers=_headers())
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            status, payload = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, payload = error.code, error.read()
    if status != 200:
        raise RuntimeError(f"legitimate API request returned HTTP {status}")
    return payload.decode(errors="replace") if raw else json.loads(payload)


def _signing_key(secret: str, date: str) -> bytes:
    date_key = hmac.new(
        ("AWS4" + secret).encode(), date.encode(), hashlib.sha256
    ).digest()
    region_key = hmac.new(date_key, b"us-east-1", hashlib.sha256).digest()
    service_key = hmac.new(region_key, b"s3", hashlib.sha256).digest()
    return hmac.new(service_key, b"aws4_request", hashlib.sha256).digest()


def _object_request(host: str, port: int, facts: dict[str, str]) -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    authority = f"{host}:{port}"
    path = "/" + urllib.parse.quote(f"{facts['bucket']}/{facts['object']}", safe="/")
    payload_hash = hashlib.sha256(b"").hexdigest()
    canonical_headers = (
        f"host:{authority}\n"
        f"x-amz-content-sha256:{payload_hash}\n"
        f"x-amz-date:{amz_date}\n"
    )
    signed_headers = "host;x-amz-content-sha256;x-amz-date"
    canonical_request = (
        f"GET\n{path}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    )
    scope = f"{date}/us-east-1/s3/aws4_request"
    string_to_sign = (
        "AWS4-HMAC-SHA256\n"
        f"{amz_date}\n{scope}\n"
        f"{hashlib.sha256(canonical_request.encode()).hexdigest()}"
    )
    signature = hmac.new(
        _signing_key(facts["secret_key"], date),
        string_to_sign.encode(),
        hashlib.sha256,
    ).hexdigest()
    authorization = (
        f"AWS4-HMAC-SHA256 Credential={facts['access_key']}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    request = urllib.request.Request(
        f"http://{authority}{path}",
        headers={
            "Authorization": authorization,
            "X-Amz-Content-Sha256": payload_hash,
            "X-Amz-Date": amz_date,
        },
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        if response.status != 200:
            raise RuntimeError(f"private object read returned HTTP {response.status}")
        return response.read().decode(errors="replace")


def _terms(alias: str, values: dict[str, str]) -> list[str]:
    """Predicates over allowed subscriber JSON, including protected-looking data."""
    terms = [
        (
            f"{alias}.attribs->>'{values['selector_key']}' "
            f"= '{values['selector_value']}'"
        ),
        f"{alias}.attribs->>'settings' = '{values['settings']}'",
        f"{alias}.attribs->>'users' = '{values['users']}'",
        (
            f"{alias}.attribs->>'upload.s3.aws_secret_access_key' "
            f"= '{values['key']}'"
        ),
    ]
    random.shuffle(terms)
    return terms


def _direct_expression(values: dict[str, str]) -> str:
    terms = _terms("subscribers", values)
    expression = " AND ".join(f"({term})" for term in terms)
    if random.random() < 0.5:
        expression = f"TRUE AND ({expression})"
    return expression


def _nested_expression(values: dict[str, str]) -> str:
    alias = "s" + secrets.token_hex(random.choice((2, 3, 4)))
    terms = _terms(alias, values)
    random.shuffle(terms)
    return (
        f"EXISTS (SELECT 1 FROM subscribers AS {alias} "
        f"WHERE {alias}.id = subscribers.id AND "
        + " AND ".join(f"({term})" for term in terms)
        + ")"
    )


def _assert_result(payload, present: str, absent: str) -> None:
    names = [row["name"] for row in payload["data"]["results"]]
    if present not in names or absent in names:
        raise RuntimeError("subscriber query returned the wrong fixture set")


def _assert_export(payload: str, present: str, absent: str) -> None:
    if present not in payload or absent in payload:
        raise RuntimeError("subscriber export returned the wrong fixture set")


def _exercise(base: str, facts: dict[str, object]) -> None:
    fixtures = facts["fixtures"]
    if not isinstance(fixtures, list) or len(fixtures) != 2:
        raise RuntimeError("provisioner returned an invalid fixture envelope")

    expressions = (
        _direct_expression(fixtures[0]["values"]),
        _nested_expression(fixtures[1]["values"]),
    )
    scoped_first = bool(secrets.randbits(1))
    for index, (fixture, expression) in enumerate(
        zip(fixtures, expressions, strict=True)
    ):
        query = urllib.parse.quote(expression)
        use_scope = (index == 0) == scoped_first
        scope = f"list_id={facts['list_id']}&" if use_scope else ""
        page_size = random.choice((100, 250, 500))
        query_payload = _request(
            base,
            f"/api/subscribers?{scope}query={query}&per_page={page_size}",
        )
        _assert_result(query_payload, fixture["present"], fixture["absent"])
        export_payload = _request(
            base,
            f"/api/subscribers/export?{scope}query={query}",
            raw=True,
        )
        _assert_export(export_payload, fixture["present"], fixture["absent"])


class ListmonkChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "listmonk-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service", "object_store")

    def run(self, target: VulboxTarget) -> CheckResult:
        host = resolve_host(target)
        if host is None:
            return CheckResult("checker", False, "public service is unreachable")

        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            return CheckResult("checker", False, "fixture facility is unavailable")
        rc, output = exec_in(target.host, PROVISION_COMMAND)
        if rc != 0:
            return CheckResult("checker", False, "fresh fixture provisioning failed")

        try:
            facts = json.loads(output)
            _exercise(f"http://{host}:{target.ports['service']}", facts)
            object_facts = facts["object_store"]
            value = _object_request(host, target.ports["object_store"], object_facts)
            if value != object_facts["expected"]:
                raise RuntimeError("private object health fixture returned the wrong value")
        except Exception as exc:  # noqa: BLE001 - broken gameplay is a failed check
            return CheckResult(
                "checker",
                False,
                f"query/export or private-object workflow failed: {type(exc).__name__}",
            )
        return CheckResult(
            "checker",
            True,
            "legitimate subscriber query/export and private-object workflows passed",
        )
