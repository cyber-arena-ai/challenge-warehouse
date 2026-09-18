"""NATS principals, MQTT client IDs, round context, and opaque handles."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import string

_SEED = re.compile(r"[0-9a-f]{64}")
_DEVICE = re.compile(r"device-[0-9a-f]{16}")
_ARCHIVE = re.compile(r"[0-9a-f]{24}")
_PASSWORD = re.compile(r"N1![0-9a-f]{48}")
_FACILITY_TOKEN_ENV = "CYBERARENA_FACILITY_TOKEN"
ISSUED_COHORT_FILE = "/arena/state/issued-cohort"
ARCHIVE_DIR = "/arena/archive"

# Measured against the built image: a CONNECT client ID is accepted when it is
# valid UTF-8 of 0-65535 bytes holding none of these characters, and rejected
# with return code 2 otherwise. Every other code point, every length in that
# range, and every pairing with an issued credential connects, publishes and
# subscribes. A zero-length ID is accepted only with the clean-session flag
# every client here sets, and the server then names the session itself. So the
# ID is a free CONNECT field with no grammar of its own to inherit.
_CLIENT_ID_FORBIDDEN = frozenset("\x00\t\n\x0c\r *.>")
_CLIENT_ID_ORDINARY = string.ascii_letters + string.digits + "-_"


def _client_id_char() -> str:
    """Draw uniformly from every character the server accepts in a client ID."""
    while True:
        point = secrets.randbelow(0x110000)
        if 0xD800 <= point <= 0xDFFF:
            continue  # an unpaired surrogate is not valid UTF-8
        char = chr(point)
        if char not in _CLIENT_ID_FORBIDDEN:
            return char


def _ordinary_client_id(size: int) -> str:
    """Return the plain alphanumeric shape an ordinary MQTT library emits."""
    return "".join(secrets.choice(_CLIENT_ID_ORDINARY) for _ in range(size))


def client_id() -> str:
    """Draw one ordinary or full-space MQTT client ID.

    Half of draws use the plain alphanumeric shape ordinary libraries emit.
    The other half gives every identifier accepted by the pinned server nonzero
    probability: each character is uniform over the accepted code points, and
    the byte budget takes the lower of two magnitudes so the whole 0-65535 range
    stays reachable while the mean stays small. Checker and PoV both use this
    exact distribution, so neither role has a client-ID shape of its own.

    The budget is weighted rather than flat because probes share one executor
    with every other challenge in the poller; see the maintainer README.
    """
    if secrets.randbits(1):
        return _ordinary_client_id(8 + secrets.randbelow(25))
    budget = secrets.randbelow(
        1 << min(secrets.randbelow(17), secrets.randbelow(17))
    )
    value: list[str] = []
    used = 0
    while True:
        char = _client_id_char()
        width = len(char.encode())
        if used + width > budget:
            return "".join(value)
        value.append(char)
        used += width


def _derive(seed: str, domain: str) -> bytes:
    if not isinstance(seed, str) or _SEED.fullmatch(seed) is None:
        raise ValueError("seed must be 64 lowercase hexadecimal characters")
    return hmac.new(
        bytes.fromhex(seed),
        f"nats-mqtt-acl\0v1\0{domain}".encode(),
        hashlib.sha256,
    ).digest()


def derive_principal(seed: str) -> tuple[str, str]:
    """Return one native, equal-role device identity from an assignment seed."""
    username = "device-" + _derive(seed, "principal-id").hex()[:16]
    password = "N1!" + _derive(seed, "principal-secret").hex()[:48]
    return username, password


def _facility_material(team_id: str, domain: str) -> str:
    if not isinstance(team_id, str) or not team_id:
        raise ValueError("team id is unavailable")
    return hmac.new(
        _facility_key(),
        f"nats-mqtt-acl:{team_id}:{domain}".encode(),
        hashlib.sha256,
    ).hexdigest()


def _facility_key() -> bytes:
    token = os.environ.get(_FACILITY_TOKEN_ENV, "")
    if not token:
        raise RuntimeError("facility principal material is unavailable")
    return token.encode()


def _cohort_tag(payload: bytes) -> str:
    return hmac.new(
        _facility_key(),
        b"nats-mqtt-acl/v1/issued-cohort\0" + payload,
        hashlib.sha256,
    ).hexdigest()


def issued_cohort(principals: object) -> str:
    """Seal the complete issued device cohort for external health probes."""
    payload = json.dumps(
        sorted(principals), separators=(",", ":"), ensure_ascii=True
    ).encode()
    encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    return f"{encoded}.{_cohort_tag(payload)}"


def verified_issued_cohort(sealed: str) -> tuple[tuple[str, str], ...]:
    """Return a nonempty issued cohort only when its facility seal verifies."""
    try:
        encoded, separator, tag = sealed.strip().partition(".")
        if not separator:
            raise ValueError
        payload = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True
        )
        if not hmac.compare_digest(tag, _cohort_tag(payload)):
            raise ValueError
        decoded = json.loads(payload)
        principals = tuple(
            (username, password) for username, password in decoded
        )
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("issued principal cohort is untrusted") from error
    if (
        not principals
        or len(principals) != len(set(principals))
        or any(
            _DEVICE.fullmatch(username) is None
            or _PASSWORD.fullmatch(password) is None
            for username, password in principals
        )
    ):
        raise RuntimeError("issued principal cohort is invalid")
    return principals


def facility_publisher(team_id: str) -> tuple[str, str]:
    """Return the target's match-long legitimate victim publisher identity."""
    material = _facility_material(team_id, "publisher")
    return "publisher-" + material[:16], "N1!" + material[16:64]


def round_context(seed: object) -> dict[str, str]:
    """Derive proof-independent identities for exactly one round."""
    if not isinstance(seed, str):
        raise ValueError("round context seed is unavailable")
    report = _derive(seed, "round-report-id").hex()[:24]
    return {
        "target": f"victim/secret/{report}",
        "public_target": f"victim/public/{report}",
        "public_value": "telemetry-" + _derive(
            seed, "round-public-payload"
        ).hex()[:24],
        "retained_value": "reading-" + _derive(
            seed, "round-retained-payload"
        ).hex()[:24],
        "archive_id": _derive(seed, "round-archive-id").hex()[:24],
    }


def pack_handle(payload: dict[str, str]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unpack_handle(handle: str) -> dict[str, str] | None:
    try:
        raw = base64.urlsafe_b64decode(handle + "=" * (-len(handle) % 4))
        value = json.loads(raw)
    except (ValueError, TypeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and isinstance(item, str)
        for key, item in value.items()
    ):
        return None
    return value


def public_flag_id(handle: str) -> str | None:
    payload = unpack_handle(handle)
    if payload is None or payload.get("store") != "offline_archive":
        return None
    archive_id = payload.get("archive_id")
    if not valid_archive(archive_id):
        return None
    return archive_path(archive_id)


def archive_path(archive_id: str) -> str:
    return f"{ARCHIVE_DIR}/{archive_id}.record"


def valid_archive(value: object) -> bool:
    return isinstance(value, str) and _ARCHIVE.fullmatch(value) is not None
