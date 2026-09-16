"""Framework-free principal, target, handle, and helper encodings."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import urllib.parse
import xml.etree.ElementTree as ET

STORE_GUARDED_FILE = "guarded_file"
STORE_COMMAND = "command"
SERVICE_USER = "service"
OBJECTIVE_HELPER = "/usr/local/bin/caddy-objective"
CHECKER_PRINCIPAL_COUNT = 4
CHECKER_CHAIN_LIMIT = 8
CHECKER_HISTORY_MIN = 2
CHECKER_HISTORY_MAX = 6
CHECKER_LOGIN_LIMIT = 2_000_000
CHECKER_RESPONSE_LIMIT = 32768
CHECKER_LISTING_LIMIT = 262144
CHECKER_TARGET_LIMIT = 80
_FACILITY_TOKEN_ENV = "CYBERARENA_FACILITY_TOKEN"

_READ_TARGET = re.compile(
    r"Guarded/[a-z]+(?P<sep>[-_ ])(?:[a-z]+(?P=sep)){0,3}"
    r"[0-9a-f]{32}\.txt"
)
_OPERATION = re.compile(r"[0-9a-f]{32}")
_DOCUMENT_SEPARATORS = ("-", "_", " ")
_REFERENCE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_CHECKER_DOCUMENT_KINDS = ("control", "shadow", "cover")

_WORDS = (
    "autumn", "bridge", "campus", "chapter", "circle", "coastal", "course",
    "creative", "design", "digital", "discovery", "evening", "field",
    "garden", "guide", "history", "ideas", "journey", "language", "learning",
    "library", "local", "making", "modern", "morning", "museum", "nature",
    "notes", "online", "pathways", "people", "planning", "practical",
    "project", "reading", "research", "resources", "science", "season",
    "seminar", "skills", "stories", "studio", "summary", "teaching", "topic",
    "training", "travel", "workshop", "writing",
)


def document_words(minimum: int, maximum: int) -> list[str]:
    count = minimum + secrets.randbelow(maximum - minimum + 1)
    return [secrets.choice(_WORDS) for _ in range(count)]


def document_name() -> str:
    separator = secrets.choice(_DOCUMENT_SEPARATORS)
    return separator.join((*document_words(1, 4), secrets.token_hex(16))) + ".txt"


def objective_document_name(material: bytes) -> str:
    """Return one ordinary-shape deterministic scored document name."""
    if not isinstance(material, bytes) or not material:
        raise ValueError("document identity material is unavailable")
    stream = bytearray(material)
    cursor = 0
    expansion = 0

    def refill() -> None:
        nonlocal expansion
        stream.extend(hashlib.sha256(
            b"caddy-objective-name\0"
            + expansion.to_bytes(4, "big")
            + material
        ).digest())
        expansion += 1

    def choose(options):
        nonlocal cursor
        limit = 256 - (256 % len(options))
        while True:
            if cursor == len(stream):
                refill()
            value = stream[cursor]
            cursor += 1
            if value < limit:
                return options[value % len(options)]

    word_count = 1 + choose(range(4))
    separator = choose(_DOCUMENT_SEPARATORS)
    words = [choose(_WORDS) for _ in range(word_count)]
    while len(stream) - cursor < 16:
        refill()
    nonce = bytes(stream[cursor:cursor + 16]).hex()
    return separator.join((*words, nonce)) + ".txt"


def _facility_token(team_id: str) -> str:
    token = os.environ.get(_FACILITY_TOKEN_ENV, "")
    if not token or not team_id:
        raise RuntimeError("facility document material is unavailable")
    return token


def _checker_tag(team_id: str, slot: int, kind: str, prefix: str) -> str:
    if kind not in _CHECKER_DOCUMENT_KINDS:
        raise ValueError("invalid checker document kind")
    token = _facility_token(team_id)
    return hmac.new(
        token.encode(),
        (
            f"caddy-nextcloud-sso:{team_id}:guarded-name:"
            f"{slot}:{kind}:{prefix}"
        ).encode(),
        hashlib.sha256,
    ).hexdigest()[:16]


def checker_document_identity(team_id: str, target: str) -> tuple[int, str] | None:
    """Identify a facility-authenticated checker filename and opaque role."""
    if not valid_read_target(target):
        return None
    stem = target.removesuffix(".txt")
    prefix = stem[:-16]
    tag = stem[-16:]
    identities = [
        (slot, kind)
        for slot in range(CHECKER_PRINCIPAL_COUNT)
        for kind in _CHECKER_DOCUMENT_KINDS
        if hmac.compare_digest(tag, _checker_tag(team_id, slot, kind, prefix))
    ]
    if len(identities) > 1:
        raise RuntimeError("ambiguous checker document identity")
    return identities[0] if identities else None


def checker_document_owner(team_id: str, target: str) -> int | None:
    """Identify a facility-authenticated checker filename without body markers."""
    identity = checker_document_identity(team_id, target)
    return identity[0] if identity else None


def checker_document_body(team_id: str, slot: int, target: str) -> bytes:
    """Synthesize one authenticated inert reference shaped like a scored proof."""
    if checker_document_owner(team_id, target) != slot:
        raise ValueError("checker document owner mismatch")
    token = _facility_token(team_id)
    material = b"".join(
        hmac.new(
            token.encode(),
            (
                f"caddy-nextcloud-sso:{team_id}:guarded-body:"
                f"{slot}:{target}:{block}"
            ).encode(),
            hashlib.sha256,
        ).digest()
        for block in range(3)
    )
    reference_values = [value for value in material if value < 252][:32]
    if len(reference_values) != 32:
        raise RuntimeError("checker document material is incomplete")
    reference = "FLAG{" + "".join(
        _REFERENCE_ALPHABET[value % len(_REFERENCE_ALPHABET)]
        for value in reference_values
    ) + "}"
    return reference.encode()


def _checker_document_from_material(
    team_id: str, slot: int, kind: str, material: bytes,
) -> tuple[str, bytes]:
    if not 0 <= slot < CHECKER_PRINCIPAL_COUNT:
        raise ValueError("invalid checker principal slot")
    stream = bytearray(material)
    cursor = 0
    expansion = 0

    def refill() -> None:
        nonlocal expansion
        stream.extend(hashlib.sha256(
            b"caddy-checker-name\0"
            + expansion.to_bytes(4, "big")
            + material
        ).digest())
        expansion += 1

    def choose(options):
        nonlocal cursor
        limit = 256 - (256 % len(options))
        while True:
            if cursor == len(stream):
                refill()
            value = stream[cursor]
            cursor += 1
            if value < limit:
                return options[value % len(options)]

    word_count = 1 + choose(range(4))
    separator = choose(_DOCUMENT_SEPARATORS)
    words = [choose(_WORDS) for _ in range(word_count)]
    while len(stream) - cursor < 8:
        refill()
    nonce = bytes(stream[cursor:cursor + 8]).hex()
    prefix = "Guarded/" + separator.join((*words, nonce))
    target = prefix + _checker_tag(team_id, slot, kind, prefix) + ".txt"
    return target, checker_document_body(team_id, slot, target)


def checker_document_seed(
    team_id: str, slot: int, kind: str = "control",
) -> tuple[str, bytes]:
    """Return the deterministic first record for one checker owner."""
    if kind not in _CHECKER_DOCUMENT_KINDS:
        raise ValueError("invalid checker document kind")
    token = _facility_token(team_id)
    material = hmac.new(
        token.encode(),
        f"caddy-nextcloud-sso:{team_id}:guarded-seed:{slot}:{kind}".encode(),
        hashlib.sha256,
    ).digest()
    return _checker_document_from_material(team_id, slot, kind, material)


def checker_document_successor(
    team_id: str, slot: int, current: str,
) -> tuple[str, bytes]:
    """Return the one authenticated successor of a current checker record."""
    identity = checker_document_identity(team_id, current)
    if identity is None or identity[0] != slot:
        raise ValueError("checker document owner mismatch")
    kind = identity[1]
    token = _facility_token(team_id)
    material = hmac.new(
        token.encode(),
        (
            f"caddy-nextcloud-sso:{team_id}:guarded-next:"
            f"{slot}:{kind}:{current}"
        ).encode(),
        hashlib.sha256,
    ).digest()
    successor = _checker_document_from_material(team_id, slot, kind, material)
    if successor[0] == current:
        raise RuntimeError("checker document successor did not advance")
    return successor


def _checker_pair_owner(material: bytes) -> int:
    stream = bytearray(material)
    expansion = 0
    limit = 256 - (256 % CHECKER_PRINCIPAL_COUNT)
    while True:
        for value in stream:
            if value < limit:
                return value % CHECKER_PRINCIPAL_COUNT
        stream = bytearray(hashlib.sha256(
            b"caddy-checker-owner\0"
            + expansion.to_bytes(4, "big")
            + material
        ).digest())
        expansion += 1


def _checker_pair_from_material(
    team_id: str, material: bytes,
) -> tuple[int, tuple[str, bytes], tuple[str, bytes]]:
    token = _facility_token(team_id)
    owner_material = hmac.new(
        token.encode(), b"caddy-checker-pair-owner\0" + material,
        hashlib.sha256,
    ).digest()
    control_material = hmac.new(
        token.encode(), b"caddy-checker-pair-control\0" + material,
        hashlib.sha256,
    ).digest()
    owner = _checker_pair_owner(owner_material)
    control = _checker_document_from_material(
        team_id, owner, "control", control_material)
    shadow = checker_pair_shadow(team_id, owner, control[0])
    return owner, control, shadow


def checker_pair_shadow(
    team_id: str, owner: int, control_target: str,
) -> tuple[str, bytes]:
    """Return the authenticated untouched companion for one control."""
    if checker_document_identity(team_id, control_target) != (owner, "control"):
        raise ValueError("checker pair control owner mismatch")
    token = _facility_token(team_id)
    shadow_material = hmac.new(
        token.encode(),
        f"caddy-nextcloud-sso:{team_id}:guarded-pair:{control_target}".encode(),
        hashlib.sha256,
    ).digest()
    return _checker_document_from_material(
        team_id, owner, "shadow", shadow_material)


def objective_cover_body(target: str) -> bytes:
    """Return inert, non-scoring content for a seed-derived cover record."""
    if not valid_read_target(target):
        raise ValueError("invalid guarded cover target")
    material = hashlib.sha256(
        b"caddy-nextcloud-sso\0guarded-objective-cover-body\0v1\0"
        + target.encode()
    ).digest()
    return (
        "FLAG{" + "".join(
            _REFERENCE_ALPHABET[value % len(_REFERENCE_ALPHABET)]
            for value in material
        ) + "}"
    ).encode()


def checker_pair_seed(
    team_id: str,
) -> tuple[int, tuple[str, bytes], tuple[str, bytes]]:
    """Return the first authenticated checker pair and its opaque owner."""
    token = _facility_token(team_id)
    material = hmac.new(
        token.encode(),
        f"caddy-nextcloud-sso:{team_id}:guarded-pair-seed".encode(),
        hashlib.sha256,
    ).digest()
    return _checker_pair_from_material(team_id, material)


def checker_pair_successor(
    team_id: str, current_control: str,
) -> tuple[int, tuple[str, bytes], tuple[str, bytes]]:
    """Return the unique next pair with a facility-secret uniform owner."""
    identity = checker_document_identity(team_id, current_control)
    if identity is None or identity[1] != "control":
        raise ValueError("checker pair control is invalid")
    token = _facility_token(team_id)
    material = hmac.new(
        token.encode(),
        (
            f"caddy-nextcloud-sso:{team_id}:guarded-pair-next:"
            f"{current_control}"
        ).encode(),
        hashlib.sha256,
    ).digest()
    return _checker_pair_from_material(team_id, material)


def checker_pair_chain(
    team_id: str, targets: list[str],
) -> tuple[tuple[int, str, str], ...]:
    """Validate and order one bounded global control/shadow pair chain."""
    if not targets or len(targets) > 2 * CHECKER_CHAIN_LIMIT:
        raise RuntimeError("invalid guarded checker pair queue")
    identities = {
        target: checker_document_identity(team_id, target) for target in targets
    }
    if (len(identities) != len(targets)
            or any(identity is None or identity[1] not in ("control", "shadow")
                   for identity in identities.values())):
        raise RuntimeError("invalid guarded checker pair queue")
    controls = {
        target: identity[0] for target, identity in identities.items()
        if identity[1] == "control"
    }
    shadows = {
        target for target, identity in identities.items()
        if identity[1] == "shadow"
    }
    pairs = {}
    for control, owner in controls.items():
        expected_shadow = checker_pair_shadow(team_id, owner, control)[0]
        if expected_shadow not in shadows:
            raise RuntimeError("incomplete guarded checker pair")
        pairs[control] = (owner, control, expected_shadow)
    if len(pairs) != len(shadows):
        raise RuntimeError("unpaired guarded checker shadow")
    successors = {
        control: checker_pair_successor(team_id, control)[1][0]
        for control in controls
    }
    parents = {}
    for parent, successor in successors.items():
        if successor not in controls:
            continue
        if successor in parents:
            raise RuntimeError("forked guarded checker pair queue")
        parents[successor] = parent
    roots = set(controls) - set(parents)
    tips = {
        control for control, successor in successors.items()
        if successor not in controls
    }
    if len(roots) != 1 or len(tips) != 1:
        raise RuntimeError("forked guarded checker pair queue")
    ordered = []
    visited = set()
    current = next(iter(roots))
    while current in pairs and current not in visited:
        visited.add(current)
        ordered.append(pairs[current])
        current = successors[current]
    if len(ordered) != len(pairs) or ordered[-1][1] not in tips:
        raise RuntimeError("broken guarded checker pair queue")
    return tuple(ordered)


def checker_document_chain(
    team_id: str, slot: int, targets: list[str],
) -> tuple[str, ...]:
    """Validate one bounded predecessor-to-successor chain and return its order."""
    if not targets or len(targets) > CHECKER_CHAIN_LIMIT:
        raise RuntimeError(f"invalid checker document chain for slot {slot}")
    nodes = set(targets)
    if len(nodes) != len(targets):
        raise RuntimeError(f"duplicate checker document for slot {slot}")
    identities = {checker_document_identity(team_id, target) for target in nodes}
    if (None in identities or any(identity[0] != slot for identity in identities)
            or len({identity[1] for identity in identities}) != 1):
        raise RuntimeError(f"foreign checker document in slot {slot}")
    successors = {
        target: checker_document_successor(team_id, slot, target)[0]
        for target in nodes
    }
    parents: dict[str, str] = {}
    for parent, successor in successors.items():
        if successor not in nodes:
            continue
        if successor in parents:
            raise RuntimeError(f"forked checker document chain for slot {slot}")
        parents[successor] = parent
    roots = nodes - set(parents)
    tips = {target for target, successor in successors.items()
            if successor not in nodes}
    if len(roots) != 1 or len(tips) != 1:
        raise RuntimeError(f"forked checker document chain for slot {slot}")
    ordered = []
    current = next(iter(roots))
    while current in nodes and current not in ordered:
        ordered.append(current)
        current = successors[current]
    if len(ordered) != len(nodes) or ordered[-1] not in tips:
        raise RuntimeError(f"broken checker document chain for slot {slot}")
    return tuple(ordered)


def checker_document_descends_from(
    team_id: str, slot: int, ancestor: str, candidate: str,
) -> bool:
    """Return whether candidate is a bounded successor of ancestor."""
    current = ancestor
    for _ in range(CHECKER_CHAIN_LIMIT + 1):
        if hmac.compare_digest(current, candidate):
            return True
        current = checker_document_successor(team_id, slot, current)[0]
    return False


def guarded_listing_targets(username: str, raw: bytes) -> tuple[str, ...]:
    """Extract bounded direct ordinary-shape records from a WebDAV listing."""
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as error:
        raise RuntimeError("guarded WebDAV listing is malformed") from error
    folder = f"/remote.php/dav/files/{urllib.parse.quote(username, safe='')}/Guarded"
    targets = []
    for response in root.findall("{DAV:}response"):
        href = response.findtext("{DAV:}href")
        if not href:
            raise RuntimeError("guarded WebDAV listing has no href")
        path = urllib.parse.unquote(urllib.parse.urlsplit(href).path).rstrip("/")
        if path == folder:
            continue
        if not path.startswith(folder + "/"):
            raise RuntimeError("guarded WebDAV listing escaped its folder")
        name = path[len(folder) + 1:]
        if "/" not in name:
            target = "Guarded/" + name
            if valid_read_target(target):
                targets.append(target)
    if len(targets) > CHECKER_TARGET_LIMIT or len(targets) != len(set(targets)):
        raise RuntimeError("guarded WebDAV listing is ambiguous")
    return tuple(targets)


def derive_principal(seed: str) -> tuple[str, str]:
    material = "".join(c for c in seed.lower() if c in "0123456789abcdef")
    if len(material) < 48:
        raise ValueError("seed does not carry enough material")
    return "user" + material[:16], "C1!" + material[16:48]


def guarded_principals_from_material(
    team_id: str, material: str,
) -> tuple[tuple[str, str], ...]:
    if not material or not team_id:
        raise RuntimeError("guarded principal material is unavailable")
    rows = []
    for slot in range(CHECKER_PRINCIPAL_COUNT):
        identity = hmac.new(
            material.encode(),
            f"caddy-nextcloud-sso:{team_id}:guarded:{slot}".encode(),
            hashlib.sha256,
        ).hexdigest()
        rows.append(("user" + identity[:16], "C1!" + identity[16:48]))
    return tuple(rows)


def guarded_principals(team_id: str) -> tuple[tuple[str, str], ...]:
    """Target-specific guarded accounts shared by trusted facilities.

    These identities are reserved for the elevated Team Folder positive path.
    Ordinary health workflows use the complete issued participant cohort.
    """
    token = os.environ.get(_FACILITY_TOKEN_ENV, "")
    if not token or not team_id:
        raise RuntimeError("guarded principal material is unavailable")
    return guarded_principals_from_material(team_id, token)


def valid_read_target(value: str) -> bool:
    return isinstance(value, str) and _READ_TARGET.fullmatch(value) is not None


def valid_operation(value: str) -> bool:
    return isinstance(value, str) and _OPERATION.fullmatch(value) is not None


def pack_handle(payload: dict) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unpack_handle(handle: str) -> dict | None:
    if not isinstance(handle, str) or not handle:
        return None
    try:
        value = json.loads(base64.urlsafe_b64decode(
            (handle + "=" * (-len(handle) % 4)).encode()))
    except (ValueError, binascii.Error):
        return None
    return value if isinstance(value, dict) else None


def public_flag_id(handle: str) -> str | None:
    payload = unpack_handle(handle)
    if payload is None:
        return None
    target = payload.get("target")
    if payload.get("store") == STORE_GUARDED_FILE and valid_read_target(target):
        return target
    if payload.get("store") == STORE_COMMAND and valid_operation(target):
        return target
    return None


def objective_command(operation: str) -> str:
    if not valid_operation(operation):
        raise ValueError("invalid operation id")
    return (
        f"su-exec {shlex.quote(SERVICE_USER)}:{shlex.quote(SERVICE_USER)} "
        f"{shlex.quote(OBJECTIVE_HELPER)} {shlex.quote(operation)}"
    )
