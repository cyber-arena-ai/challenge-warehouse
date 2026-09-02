"""Identifier derivation and flag handles for grav-editor-sandbox.

Deliberately framework-free and stdlib-only, for three reasons: the flag handler
(flag-service container), the checker (health-poller container) and the private
exploit (attacker container) all need the same encodings; the exploit copy
contract only carries same-directory ``_*.py`` siblings; and the pieces that are
worth unit-testing — seed derivation, the handle codec, the helper invocation —
are then testable with no repository integration at all.

Nothing here ever emits a credential or a flag into a public field: ``flag_id``
returns only the target half of a handle, and the derivation functions are pure.
"""

from __future__ import annotations

import base64
import binascii
import json
import shlex

# ── stores ──────────────────────────────────────────────────────────────────

STORE_JWT = "jwt_secret"
STORE_COMMAND = "command"

# The READ store's public locator: the logical config key that holds the site's
# API signing credential. A logical target, never a filesystem path.
JWT_TARGET = "plugins.api.auth.jwt_secret"

# ── the command objective's fixed helper ────────────────────────────────────

CATFLAG_PATH = "/usr/local/bin/catflag"
SERVICE_USER = "grav"


def catflag_command(operation_id: str, *, service_user: str = SERVICE_USER) -> str:
    """The one supported way to exercise the command objective: run the fixed
    helper AS the unprivileged service account, passing the current operation id.

    Used verbatim by ``retrieve`` (through privileged docker-exec) so the audit
    exercises the same helper and the same execution context an attacker must
    reach — reading the backing file through a privileged bypass would let a
    defender delete the helper, deny every capture, and still look intact.
    """
    if not operation_id:
        raise ValueError("operation id must be non-empty")
    return (
        f"runuser -u {shlex.quote(service_user)} -- "
        f"{shlex.quote(CATFLAG_PATH)} {shlex.quote(operation_id)}"
    )


# ── baseline principals ─────────────────────────────────────────────────────

# Grav's default account policy wants a mixed-case password with a digit; the
# fixed prefix supplies both, the seed slice supplies the entropy.
_PASSWORD_PREFIX = "Ed1-"


def derive_principal(seed: str) -> tuple[str, str]:
    """``seed -> (username, password)`` for one attacker's baseline principal.

    Derived from the per-assignment seed ALONE — never from a team id, a host, or
    another attacker's assignment — so no team can compute another's credential.
    Deterministic, so a re-derivation inside one setup call agrees with itself.
    """
    material = "".join(c for c in seed.lower() if c in "0123456789abcdef")
    if len(material) < 34:
        raise ValueError("seed does not carry enough material to derive a principal")
    return "editor" + material[:10], _PASSWORD_PREFIX + material[10:34]


# ── flag handles ────────────────────────────────────────────────────────────


def pack_handle(payload: dict) -> str:
    """Opaque, single-token handle. Facility-private: it packs the flag so
    ``retrieve`` can default its comparison, and is never published anywhere."""
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unpack_handle(handle: str) -> dict | None:
    """Inverse of `pack_handle`; ``None`` for anything unparseable, so every
    caller (including the must-never-raise ``retrieve``) can guard on it."""
    if not isinstance(handle, str) or not handle:
        return None
    padded = handle + "=" * (-len(handle) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(padded.encode()))
    except (ValueError, binascii.Error):
        return None
    return payload if isinstance(payload, dict) else None


def public_flag_id(handle: str) -> str | None:
    """The PUBLIC attack-info locator for a handle — the target half only.

    READ store  → the logical config key holding the site's signing credential.
    EXECUTE store → this round's operation id, the argument the fixed helper
                    requires. Never the flag, never the facility credential.
    """
    payload = unpack_handle(handle)
    if payload is None:
        return None
    if payload.get("store") == STORE_JWT:
        target = payload.get("target")
        return target if isinstance(target, str) and target else None
    if payload.get("store") == STORE_COMMAND:
        operation = payload.get("op")
        return operation if isinstance(operation, str) and operation else None
    return None
