"""Private facility-derived identities for SuiteCRM's external checker."""

from __future__ import annotations

from functools import lru_cache
import base64
import hashlib
import hmac
import json
import os
import secrets

from challenges.interface import VulboxTarget

from ._ids import derive_principal

_FACILITY_TOKEN_ENV = "CYBERARENA_FACILITY_TOKEN"
_VERIFIER_TEAM_ID = "check"
CHECKER_POOL_SIZE = 4
COHORT_PATH = "/arena/state/issued-cohort"
_COHORT_LABEL = b"suitecrm-security-groups/v1/issued-cohort\0"


@lru_cache(maxsize=1)
def _verifier_secret() -> str:
    """Keep standalone verifier identities private and stable in this process."""

    return secrets.token_hex(32)


def private_identity_context(target: VulboxTarget) -> tuple[str, str]:
    """Return facility-only keying material and the victim identity."""

    team_id = target.meta.get("team_id")
    if not isinstance(team_id, str) or not team_id:
        raise RuntimeError("checker identity context unavailable")
    secret = os.environ.get(_FACILITY_TOKEN_ENV, "")
    if not secret:
        if team_id != _VERIFIER_TEAM_ID:
            raise RuntimeError("checker identity context unavailable")
        secret = _verifier_secret()
    return secret, team_id


def _digest(secret: str, team_id: str, label: str) -> str:
    return hmac.new(
        secret.encode(),
        f"suitecrm-security-groups\0{team_id}\0{label}".encode(),
        hashlib.sha256,
    ).hexdigest()


def _cohort_signature(target: VulboxTarget, payload: bytes) -> str:
    secret, _ = private_identity_context(target)
    return hmac.new(
        secret.encode(), _COHORT_LABEL + payload, hashlib.sha256
    ).hexdigest()


def seal_cohort(target: VulboxTarget, accounts: object) -> str:
    """Seal the issued cohort so health can tell it from defender-authored state."""

    payload = json.dumps(
        {"accounts": sorted(accounts), "v": 1},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    return f"{encoded}.{_cohort_signature(target, payload)}"


def sealed_cohort(target: VulboxTarget, sealed: str) -> tuple[tuple[str, str], ...]:
    """Recover the issued cohort only when the facility seal verifies."""

    encoded, _, signature = sealed.strip().partition(".")
    payload = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    if not hmac.compare_digest(signature, _cohort_signature(target, payload)):
        raise RuntimeError("issued principal cohort is untrusted")
    accounts = tuple(
        (username, password)
        for username, password in json.loads(payload)["accounts"]
    )
    if not accounts:
        raise RuntimeError("issued principal cohort is empty")
    return accounts


def _uuid(material: str) -> str:
    return (
        material[:8] + "-" + material[8:12] + "-" + material[12:16]
        + "-" + material[16:20] + "-" + material[20:32]
    )


def checker_setup(target: VulboxTarget) -> dict[str, object]:
    """Derive victim-specific ordinary accounts and shared OAuth credentials."""

    secret, team_id = private_identity_context(target)
    ordinary = tuple(
        derive_principal(_digest(secret, team_id, f"ordinary:{index}"))
        for index in range(CHECKER_POOL_SIZE)
    )
    guarded = tuple(
        derive_principal(_digest(secret, team_id, f"guarded:{index}"))
        for index in range(CHECKER_POOL_SIZE)
    )
    client = _digest(secret, team_id, "oauth")
    return {
        "ordinary": ordinary,
        "guarded": guarded,
        "client_id": _uuid(client),
        "client_secret": "S7!" + _digest(secret, team_id, "oauth-secret")[:40],
    }
