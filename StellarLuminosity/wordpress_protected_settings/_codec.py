"""Private round-context and handle codecs."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re


STORE = "protected-setting"
TARGET_RE = re.compile(r"site_private_[0-9a-f]{24}")


def derive(seed: str, label: str) -> bytes:
    if not isinstance(seed, str) or re.fullmatch(r"[0-9a-f]{64}", seed) is None:
        raise ValueError("round context seed is unavailable")
    return hmac.new(bytes.fromhex(seed), label.encode(), hashlib.sha256).digest()


def target_option(seed: str) -> str:
    return "site_private_" + derive(seed, f"{STORE}:option-name").hex()[:24]


def context_id(seed: str) -> str:
    return derive(seed, f"{STORE}:generation").hex()


def valid_target(value: object) -> bool:
    return isinstance(value, str) and TARGET_RE.fullmatch(value) is not None


def pack_handle(target: str, proof: str) -> str:
    raw = json.dumps(
        {"v": 1, "target": target, "proof": proof},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unpack_handle(handle: str) -> tuple[str, str] | None:
    try:
        raw = base64.urlsafe_b64decode(handle + "=" * (-len(handle) % 4))
        value = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict) or set(value) != {"v", "target", "proof"}:
        return None
    target = value.get("target")
    proof = value.get("proof")
    if value.get("v") != 1 or not valid_target(target) or not isinstance(proof, str):
        return None
    return target, proof
