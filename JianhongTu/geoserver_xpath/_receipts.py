"""Shared public-resource paths for ordinary GeoServer receipt traffic."""

from __future__ import annotations

import base64
import math
import re
import secrets
import urllib.parse

_SAFE_PATH = re.compile(
    r"[A-Za-z0-9_-]{4,80}(?:/[A-Za-z0-9_-]{4,80}){0,3}"
    r"(?:\.(?:bin|csv|dat|json|log|txt|xml))?"
)
_EXTENSIONS = ("", ".bin", ".csv", ".dat", ".json", ".log", ".txt", ".xml")


def receipt_path(entropy: bytes | None = None) -> str:
    """Return an open-ended, URL-safe relative resource path."""
    if entropy is None:
        entropy = secrets.token_bytes(24 + secrets.randbelow(57))
    if not isinstance(entropy, bytes) or len(entropy) < 8:
        raise ValueError("receipt entropy is too short")
    encoded = base64.urlsafe_b64encode(entropy).decode().rstrip("=")
    depth = max(1 + entropy[0] % 4, math.ceil(len(encoded) / 80))
    extension = _EXTENSIONS[entropy[1] % len(_EXTENSIONS)]
    width, remainder = divmod(len(encoded), depth)
    segments = []
    offset = 0
    for index in range(depth):
        length = width + (1 if index < remainder else 0)
        segments.append(encoded[offset:offset + length])
        offset += length
    path = "/".join(segments) + extension
    if _SAFE_PATH.fullmatch(path) is None:
        raise RuntimeError("generated receipt path is invalid")
    return path


def validate_receipt_path(path: object) -> str:
    if not isinstance(path, str) or _SAFE_PATH.fullmatch(path) is None:
        raise ValueError("invalid public receipt path")
    return path


def public_receipt_path(path: object) -> str:
    relative = validate_receipt_path(path)
    return "/geoserver/www/" + urllib.parse.quote(relative, safe="/-._~")


def rest_receipt_path(path: object) -> str:
    relative = validate_receipt_path(path)
    return "/geoserver/rest/resource/www/" + urllib.parse.quote(
        relative, safe="/-._~"
    )


def filesystem_receipt_path(path: object) -> str:
    return "/opt/geoserver_data/www/" + validate_receipt_path(path)
