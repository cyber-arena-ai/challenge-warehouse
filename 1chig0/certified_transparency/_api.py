"""Wire protocol + binary (de)serialization for certified-transparency.

A faithful, stdlib+httpx port of the upstream `checkers/api.py` / `exploits/api.py`
used by the FlagHandler / FunctionalityTest in the host (orchestrator) process.

Two HTTP daemons:
  * log     http://<ip>:3000  — get-pubkey, get-sth, get-entries,
                                 get-entry-and-proof, add-entry, sign-entry
  * monitor http://<ip>:3001  — get-pubkey, claim-private, claim-public, /watch ws

The binary encodings match the Go `pkg/models/serialization.go` byte-for-byte.
"""
from __future__ import annotations

import json
import struct
from base64 import b64decode, b64encode
from dataclasses import dataclass, field
from hashlib import sha3_256
from typing import Any

import httpx

LOG_PORT = 3000
MONITOR_PORT = 3001
_TIMEOUT = 8.0


class ApiError(Exception):
    """Transport- or protocol-level failure talking to the service."""


# ---- low-level helpers (mirror models/serialization.go) --------------------

def byte_slice(b: bytes) -> bytes:
    return struct.pack(">H", len(b)) + b


def read_byte_slice(b: bytes) -> tuple[bytes, bytes]:
    (l,) = struct.unpack(">H", b[:2])
    return b[2:2 + l], b[2 + l:]


def read_string(b: bytes) -> bytes:
    return b[1:1 + b[0]]


def write_string(b: bytes) -> bytes:
    return bytes([len(b)]) + b


def json_encode(data: dict[str, Any]) -> bytes:
    out = dict(data)
    for k, v in list(out.items()):
        if isinstance(v, bytes):
            out[k] = b64encode(v).decode()
    return json.dumps(out).encode()


# ---- models ----------------------------------------------------------------

@dataclass
class Sth:
    size: int
    timestamp: bytes
    hash: bytes
    signature: bytes

    @classmethod
    def from_binary(cls, b: bytes) -> "Sth":
        return Sth(
            int.from_bytes(b[:8], "big"),
            b[8:8 + 15],
            b[8 + 15:8 + 15 + 32],
            b[8 + 15 + 32:],
        )

    def to_binary(self) -> bytes:
        return struct.pack(">Q", self.size) + self.timestamp + self.hash + self.signature


@dataclass
class TreeLeaf:
    created: bytes
    contenthash: bytes
    name: bytes
    pubkey: bytes
    data_private: bytes
    data_public: bytes

    def to_binary(self) -> bytes:
        assert len(self.created) == 15
        assert len(self.contenthash) == 32
        return (
            self.created
            + byte_slice(self.contenthash + struct.pack(">B", len(self.name)) + self.name)
            + byte_slice(self.pubkey)
            + byte_slice(self.data_private)
            + byte_slice(self.data_public)
        )

    @classmethod
    def from_binary(cls, data: bytes) -> "TreeLeaf":
        ts = data[:15]
        owner, data = read_byte_slice(data[15:])
        pubkey, data = read_byte_slice(data)
        data_private, data = read_byte_slice(data)
        data_public, data = read_byte_slice(data)
        return TreeLeaf(ts, owner[:32], read_string(owner[32:]), pubkey, data_private, data_public)


@dataclass
class TreeLeafProof:
    head: Sth
    index: int
    leaf: bytes
    hashes: list[bytes] = field(default_factory=list)

    def to_binary(self) -> bytes:
        return (
            byte_slice(self.head.to_binary())
            + struct.pack(">Q", self.index)
            + byte_slice(self.leaf)
            + struct.pack(">H", len(self.hashes))
            + b"".join(self.hashes)
        )

    @classmethod
    def from_binary(cls, data: bytes) -> "TreeLeafProof":
        head, data = read_byte_slice(data)
        (index,) = struct.unpack(">Q", data[:8])
        leaf, data = read_byte_slice(data[8:])
        (hash_len,) = struct.unpack(">H", data[:2])
        hashes = [data[2 + i * 32:2 + i * 32 + 32] for i in range(hash_len)]
        return TreeLeafProof(Sth.from_binary(head), index, leaf, hashes)


# ---- HTTP client -----------------------------------------------------------

class Api:
    def __init__(self, ip: str) -> None:
        self.ip = ip
        self._c = httpx.Client(timeout=_TIMEOUT)

    def close(self) -> None:
        try:
            self._c.close()
        except Exception:
            pass

    def __enter__(self) -> "Api":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def _log(self, path: str) -> str:
        return f"http://{self.ip}:{LOG_PORT}{path}"

    def _mon(self, path: str) -> str:
        return f"http://{self.ip}:{MONITOR_PORT}{path}"

    def _json(self, r: httpx.Response, key: str) -> Any:
        if r.status_code != 200:
            raise ApiError(f"{r.request.url.path}: HTTP {r.status_code}: {r.text[:120]}")
        try:
            d = r.json()
        except Exception as e:
            raise ApiError(f"{r.request.url.path}: non-JSON: {r.text[:120]}") from e
        if key not in d:
            raise ApiError(f"{r.request.url.path}: missing {key!r}")
        return d[key]

    def get_pubkey(self, from_monitor: bool = False) -> bytes:
        url = self._mon("/api/v1/get-pubkey") if from_monitor else self._log("/api/v1/get-pubkey")
        return b64decode(self._json(self._c.get(url), "pubkey"))

    def get_sth(self) -> bytes:
        return b64decode(self._json(self._c.get(self._log("/api/v1/get-sth")), "sth"))

    def get_entries(self, start: int, end: int) -> list[bytes]:
        r = self._c.get(self._log(f"/api/v1/get-entries?start={start}&end={end}"))
        return [b64decode(x) for x in self._json(r, "leaves")]

    def get_entry_proof(self, index: int) -> bytes:
        r = self._c.get(self._log(f"/api/v1/get-entry-and-proof?leaf_index={index}"))
        return b64decode(self._json(r, "proof"))

    def add_entry(self, entry: dict[str, Any]) -> int:
        r = self._c.post(self._log("/api/v1/add-entry"), content=json_encode(entry))
        idx = self._json(r, "index")
        if not isinstance(idx, int):
            raise ApiError("add-entry: non-int index")
        return idx

    def sign_entry(self, entry: dict[str, Any]) -> bytes:
        r = self._c.post(self._log("/api/v1/sign-entry"), content=json_encode(entry))
        return b64decode(self._json(r, "sot"))

    def claim_private(self, sot: bytes, claimed_leaf: bytes) -> str:
        r = self._c.post(self._mon("/api/v1/claim-private"),
                         content=json_encode({"sot": sot, "claimed_leaf": claimed_leaf}))
        return self._claim_data(r)

    def claim_public(self, claiming_leaf: bytes, claimed_leaf: bytes, signature: bytes) -> str:
        r = self._c.post(self._mon("/api/v1/claim-public"), content=json_encode({
            "claiming_leaf": claiming_leaf,
            "claimed_leaf": claimed_leaf,
            "claiming_leaf_signature": signature,
        }))
        return self._claim_data(r)

    def _claim_data(self, r: httpx.Response) -> str:
        if r.status_code != 200:
            raise ApiError(f"claim: HTTP {r.status_code}: {r.text[:120]}")
        d = r.json()
        if not d.get("granted"):
            raise ApiError(f"claim not granted: {r.text[:120]}")
        return d["data"]
