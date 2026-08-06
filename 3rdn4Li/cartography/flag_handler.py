"""FlagHandler for faust-cartography.

Inlines the upstream `place_flag` / `check_flag`: create a sector sized to the
flag, write the flag at offset 0, save it (server returns a sector name).
Retrieve loads that sector by name and reads the flag back. Raw-socket protocol
helpers live in `_client.py`.
"""
from __future__ import annotations

import base64
import json
import logging

import nclib

from challenges.interface import (
    FlagObservation,
    ObservationStatus,
    SingleFlagHandler,
    VulboxTarget,
)

from . import _client, _net

log = logging.getLogger(__name__)


def _pack(state: dict) -> str:
    return base64.b64encode(json.dumps(state).encode()).decode("ascii")


def _unpack(handle: str) -> dict | None:
    try:
        st = json.loads(base64.b64decode(handle))
        return st if isinstance(st, dict) and "flag" in st else None
    except Exception:
        return None


class CartographyFlagHandler(SingleFlagHandler):
    @property
    def name(self) -> str:
        return "faust-cartography-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def plant_one(self, target: VulboxTarget, flag: str) -> str:
        conn = _client.connect(_net.resolve(target))
        if conn is None:
            raise RuntimeError(f"{self.name}: connect failed (DOWN)")
        try:
            _client.new_sector(conn, len(flag))
            _client.fill_sector(conn, 0, flag)
            sector = _client.save_sector(conn)
        except (_client.ClientError, nclib.NetcatError, UnicodeDecodeError) as e:
            raise RuntimeError(f"{self.name}: plant failed: {e}") from e
        finally:
            conn.close()
        return _pack({"flagid": sector, "sector": sector, "flag": flag})

    def retrieve(self, target: VulboxTarget, handle: str, expected: str | None = None) -> FlagObservation:
        """Structured, read-only read of the flag via the load_sector/read_sector path."""
        try:
            st = _unpack(handle)
            if st is None:
                return FlagObservation(ObservationStatus.ERROR, detail="bad handle")
            exp = expected if expected is not None else st["flag"]
            conn = _client.connect(_net.resolve(target))
            if conn is None:
                return FlagObservation(ObservationStatus.ERROR, detail="connect failed (DOWN)")
            try:
                if not _client.load_sector(conn, st["sector"]):
                    return FlagObservation(ObservationStatus.NOT_FOUND, detail="sector gone")
                found = _client.read_sector(conn, 0, len(st["flag"]))
                if found == exp:
                    return FlagObservation(ObservationStatus.PRESENT, value=found)
                if found:
                    return FlagObservation(ObservationStatus.MISMATCH, value=found)
                return FlagObservation(ObservationStatus.NOT_FOUND, detail="empty sector read")
            except (_client.ClientError, nclib.NetcatError, UnicodeDecodeError) as e:
                return FlagObservation(ObservationStatus.ERROR, detail=type(e).__name__)
            finally:
                conn.close()
        except Exception as e:  # noqa: BLE001 — retrieve must never raise
            return FlagObservation(ObservationStatus.ERROR, detail=f"unexpected: {type(e).__name__}")
