"""FlagHandler for faust-birthdaygram.

Inlines the upstream `place_flag` / `check_flag`: the flag is steganographically
embedded into a PNG and uploaded as a fresh user's PRIVATE image. Retrieve logs
back in as that user, fetches their view, and byte-compares the stored image.
Reuses the vendored `_checker/utils.py` (PNG/stego/HTTP) UNMODIFIED.
"""
from __future__ import annotations

import base64
import json
import logging

import requests

from challenges.interface import (
    FlagObservation,
    ObservationStatus,
    SingleFlagHandler,
    VulboxTarget,
)

from . import _net
from ._checker import utils

log = logging.getLogger(__name__)


def _pack(state: dict) -> str:
    return base64.b64encode(json.dumps(state).encode()).decode("ascii")


def _unpack(handle: str) -> dict | None:
    try:
        st = json.loads(base64.b64decode(handle))
        return st if isinstance(st, dict) and "flag" in st else None
    except Exception:
        return None


class BirthdaygramFlagHandler(SingleFlagHandler):
    @property
    def name(self) -> str:
        return "faust-birthdaygram-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def plant_one(self, target: VulboxTarget, flag: str) -> str:
        c = _net.make_checker(target)
        session = requests.session()
        username = utils.generate_name()
        password = utils.generate_password()
        try:
            utils.check_register(c, session, username, password)
            utils.check_login(c, session, username, password)
            flag_image = utils.create_image_with_flag(flag.encode())
            utils.upload_private_image(c, session, flag_image)
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(f"{self.name}: plant failed: {e}") from e
        return _pack({
            "flag_id": username,
            "username": username,
            "password": password,
            "flag": flag,
            "image_b64": base64.b64encode(flag_image).decode("ascii"),
        })

    def retrieve(
        self, target: VulboxTarget, handle: str, expected: str | None = None,
    ) -> FlagObservation:
        """Read-only structured observation. Never raises.

        Preserves the two-block boundary: a login-block failure is a
        precondition/service failure (ERROR), while the view/parse block splits
        a raised request error (ERROR) from a fetched-but-no-matching-image
        result (NOT_FOUND)."""
        st = _unpack(handle)
        if st is None:
            return FlagObservation(ObservationStatus.ERROR, detail="bad handle")
        try:
            try:
                flag_image = base64.b64decode(st["image_b64"])
            except Exception:  # noqa: BLE001
                return FlagObservation(
                    ObservationStatus.ERROR, detail="bad image handle")
            exp = expected if expected is not None else st["flag"]
            c = _net.make_checker(target)
            session = requests.session()
            try:
                utils.check_login(c, session, st["username"], st["password"])
            except Exception:  # noqa: BLE001
                return FlagObservation(
                    ObservationStatus.ERROR, detail="login failed")
            try:
                view = utils.get_view(c, session, st["username"])
            except Exception:  # noqa: BLE001
                return FlagObservation(
                    ObservationStatus.ERROR, detail="get_view failed")
            try:
                part = view.split("<img")[2].split("base64, ")[1].split(" />")[0]
                img_bytes = base64.decodebytes(part[:-1].encode("utf-8"))
            except Exception:  # noqa: BLE001
                return FlagObservation(
                    ObservationStatus.NOT_FOUND, detail="no image in view")
            if img_bytes == flag_image:
                return FlagObservation(ObservationStatus.PRESENT, value=exp)
            return FlagObservation(ObservationStatus.NOT_FOUND)
        except Exception:  # noqa: BLE001 — observe must never raise
            return FlagObservation(ObservationStatus.ERROR, detail="observe raised")

    def flag_id(self, handle: str) -> str | None:
        """Attack-info hook: the PUBLIC identifier the attacker targets — the
        username whose per-user image holds this round's flag (already computed
        in plant). None for an unparseable handle; never the flag value."""
        st = _unpack(handle)
        return st.get("flag_id") if st else None
