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

from challenges.interface import SingleFlagHandler, VulboxTarget

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
            "flagid": username,
            "username": username,
            "password": password,
            "flag": flag,
            "image_b64": base64.b64encode(flag_image).decode("ascii"),
        })

    def retrieve(self, target: VulboxTarget, handle: str) -> str | None:
        st = _unpack(handle)
        if st is None:
            return None
        try:
            flag_image = base64.b64decode(st["image_b64"])
        except Exception:
            return None
        c = _net.make_checker(target)
        session = requests.session()
        try:
            utils.check_login(c, session, st["username"], st["password"])
        except Exception:  # noqa: BLE001
            return None
        try:
            view = utils.get_view(c, session, st["username"])
            part = view.split("<img")[2].split("base64, ")[1].split(" />")[0]
            img_bytes = base64.decodebytes(part[:-1].encode("utf-8"))
        except Exception:  # noqa: BLE001
            return None
        return st["flag"] if img_bytes == flag_image else None

    def flag_id(self, handle: str) -> str | None:
        """Attack-info hook: the PUBLIC identifier the attacker targets — the
        username whose per-user image holds this round's flag (already computed
        in plant). None for an unparseable handle; never the flag value."""
        st = _unpack(handle)
        return st.get("flagid") if st else None
