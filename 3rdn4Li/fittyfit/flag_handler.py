"""FlagHandler for faust-fittyfit.

Inlines the upstream `place_flag` / `check_flag`: the flag is rendered into a
PDF, uploaded, and "generated" as an NFT owned by a fresh TOTP-auth'd user.
Retrieve logs back in as that user and reads the flag out of the stored PDFs.
Protocol/PDF helpers live in `_client.py`.
"""
from __future__ import annotations

import base64
import json
import logging
from uuid import uuid4

import requests

from challenges.interface import SingleFlagHandler, VulboxTarget

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


class FittyfitFlagHandler(SingleFlagHandler):
    @property
    def name(self) -> str:
        return "faust-fittyfit-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def plant_one(self, target: VulboxTarget, flag: str) -> str:
        base = _net.base_url(target)
        session = requests.Session()
        if not _client.check_index(base):
            raise RuntimeError(f"{self.name}: index DOWN")
        pdf = _client.write_pdf(flag)
        uid = str(uuid4())
        name = "MrFlag_" + uid
        key = _client.register_user(session, base, name)
        if not key:
            raise RuntimeError(f"{self.name}: register failed")
        if not _client.login_user(session, base, name, key):
            raise RuntimeError(f"{self.name}: login failed")
        filename = "FlagNFT_" + uid + ".pdf"
        if not _client.upload_file(session, base, filename, pdf):
            raise RuntimeError(f"{self.name}: upload failed")
        data = {
            "step": "generate", "filename": filename, "creator": name,
            "description": "A great hacking exercise!",
            "part": "All parts of the brain", "score": "1337", "level": "medium",
        }
        if not _client.generate_file(session, base, data):
            raise RuntimeError(f"{self.name}: generate failed")
        return _pack({"flagid": name, "name": name, "key": key, "flag": flag})

    def retrieve(self, target: VulboxTarget, handle: str) -> str | None:
        st = _unpack(handle)
        if st is None:
            return None
        base = _net.base_url(target)
        session = requests.Session()
        if not _client.check_index(base):
            return None
        name, key, flag = st.get("name"), st.get("key"), st["flag"]
        if not _client.login_user(session, base, name, key):
            return None
        res = session.get(f"{base}/home")
        for f in res.text.split('<iframe src="')[1:]:
            path = f.split('"></iframe>')[0]
            try:
                pdf = _client.open_pdf_bytes(
                    session.get(f"{base}" + path, stream=True).content)
                if flag.encode() in _client.read_pdf(pdf):
                    return flag
            except Exception:  # noqa: BLE001
                continue
        return None
