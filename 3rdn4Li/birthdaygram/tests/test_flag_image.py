"""The planted image must carry the flag as TEXT.

stegano 3.0.0 (2026-07-19) made lsb.hide() encode its message itself, so the
bytes the handler used to pass raise "'bytes' object has no attribute 'encode'"
— every plant failed from 2026-07-28. Under 2.x the same bytes silently hid the
garbled repr `b'FLAG{…` instead of the flag. Both are fixed by passing a str.
"""

from __future__ import annotations

import io
from unittest import mock

import pytest
from stegano import lsb

from challenges.interface import VulboxTarget

from birthdaygram import flag_handler
from birthdaygram._checker import utils


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    (tmp_path / "images").mkdir()
    (tmp_path / "flags").mkdir()
    monkeypatch.setattr(utils, "CUR_DIR", str(tmp_path))
    return tmp_path


def _reveal(png: bytes) -> str:
    return lsb.reveal(io.BytesIO(png))


def test_image_hides_the_flag_text_exactly(workdir):
    png = utils.create_image_with_flag("FLAG{a1b2c3}")
    assert png.startswith(b"\x89PNG")
    assert _reveal(png) == "FLAG{a1b2c3}"


def test_bytes_input_is_tolerated_and_still_hides_text(workdir):
    png = utils.create_image_with_flag(b"FLAG{a1b2c3}")
    assert _reveal(png) == "FLAG{a1b2c3}"          # not "b'FLAG{…"


def test_plant_one_hands_the_helper_a_str(workdir, monkeypatch):
    seen = []
    real = utils.create_image_with_flag

    def spy(flag):
        seen.append(flag)
        return real(flag)

    monkeypatch.setattr(utils, "create_image_with_flag", spy)
    monkeypatch.setattr(utils, "check_register", lambda *a, **k: None)
    monkeypatch.setattr(utils, "check_login", lambda *a, **k: None)
    monkeypatch.setattr(utils, "upload_private_image", lambda *a, **k: None)
    monkeypatch.setattr(flag_handler._net, "make_checker", lambda target: object())

    h = flag_handler.BirthdaygramFlagHandler() if hasattr(flag_handler, "BirthdaygramFlagHandler") \
        else next(v for v in vars(flag_handler).values()
                  if isinstance(v, type) and hasattr(v, "plant_one") and v.__module__ == flag_handler.__name__)()
    handle = h.plant_one(mock.Mock(spec=VulboxTarget), "FLAG{zz}")
    assert seen == ["FLAG{zz}"] and isinstance(seen[0], str)
    assert isinstance(handle, str) and handle
