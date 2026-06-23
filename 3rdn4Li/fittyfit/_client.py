"""Protocol client for faust-fittyfit (HTTP + PDF). `baseurl` carries a
trailing slash like the original checker's base URL.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import logging
import struct
import time

import requests
from fpdf import FPDF
from pikepdf import Pdf

log = logging.getLogger(__name__)


def totp(key, interval=60):
    now = time.time()
    try:
        key = key.encode()
        counter = struct.pack(">Q", int(now / interval))
        mac = hmac.new(key, counter, hashlib.sha256).digest()
        password = base64.b32encode(mac).decode().replace("=", "")
    except Exception as e:  # noqa: BLE001
        log.error("totp: %s", e)
        password = None
    return password


def check_index(baseurl) -> bool:
    res = requests.get(f"{baseurl}/")
    return res.status_code == 200


def register_user(session, baseurl, username):
    res = session.post(baseurl + "register", data={"name": username})
    if res.status_code != 200:
        return None
    try:
        return res.text.split("This is your key: <b>")[1].split("</b>")[0]
    except Exception:  # noqa: BLE001
        return None


def login_user(session, baseurl, username, key) -> bool:
    password = totp(key)
    res = session.post(baseurl + "login", data={"name": username, "pass": password})
    return res.status_code == 200 and "home" in res.url


def upload_file(session, baseurl, filename, pdf) -> bool:
    res = session.post(baseurl + "generate",
                       files={"file": (filename, pdf)}, data={"step": "upload"})
    return "M.toast" not in res.text


def generate_file(session, baseurl, data) -> bool:
    res = session.post(baseurl + "generate", data=data)
    return "succesfully" in res.text


def write_pdf(text):
    pdf = FPDF("P", "mm", "A4")
    # Keep the content stream uncompressed: retrieve() searches the raw page
    # bytes for the flag, so the drawn text must stay plaintext in the PDF.
    pdf.set_compression(False)
    pdf.add_page()
    pdf.set_font("Arial", "B", 18)
    pdf.cell(40, 5, text, 0, 1)
    return bytes(pdf.output())


def read_pdf(pdf):
    return pdf.pages[0].Contents.read_bytes()


def open_pdf_bytes(content):
    return Pdf.open(io.BytesIO(content))
