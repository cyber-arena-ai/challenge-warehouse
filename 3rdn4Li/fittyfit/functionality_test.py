"""FunctionalityTest for faust-fittyfit.

Inlines the upstream `check_service`: register + TOTP login, upload a PDF,
generate the NFT, then fetch /home and confirm the PDF's content is readable
back through pikepdf. Returns a CheckResult tree (tcp + checker leaves).
"""
from __future__ import annotations

import logging
import random
import string
from uuid import uuid4

import requests

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from . import _client, _net

log = logging.getLogger(__name__)


def _rand(n=12):
    return "".join(random.choice(string.ascii_letters) for _ in range(n))


class FittyfitFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "faust-fittyfit-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        base = _net.base_url(target)
        try:
            up = _client.check_index(base)
            tcp_detail = "GET / 200" if up else "GET / non-200"
        except Exception as e:  # noqa: BLE001
            up, tcp_detail = False, f"connect failed: {e}"
        tcp = CheckResult(name="tcp", passed=up, detail=tcp_detail)
        if not up:
            return CheckResult(name="faust-fittyfit", passed=False, children=[tcp])

        ok, detail = self._check(base)
        checker = CheckResult(name="checker", passed=ok, detail=detail[-200:])
        return CheckResult(name="faust-fittyfit",
                           passed=tcp.passed and checker.passed, children=[tcp, checker])

    def _check(self, base: str) -> tuple[bool, str]:
        session = requests.Session()
        name = "User" + _rand()
        key = _client.register_user(session, base, name)
        if not key:
            return False, "register failed"
        if not _client.login_user(session, base, name, key):
            return False, "login failed"

        pdf_content = _rand()
        pdf = _client.write_pdf(pdf_content)
        filename = str(uuid4()) + ".pdf"
        if not _client.upload_file(session, base, filename, pdf):
            return False, "upload failed"
        data = {
            "step": "generate", "filename": filename, "creator": name,
            "description": _rand(), "part": _rand(), "score": "10", "level": "easy",
        }
        if not _client.generate_file(session, base, data):
            return False, "generate failed"

        res = session.get(f"{base}/home")
        files = res.text.split('<iframe src="')
        if len(files) < 2:
            return False, "no NFT files listed on /home"
        contents = []
        for f in files[1:]:
            path = f.split('"></iframe>')[0]
            if name not in path:
                return False, f"NFT path missing owner: {path}"
            try:
                pdf_obj = _client.open_pdf_bytes(
                    session.get(f"{base}" + path, stream=True).content)
                contents.append(_client.read_pdf(pdf_obj))
            except Exception:  # noqa: BLE001
                continue
        if pdf_content.encode() not in b"".join(contents):
            return False, "uploaded PDF content not readable back"
        return True, "register/login/upload/generate/read round-trip OK"
