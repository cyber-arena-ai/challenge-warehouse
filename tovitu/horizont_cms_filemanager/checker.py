"""External issued-Editor legitimate-workflow checker for HorizontCMS."""

from __future__ import annotations

import csv
import html
import io
import json
import secrets
import string

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._client import HorizontError, exercise_filemanager, login
from .cohort import COHORT_PATH, open_issued_cohort


_FILE_TYPES = (
    ("txt", "text/plain"),
    ("md", "text/markdown"),
    ("csv", "text/csv"),
    ("json", "application/json"),
    ("xml", "application/xml"),
    ("bin", "application/octet-stream"),
)
_NAME_ALPHABET = string.ascii_letters + string.digits + "-_"
_TEXT_ALPHABET = string.ascii_letters + string.digits + string.punctuation + " \t"


def _fragment(minimum: int = 8, spread: int = 24) -> str:
    length = minimum + secrets.randbelow(spread + 1)
    return "".join(secrets.choice(_NAME_ALPHABET) for _ in range(length))


def _text(minimum: int = 8, spread: int = 24) -> str:
    length = minimum + secrets.randbelow(spread + 1)
    return "".join(secrets.choice(_TEXT_ALPHABET) for _ in range(length))


def _fresh_file(file_type: tuple[str, str]) -> tuple[bytes, str, str, str]:
    extension, content_type = file_type
    if extension == "txt":
        content = "\n".join(
            _text(12, 52) for _ in range(2 + secrets.randbelow(8))
        ).encode()
    elif extension == "md":
        content = (
            f"# {_text()}\n\n"
            + " ".join(
                _text(4, 16) for _ in range(8 + secrets.randbelow(24))
            )
            + "\n"
        ).encode()
    elif extension == "csv":
        rows = 3 + secrets.randbelow(8)
        columns = 2 + secrets.randbelow(5)
        stream = io.StringIO(newline="")
        writer = csv.writer(stream)
        writer.writerows(
            [_text(4, 12) for _ in range(columns)] for _ in range(rows)
        )
        content = stream.getvalue().encode()
    elif extension == "json":
        content = json.dumps(
            {
                _text(5, 12): _text(6, 30)
                for _ in range(2 + secrets.randbelow(7))
            },
            separators=(",", ":"),
        ).encode()
    elif extension == "xml":
        entries = "".join(
            f'<entry key="{html.escape(_text(5, 12), quote=True)}">'
            f"{html.escape(_text(8, 28))}</entry>"
            for _ in range(2 + secrets.randbelow(7))
        )
        document_id = html.escape(_text(8, 16), quote=True)
        content = f'<document id="{document_id}">{entries}</document>'.encode()
    else:
        content = secrets.token_bytes(128 + secrets.randbelow(896))

    source = f"{_fragment(10, 30)}.{extension}"
    destination = f"{_fragment(10, 30)}.{extension}"
    while destination == source:
        destination = f"{_fragment(10, 30)}.{extension}"
    return content, source, destination, content_type


class HorizontCmsChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "horizont-cms-filemanager-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        base_url = f"http://{target.host}:{target.ports['service']}"
        try:
            observations = []
            exec_in = target.meta.get("exec_in_container")
            if not callable(exec_in):
                raise RuntimeError("issued cohort unavailable")
            rc, sealed = exec_in(target.host, f"cat {COHORT_PATH}")
            if rc != 0:
                raise RuntimeError("issued cohort unavailable")
            identities = open_issued_cohort(sealed or "")
            for username, password in identities:
                file_type = secrets.choice(_FILE_TYPES)
                content, source, destination, content_type = _fresh_file(file_type)
                session = login(base_url, username, password)
                exercise_filemanager(
                    session, content, source, destination, content_type
                )
                observations.append((source, destination, content_type, len(content)))
        except Exception as exc:
            detail = "workflow rejected" if isinstance(exc, HorizontError) else type(exc).__name__
            return CheckResult(name="checker", passed=False, detail=detail)

        return CheckResult(
            name="checker",
            passed=len(observations) == len(identities),
            detail=f"{len(observations)} issued Editor workflows passed",
        )
