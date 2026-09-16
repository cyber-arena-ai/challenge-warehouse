"""Deep, public-network Navigate CMS workflow checker."""

from __future__ import annotations

import secrets
import string
import threading

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from . import _http
from .config import COHORT_FILE, sealed_cohort


_NAME_ALPHABET = string.ascii_letters + string.digits + "-_"
_TEXT_ALPHABET = string.ascii_letters + string.digits + " .,:;()[]!?-_\n"
_CONTEXT_HEADERS = ("User-Agent", "Accept", "Accept-Language", "Accept-Encoding")
# Nothing on this workflow gates on these headers: `login.php` reads
# Accept-Language only to pick the login page's language, which no assertion here
# depends on. Measured on the image, the service serves tab and every byte from
# 0x20 up except DEL, on a "Name: value" line no longer than _FIELD_LINE_LIMIT,
# and serves the request just as well with the header left out. That whole space
# is open to a participant too.
_CONTEXT_ALPHABET = "\t" + "".join(
    chr(code) for code in range(0x20, 0x100) if code != 0x7F
)
_FIELD_LINE_LIMIT = 8191
# `mod_deflate` is the one server-side reader among these headers: it compresses
# when Accept-Encoding offers gzip and not otherwise, and `_http.request` decodes
# what comes back. A free-form draw lands on any of these tokens about once in
# 20000, so the tokens themselves are drawn; their number, order, separator and
# the free-form tokens beside them are not.
_ENCODING_TOKENS = ("gzip", "deflate", "identity", "br", "zstd", "compress", "*")
_TOKEN_ALPHABET = string.ascii_letters + string.digits + "-_.*;="


_LOCKS_GUARD = threading.Lock()
_LOCKS: dict[tuple[str, int], threading.Lock] = {}


def _lock(target: VulboxTarget) -> threading.Lock:
    """Serialize probes per target: a concurrent remembered login rotates the
    single `cookie_hash` column and invalidates the other probe's token."""
    key = (target.host, target.ports["service"])
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(key, threading.Lock())


def _free_form(alphabet: str, minimum: int, maximum: int) -> str:
    size = minimum + secrets.randbelow(maximum - minimum + 1)
    return "".join(secrets.choice(alphabet) for _ in range(size))


def _negotiated_value() -> str:
    """A content-negotiation value: drawn encoding tokens among free-form ones.

    Every token is a whole token, so no draw opens with the empty one that makes
    Apache stop reading the header.
    """
    tokens = [
        secrets.choice(_ENCODING_TOKENS) if secrets.randbelow(2)
        else _free_form(_TOKEN_ALPHABET, 1, 32)
        for _ in range(1 + secrets.randbelow(4))
    ]
    return secrets.choice((",", ", ")).join(tokens)


def _context_value(name: str) -> str | None:
    """One header value, or None to leave the header out of the request.

    The value is free-form over everything the service accepts, its length drawn
    through a random bound so that short values stay common; drawn flat it would
    be long almost every time, and "long header" would characterize health on its
    own. Accept-Encoding draws a third way as well, because it is the one header
    a defender can read a decision out of rather than only a shape.
    """
    outcome = secrets.randbelow(3 if name == "Accept-Encoding" else 2)
    if not outcome:
        return None
    if outcome > 1:
        return _negotiated_value()
    ceiling = _FIELD_LINE_LIMIT - len(name) - len(": ")
    return _free_form(_CONTEXT_ALPHABET, 0, secrets.randbelow(ceiling + 1))


def _request_context() -> dict[str, str]:
    """Draw one round's request context from the whole accepted header space.

    Each header is independently absent or free-form over every accepted value,
    so health has no shape a defender can require: a rule that admits what
    health sends admits what an ordinary participant sends as well.
    """
    drawn = ((name, _context_value(name)) for name in _CONTEXT_HEADERS)
    return {name: value for name, value in drawn if value is not None}


def _upload_name() -> str:
    return _free_form(_NAME_ALPHABET, 8, 24) + ".txt"


def _upload_body() -> bytes:
    return _free_form(_TEXT_ALPHABET, 48, 512).encode()


def _issued_cohort(target: VulboxTarget) -> tuple[tuple[str, str], ...]:
    """Read the facility-sealed issued cohort out of root-only bookkeeping."""
    exec_in = target.meta.get("exec_in_container")
    if not callable(exec_in):
        raise RuntimeError("Navigate issued cohort is unavailable")
    rc, output = exec_in(target.host, f"cat {COHORT_FILE}")
    if rc != 0:
        raise RuntimeError("Navigate issued cohort is unavailable")
    return sealed_cohort(output or "")


class NavigateChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "navigate-cms-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        lock = _lock(target)
        if not lock.acquire(timeout=120):
            return CheckResult("checker", False, "another probe did not finish")
        try:
            cohort = _issued_cohort(target)
            base = f"http://{target.host}:{target.ports['service']}/navigate"
            for username, password in cohort:
                context = _request_context()
                opener, session_id = _http.login(
                    base, username, password, headers=context, remember=True
                )
                self._media_workflow(base, opener, session_id, context)
            return CheckResult(
                "checker", True,
                "issued User persistent login/dashboard/media round-trip passed",
            )
        except Exception as exc:
            return CheckResult("checker", False, f"workflow failed: {type(exc).__name__}")
        finally:
            lock.release()

    @staticmethod
    def _media_workflow(base: str, opener, session_id: str, context: dict) -> None:
        """Register media either side of the promised TinyMCE upload.

        `before` and `after` are created by the application's own
        `file::register_upload`, so they are consecutive ids of the live media
        sequence. A TinyMCE upload that registers nothing cannot report an id
        between them, because consecutive ids leave no room for one.
        """
        created: list[int] = []
        try:
            before = _http.register_upload(
                base, opener, session_id, _upload_name(), _upload_body(),
                headers=context,
            )
            created.append(before)
            filename, marker = _upload_name(), _upload_body()
            media = _http.ordinary_upload(
                base, opener, session_id, filename, marker, headers=context,
                on_registered=created.append,
            )
            after = _http.register_upload(
                base, opener, session_id, _upload_name(), _upload_body(),
                headers=context,
            )
            created.append(after)
            if not before < media < after:
                raise RuntimeError("registered media left the live media sequence")
        finally:
            cleanup_errors = []
            for media_id in created:
                try:
                    _http.delete_media(base, opener, media_id, headers=context)
                except Exception as exc:
                    cleanup_errors.append(exc)
            if cleanup_errors:
                raise RuntimeError("native media cleanup failed") from cleanup_errors[0]
