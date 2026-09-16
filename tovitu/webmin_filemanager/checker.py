"""External legitimate-workflow checker for Webmin module boundaries."""

from __future__ import annotations

import secrets
import threading

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._client import FILE_MANAGER_ROOT, PayloadServer, Webmin, WebminError, login
from .checker_identity import assignment_filename, open_assignments


_LANGUAGES = {
    "en": b"Change Language and Theme",
    "fr": b"Modification de la langue et du th",
}
_DOCUMENTS = (
    "maintenance-window",
    "storage-review",
    "support-handoff",
    "system-inventory",
)
_CHECK_LOCKS: dict[tuple[str, int], threading.Lock] = {}
_CHECK_LOCKS_GUARD = threading.Lock()


def _target_lock(target: VulboxTarget) -> threading.Lock:
    key = (target.host, target.ports["service"])
    with _CHECK_LOCKS_GUARD:
        return _CHECK_LOCKS.setdefault(key, threading.Lock())


class WebminChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "webmin-filemanager-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        with _target_lock(target):
            return self._run_locked(target)

    def _run_locked(self, target: VulboxTarget) -> CheckResult:
        nonce = secrets.token_hex(10)
        base_url = f"http://{target.host}:{target.ports['service']}"
        try:
            team_id = str(target.meta["team_id"])
            random = secrets.SystemRandom()
            filename = assignment_filename()
            context_status, _, context = Webmin(base_url).request(
                "GET", "/" + filename
            )
            if context_status != 200:
                raise WebminError("principal assignment record unavailable")
            assignments = open_assignments(team_id, context.decode())
            restricted = assignments.issued
            if not restricted:
                raise WebminError("legitimate principal pool unavailable")
            admin_username, admin_password = random.choice(
                assignments.file_managers
            )
            admin = login(base_url, admin_username, admin_password)
            users = []
            for username, password in random.sample(restricted, len(restricted)):
                client = login(base_url, username, password)
                status, _, page = client.request("GET", "/change-user/")
                current = next(
                    (
                        language
                        for language, marker in _LANGUAGES.items()
                        if marker in page
                    ),
                    None,
                )
                if status != 200 or current is None:
                    raise WebminError("preference module unavailable")
                language = random.choice(
                    tuple(candidate for candidate in _LANGUAGES if candidate != current)
                )
                client.change_language(language)
                status, _, page = client.request("GET", "/change-user/")
                if status != 200 or _LANGUAGES[language] not in page:
                    raise WebminError("language preference did not persist")
                for path in ("/filemin/", "/shell/"):
                    status, _, denied = client.request("GET", path)
                    denial_markers = (
                        b'data-title-initial="Error',
                        b'data-title-initial="Erreur',
                    )
                    if status != 200 or not any(
                        marker in denied for marker in denial_markers
                    ):
                        raise WebminError("restricted module boundary changed")
                users.append(username)

            document = random.choice(_DOCUMENTS)
            filename = f"{document}-{nonce[:10]}.txt"
            content = f"{document.replace('-', ' ').title()} {nonce}\n".encode()
            with PayloadServer(target.host) as payloads:
                remote_url = payloads.add(filename, content)
                status, _, _ = admin.file_manager_download(
                    remote_url, "/srv/challenge/webmin"
                )
            read_status, _, received = admin.request("GET", "/" + filename)
            if status != 302 or read_status != 200 or received != content:
                raise WebminError("administrator File Manager round-trip failed")
        except Exception as exc:
            detail = str(exc) if isinstance(exc, WebminError) else type(exc).__name__
            return CheckResult(name="checker", passed=False, detail=detail)

        return CheckResult(
            name="checker",
            passed=len(users) == len(restricted) and len(users) == len(set(users)),
            detail=(
                f"{len(users)} issued preference workflows and "
                "admin File Manager passed"
            ),
        )
