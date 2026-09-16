"""External checker for the ordinary Xerte project and media workflow.

Runs in the health poller and makes every assertion through the public service.
Its ordinary accounts are provisioned once with the attacker accounts and are
derived independently by the two trusted facility containers.
"""

from __future__ import annotations

import secrets

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._client import XerteApi, resolve_host
from ._ids import checker_principals, project_path

_WORDS = (
    "autumn", "bridge", "campus", "chapter", "circle", "coastal", "course",
    "creative", "design", "digital", "discovery", "evening", "field",
    "garden", "guide", "history", "ideas", "journey", "language", "learning",
    "library", "local", "making", "modern", "morning", "museum", "nature",
    "notes", "online", "pathways", "people", "planning", "practical",
    "project", "reading", "research", "resources", "science", "season",
    "seminar", "skills", "stories", "studio", "summary", "teaching", "topic",
    "training", "travel", "workshop", "writing",
)


def _words(minimum: int, maximum: int) -> list[str]:
    count = minimum + secrets.randbelow(maximum - minimum + 1)
    return [secrets.choice(_WORDS) for _ in range(count)]


def _project_title() -> str:
    return " ".join(word.capitalize() for word in _words(2, 5))


def _media_name() -> str:
    separator = secrets.choice(("-", "_"))
    return separator.join(_words(1, 4)) + ".txt"


def _media_body() -> bytes:
    sentences = []
    for _ in range(2 + secrets.randbelow(5)):
        words = _words(6, 14)
        sentences.append(
            " ".join((words[0].capitalize(), *words[1:]))
            + secrets.choice((".", ".", "?", "!"))
        )
    return " ".join(sentences).encode()


class XerteChecker(FunctionalityTest):
    def __init__(self) -> None:
        self._anchors: dict[str, tuple[int, str, bytes]] = {}

    @property
    def name(self) -> str:
        return "xerte-online-toolkits-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def _anchor(self, key: str, api: XerteApi, session,
                username: str) -> tuple[int, str, bytes]:
        """A poller-owned project whose media must survive every restart."""
        if key in self._anchors:
            return self._anchors[key]

        project_id = api.create_project(session, _project_title())
        if not project_id:
            raise RuntimeError("anchor project creation failed")
        filename = _media_name()
        body = _media_body()
        status, response = api.upload_media(
            session, project_path(project_id, username), filename, body)
        if status != 200 or b"added" not in response:
            raise RuntimeError("anchor media upload failed")
        self._anchors[key] = (project_id, filename, body)
        return self._anchors[key]

    def run(self, target: VulboxTarget) -> CheckResult:
        api = XerteApi(f"http://{resolve_host(target.host)}:{target.ports['service']}")
        children: list[CheckResult] = []
        try:
            pool = checker_principals(str(target.meta["team_id"]))
            first_account = secrets.choice(pool)
            second_account = secrets.choice(
                tuple(account for account in pool if account != first_account))
            first = api.login(*first_account)
            second = api.login(*second_account)
            ok = first is not None and second is not None
            children.append(CheckResult("accounts", ok,
                                        f"logins={'ok' if ok else 'rejected'}"))
            if not ok:
                return CheckResult("checker", False, children=children)

            first_id = api.create_project(first, _project_title())
            second_id = api.create_project(second, _project_title())
            distinct = bool(first_id and second_id and first_id != second_id)
            children.append(CheckResult(
                "projects", distinct,
                f"first={first_id}, second={second_id}"))
            if not distinct:
                return CheckResult("checker", False, children=children)

            first_path = project_path(first_id, first_account[0])
            second_path = project_path(second_id, second_account[0])
            filename = _media_name()
            body = _media_body()
            first_status, first_body = api.upload_media(
                first, first_path, filename, body)
            second_status, second_body = api.upload_media(
                second, second_path, _media_name(), _media_body())
            uploads_ok = (first_status == 200 and b"added" in first_body
                          and second_status == 200 and b"added" in second_body)
            children.append(CheckResult(
                "media_upload", uploads_ok,
                f"first={first_status}, second={second_status}"))

            served_status, served = api.fetch_media(first_path, filename)
            children.append(CheckResult(
                "media_serving", served_status == 200 and served == body,
                f"GET {filename} -> {served_status}, exact={served == body}"))

            owner_status, owner_view = api.media_listing(first, first_id)
            other_status, other_view = api.media_listing(second, first_id)
            visible = filename.encode() in owner_view
            leaked = filename.encode() in other_view
            children.append(CheckResult(
                "media_boundary", visible and not leaked,
                f"owner={owner_status}/{visible}, other={other_status}/{leaked}"))

            anchor_account = pool[0]
            anchor_session = api.login(*anchor_account)
            if anchor_session is None:
                raise RuntimeError("anchor account login rejected")
            anchor_id, anchor_name, anchor_body = self._anchor(
                str(target.meta["team_id"]), api, anchor_session,
                anchor_account[0])
            anchor_path = project_path(anchor_id, anchor_account[0])
            anchor_status, anchor_served = api.fetch_media(anchor_path, anchor_name)
            _, anchor_view = api.media_listing(anchor_session, anchor_id)
            children.append(CheckResult(
                "persistence",
                anchor_status == 200 and anchor_served == anchor_body
                and anchor_name.encode() in anchor_view,
                f"anchor project {anchor_id} -> {anchor_status}"))
        except Exception as error:  # noqa: BLE001
            children.append(CheckResult("exception", False, str(error)))
        return CheckResult("checker", all(child.passed for child in children),
                           children=children)
