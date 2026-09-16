from __future__ import annotations

import re

from challenges.interface import VulboxTarget
from challenges.suitecrm_security_groups import checker, checker_identity


def test_checker_selects_a_principal_from_each_pool(monkeypatch) -> None:
    setup = {
        "ordinary": (
            ("user-a", "password-a", "group-a"),
            ("user-b", "password-b", "group-b"),
        ),
        "guarded": (
            ("user-c", "password-c", "group-c"),
            ("user-d", "password-d", "group-d"),
        ),
        "client_id": "client-id",
        "client_secret": "client-secret",
    }
    monkeypatch.setattr(checker.secrets, "choice", lambda values: values[-1])

    ordinary = checker._account(setup, "ordinary")
    guarded = checker._account(setup, "guarded")

    assert ordinary["username"] == "user-b"
    assert guarded["username"] == "user-d"


def test_checker_uses_only_public_http_with_ordinary_fresh_records(monkeypatch) -> None:
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-test-token")
    records: dict[str, dict[str, str]] = {}
    relationships: dict[str, set[str]] = {}
    created: list[dict[str, str]] = []
    profiles: list[tuple[str, str]] = []
    v8_calls: list[tuple[str, str, str]] = []

    class Api:
        sequence = 0

        def __init__(
            self,
            base: str,
            *,
            application_name: str = "SuiteCRM REST Client",
            user_agent: str = "SuiteCRM-Client/7.15",
        ):
            assert base == "http://victim:8080"
            profiles.append((application_name, user_agent))
            self.username = ""
            self.user_id = ""

        def login(self, username: str, _password: str) -> bool:
            self.username = username
            self.user_id = "user-" + username
            return True

        def oauth_login(self, *_args: str) -> bool:
            return True

        def set_entry(self, module: str, fields: dict[str, str]) -> str:
            if fields.get("deleted") == "1":
                records.pop(fields["id"], None)
                return fields["id"]
            Api.sequence += 1
            record_id = fields.get("id", f"record-{Api.sequence}")
            records[record_id] = {
                "id": record_id,
                "module": module,
                "owner": self.username,
                **fields,
            }
            created.append(records[record_id])
            return record_id

        def get_entry(
            self, module: str, record_id: str, _fields
        ) -> list[dict[str, str]]:
            row = records.get(record_id)
            if not row or row["module"] != module or row["owner"] != self.username:
                return []
            return [row]

        def v8(self, method: str, path: str, payload=None):
            v8_calls.append((self.username, method, path))
            case_id = path.split("/")[3]
            if method == "POST":
                relationships.setdefault(case_id, set()).add(payload["data"]["id"])
                return 201, {}
            if method == "DELETE":
                relationships.setdefault(case_id, set()).discard(path.rsplit("/", 1)[1])
                return 204, {}
            data = []
            for note_id in relationships.get(case_id, set()):
                row = records[note_id]
                data.append({"id": note_id, "attributes": {"filename": row["filename"]}})
            return 200, {"data": data}

        def save_report_field(self, *_args, **_kwargs) -> None:
            return None

        def html(self, _path: str) -> tuple[int, str]:
            return 200, " ".join(
                row["name"] for row in records.values()
                if row["owner"] == self.username and "name" in row
            )

    monkeypatch.setattr(checker, "SuiteCrmClient", Api)
    target = VulboxTarget(
        host="victim",
        ports={"service": 8080},
        meta={"team_id": "victim"},
    )
    issued = (
        ("arena_" + "a" * 16, "S7!" + "b" * 32),
        ("arena_" + "c" * 16, "S7!" + "d" * 32),
    )
    sealed = checker_identity.seal_cohort(
        target, [list(account) for account in issued]
    )
    commands: list[str] = []

    def exec_in(host: str, command: str) -> tuple[int, str]:
        assert host == "victim"
        commands.append(command)
        return 0, sealed + "\n"

    target.meta["exec_in_container"] = exec_in

    result = checker.SuiteCrmChecker().run(target)

    assert result.passed
    assert commands == [f"cat {checker_identity.COHORT_PATH}"]
    assert all(
        any(
            row["owner"] == account[0] and row["module"] == "Notes"
            for row in created
        )
        for account in issued
    )
    assert profiles.count(("SuiteCRM REST Client", "SuiteCRM-Client/7.15")) == 2
    browser_profiles = [profile for profile in profiles if profile != (
        "SuiteCRM REST Client", "SuiteCRM-Client/7.15"
    )]
    assert len(browser_profiles) == 2
    assert all(
        "arena" not in application.lower() and user_agent.startswith("Mozilla/")
        for application, user_agent in browser_profiles
    )
    for username, _password in issued:
        calls = [method for owner, method, _path in v8_calls if owner == username]
        assert calls == ["POST", "GET", "DELETE", "GET"]
    ordinary_records = [row for row in created if row["module"] in {"Notes", "Cases"}]
    assert ordinary_records
    for row in ordinary_records:
        text = " ".join(
            str(row.get(field, ""))
            for field in ("name", "description", "filename", "file_mime_type")
        ).lower()
        assert "checker" not in text and "cyber" not in text and "arena" not in text
    note_files = [row["filename"] for row in created if row["module"] == "Notes"]
    assert all(re.fullmatch(r"[a-z-]+-[A-Za-z0-9_-]+\.(?:pdf|txt|csv|odt)", name)
               for name in note_files)


def test_issued_principal_default_context_discrimination_fails_health(
    monkeypatch,
) -> None:
    observed: list[tuple[str, str, str]] = []

    class Api:
        def __init__(
            self,
            _base: str,
            *,
            application_name: str = "SuiteCRM REST Client",
            user_agent: str = "SuiteCRM-Client/7.15",
        ):
            self.application_name = application_name
            self.user_agent = user_agent
            self.user_id = ""

        def login(self, username: str, _password: str) -> bool:
            observed.append((username, self.application_name, self.user_agent))
            return False

    monkeypatch.setattr(checker, "SuiteCrmClient", Api)
    cleanup = []
    result = checker.SuiteCrmChecker._issued_principals(
        "http://victim:8080",
        {"client_id": "client-id", "client_secret": "client-secret"},
        (("user-a", "password-a"), ("user-b", "password-b")),
        cleanup,
    )

    assert not result.passed
    assert result.detail == "legacy login rejected"
    assert observed == [
        ("user-a", "SuiteCRM REST Client", "SuiteCRM-Client/7.15")
    ]
    assert cleanup == []


def test_default_client_relationship_filter_fails_health_but_browser_survives(
    monkeypatch,
) -> None:
    activity: list[str] = []

    class Api:
        sequence = 0

        def __init__(
            self,
            _base: str,
            *,
            application_name: str = "SuiteCRM REST Client",
            user_agent: str = "SuiteCRM-Client/7.15",
        ):
            self.user_agent = user_agent
            self.user_id = ""
            self.records: dict[str, dict[str, str]] = {}
            self.relationships: set[str] = set()

        def login(self, _username: str, _password: str) -> bool:
            activity.append("legacy_login")
            self.user_id = "issued-user-id"
            return True

        def oauth_login(self, *_args: str) -> bool:
            activity.append("oauth_login")
            return True

        def set_entry(self, module: str, fields: dict[str, str]) -> str:
            Api.sequence += 1
            record_id = f"record-{Api.sequence}"
            self.records[record_id] = {
                "id": record_id, "module": module, **fields,
            }
            activity.append(f"create_{module.lower()}")
            return record_id

        def get_entry(self, module: str, record_id: str, _fields):
            activity.append(f"read_{module.lower()}")
            row = self.records.get(record_id)
            return [row] if row and row["module"] == module else []

        def v8(self, method: str, path: str, payload=None):
            activity.append(f"{self.user_agent}:{method}:{path}")
            if (
                self.user_agent == "SuiteCRM-Client/7.15"
                and "/relationships/notes" in path
            ):
                return 403, {}
            note_id = path.rsplit("/", 1)[-1]
            if method == "POST":
                note_id = payload["data"]["id"]
                self.relationships.add(note_id)
                return 201, {}
            if method == "DELETE":
                self.relationships.discard(note_id)
                return 204, {}
            return 200, {"data": [
                {"id": linked, "attributes": {
                    "filename": self.records[linked]["filename"],
                }}
                for linked in self.relationships
            ]}

    monkeypatch.setattr(checker, "SuiteCrmClient", Api)
    cleanup = []
    result = checker.SuiteCrmChecker._issued_principals(
        "http://victim:8080",
        {"client_id": "client-id", "client_secret": "client-secret"},
        (("issued-user", "issued-password"),),
        cleanup,
    )

    assert not result.passed
    assert result.detail.startswith("default-client V8 relationship failed")
    assert activity[:5] == [
        "legacy_login", "oauth_login", "create_notes", "create_cases",
        "read_notes",
    ]
    assert [(module, record_id) for _api, module, record_id in cleanup] == [
        ("Notes", "record-1"), ("Cases", "record-2"),
    ]

    browser = Api(
        "http://victim:8080",
        application_name="Customer Portal",
        user_agent="Mozilla/5.0 test browser",
    )
    note_id = browser.set_entry("Notes", {"filename": "ordinary-note.txt"})
    case_id = browser.set_entry("Cases", {"name": "Ordinary case"})
    passed, detail = checker._relationship_roundtrip(
        browser, case_id, note_id, "ordinary-note.txt"
    )
    assert passed, detail


def test_issued_principal_v8_default_context_discrimination_fails_health(
    monkeypatch,
) -> None:
    observed: list[tuple[str, str]] = []

    class Api:
        def __init__(
            self,
            _base: str,
            *,
            application_name: str = "SuiteCRM REST Client",
            user_agent: str = "SuiteCRM-Client/7.15",
        ):
            observed.append((application_name, user_agent))
            self.user_id = "user-id"

        def login(self, _username: str, _password: str) -> bool:
            return True

        def oauth_login(self, *_args: str) -> bool:
            return False

    monkeypatch.setattr(checker, "SuiteCrmClient", Api)
    result = checker.SuiteCrmChecker._issued_principals(
        "http://victim:8080",
        {"client_id": "client-id", "client_secret": "client-secret"},
        (("user-a", "password-a"),),
        [],
    )

    assert not result.passed
    assert result.detail == "OAuth login rejected"
    assert observed == [("SuiteCRM REST Client", "SuiteCRM-Client/7.15")]
