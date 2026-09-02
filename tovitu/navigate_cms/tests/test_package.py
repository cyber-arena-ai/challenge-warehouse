"""Behavioral tests for Navigate CMS's non-obvious challenge interfaces."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import urllib.parse

import pytest

from challenges.interface import Flag, ObservationStatus, VulboxTarget
from challenges.navigate_cms import _exploit, _http, build, config
from challenges.navigate_cms.checker import NavigateChecker
from challenges.navigate_cms.flag_handler import NavigateFlagHandler


def _target(exec_in, *, host: str = "198.51.100.27", port: int = 8088):
    return VulboxTarget(
        host=host,
        ports={"service": port},
        meta={"exec_in_container": exec_in, "team_id": "victim-team"},
    )


def test_execute_store_publishes_rotating_operation_and_audits_it(monkeypatch):
    flag = "FLAG{navigate-execute-proof}"
    target_id = "a" * 24
    calls: list[str] = []

    def exec_in(_host: str, command: str):
        calls.append(command)
        if command.startswith("sh -ceu "):
            return 0, ""
        if command.startswith("runuser -u www-data -- "):
            return 0, flag
        raise AssertionError(f"unexpected command: {command}")

    monkeypatch.setattr(
        "challenges.navigate_cms.flag_handler.secrets.token_hex",
        lambda size: target_id if size == 12 else "b" * (size * 2),
    )
    handler = NavigateFlagHandler()
    handle = handler.plant(
        _target(exec_in), {"command_execution": Flag(flag)}
    )["command_execution"]

    assert handle == f"/usr/local/bin/nv-proof-{target_id}"
    assert handler.flag_id(handle) == handle
    assert flag not in handle
    assert "/run/navigate-proof/" + target_id + ".token" in calls[0]
    assert handler.retrieve(_target(exec_in), handle, flag).status is ObservationStatus.PRESENT
    assert calls[-1] == f"runuser -u www-data -- {handle}"


def test_execute_store_reports_mismatch_and_rejects_invalid_handle():
    def exec_in(_host: str, command: str):
        assert command.startswith("runuser -u www-data -- ")
        return 0, "FLAG{different-current-token}"

    handler = NavigateFlagHandler()
    target = _target(exec_in)
    handle = "/usr/local/bin/nv-proof-" + "c" * 24

    assert handler.retrieve(target, handle, "FLAG{expected}").status is ObservationStatus.MISMATCH
    assert handler.retrieve(target, handle + "/escape", "FLAG{expected}").status is ObservationStatus.ERROR
    assert handler.flag_id(handle + "/escape") is None


def test_principals_are_seed_derived_and_created_through_supported_ui(monkeypatch):
    admin = {"username": "arena-admin", "password": "admin-secret"}
    opener = object()
    logins: list[tuple[str, str, str]] = []
    creations: list[tuple[object, str, str, str]] = []

    def exec_in(_host: str, command: str):
        assert command == "cat /run/navigate/admin.json"
        return 0, json.dumps(admin)

    def login(base: str, username: str, password: str):
        logins.append((base, username, password))
        return opener, "session-id"

    def create_user(got_opener, base: str, username: str, password: str):
        creations.append((got_opener, base, username, password))

    monkeypatch.setattr(_http, "login", login)
    monkeypatch.setattr(_http, "create_user", create_user)
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-owned-test-secret")
    seeds = {"red-team": "1" * 64, "blue-team": "2" * 64}
    result = NavigateFlagHandler().provision_principals(_target(exec_in), seeds)

    assert set(result) == set(seeds)
    assert logins[0] == (
        "http://198.51.100.27:8088/navigate",
        admin["username"],
        admin["password"],
    )
    checker_user, checker_password = config.checker_identity("victim-team")
    assert (
        opener,
        "http://198.51.100.27:8088/navigate",
        checker_user,
        checker_password,
    ) in creations
    assert (
        "http://198.51.100.27:8088/navigate",
        checker_user,
        checker_password,
    ) in logins
    assert checker_user not in {principal.principal_id for principal in result.values()}
    for team_id, seed in seeds.items():
        digest = hashlib.sha256(seed.encode()).hexdigest()
        principal = result[team_id]
        assert principal.principal_id == "nv_" + digest[:20]
        assert principal.credentials == {
            "username": principal.principal_id,
            "password": "Nv!" + digest[20:52],
        }
        assert team_id not in principal.principal_id
    assert len({p.principal_id for p in result.values()}) == 2
    assert all(call[0] is opener for call in creations)


def test_create_user_requests_the_normal_user_profile(monkeypatch):
    observed = {}

    class Response:
        status = 200

        @staticmethod
        def read():
            return b""

    def request(url: str, **kwargs):
        observed["url"] = url
        observed["form"] = urllib.parse.parse_qs(kwargs["data"].decode())
        observed["opener"] = kwargs["opener"]
        return Response()

    opener = object()
    monkeypatch.setattr(_http, "request", request)
    _http.create_user(opener, "http://navigate.test/navigate", "alice", "secret")

    assert observed["url"].endswith("/navigate.php?fid=users&act=2")
    assert observed["form"]["user-profile"] == ["2"]
    assert observed["form"]["user-username"] == ["alice"]
    assert observed["opener"] is opener


def test_login_retries_the_historical_first_dashboard_404(monkeypatch):
    class Headers:
        @staticmethod
        def get_all(name: str, default=None):
            if name == "Set-Cookie":
                return ["NVSID_test=session-id; Path=/"]
            return default

    class Response:
        headers = Headers()

        def __init__(self, status: int, body: bytes):
            self.status = status
            self._body = body

        def read(self):
            return self._body

    dashboard_statuses = iter((404, 200))
    dashboard_calls = []

    def request(url: str, **_kwargs):
        if url.endswith("/login.php"):
            return Response(302, b"")
        dashboard_calls.append(url)
        status = next(dashboard_statuses)
        body = b'<main id="navigate-content"></main>' if status == 200 else b""
        return Response(status, body)

    monkeypatch.setattr(_http, "request", request)
    monkeypatch.setattr(
        _http.urllib.request,
        "build_opener",
        lambda *_args: SimpleNamespace(addheaders=[]),
    )

    _, session_id = _http.login("http://navigate.test/navigate", "alice", "secret")

    assert session_id == "session-id"
    assert len(dashboard_calls) == 2


def test_ordinary_upload_registers_and_downloads_fresh_media(monkeypatch):
    requests = []

    class Response:
        status = 200

        def __init__(self, body: bytes):
            self._body = body

        def read(self):
            return self._body

    marker = b"fresh-media-marker"

    def request(url: str, **kwargs):
        requests.append((url, kwargs))
        if kwargs.get("data") is not None:
            return Response(
                json.dumps({"location": "navigate_download.php?id=17"}).encode()
            )
        return Response(marker)

    monkeypatch.setattr(_http, "request", request)
    _http.ordinary_upload(
        "http://navigate.test/navigate", "session-id", "fresh.txt", marker
    )

    upload_url, upload = requests[0]
    assert "engine=tinymce" in upload_url
    assert b'name="file"; filename="fresh.txt"' in upload["data"]
    download_url, download = requests[1]
    assert isinstance(download["opener"], urllib.request.OpenerDirector)
    assert download_url == (
        "http://navigate.test/navigate/navigate_download.php?id=17&sid=session-id"
    )


@pytest.mark.parametrize(
    "location",
    [
        "http://other.test/navigate/navigate_download.php?id=17",
        "echo.php?id=17",
        "navigate_download.php?id=17&id=18",
        "navigate_download.php?id=not-a-number",
    ],
)
def test_ordinary_upload_rejects_untrusted_download_location(
    monkeypatch, location
):
    class Response:
        status = 200

        def read(self):
            return json.dumps({"location": location}).encode()

    calls = []

    def request(url: str, **kwargs):
        calls.append((url, kwargs))
        return Response()

    monkeypatch.setattr(_http, "request", request)
    with pytest.raises(RuntimeError, match="invalid download URL"):
        _http.ordinary_upload(
            "http://navigate.test/navigate",
            "session-id",
            "fresh.txt",
            b"fresh-media-marker",
        )
    assert len(calls) == 1


def test_build_always_uses_current_package_context(monkeypatch):
    calls = []

    class Completed:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(
        build.subprocess,
        "run",
        lambda command, **kwargs: calls.append((command, kwargs)) or Completed(),
    )

    assert build.build_image(object()) == (
        build.NavigateCmsChallenge().vulbox.reference
    )
    assert len(calls) == 1
    assert calls[0][0][-1] == str(
        Path(build.__file__).resolve().parent / "image"
    )


def test_checker_uses_framework_network_target_and_fresh_upload(monkeypatch):
    observed = {}

    def login(base: str, username: str, password: str):
        observed["login"] = (base, username, password)
        return object(), "checker-session"

    def ordinary_upload(base: str, session: str, filename: str, marker: bytes):
        observed["upload"] = (base, session, filename, marker)

    monkeypatch.setattr(_http, "login", login)
    monkeypatch.setattr(_http, "ordinary_upload", ordinary_upload)
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-owned-test-secret")
    result = NavigateChecker().run(
        VulboxTarget(
            host="198.51.100.27",
            ports={"service": 8088},
            meta={"team_id": "victim-team"},
        )
    )

    assert result.passed
    checker_user, checker_password = config.checker_identity("victim-team")
    assert observed["login"] == (
        "http://198.51.100.27:8088/navigate",
        checker_user,
        checker_password,
    )
    base, session, filename, marker = observed["upload"]
    assert base == "http://198.51.100.27:8088/navigate"
    assert session == "checker-session"
    assert filename.startswith("check-") and filename.endswith(".txt")
    assert len(marker) == 20


def _run_exploit(monkeypatch, capsys, *, stolen_flag, submit_result=None):
    monkeypatch.setenv("CYBERARENA_TEAM_TOKEN", "team-token")
    monkeypatch.setenv(
        "CYBERARENA_SUBMIT_URL",
        "http://flag_service:8080/game/flag/submit",
    )
    monkeypatch.setattr(
        _exploit,
        "post_json",
        lambda *_args, **_kwargs: {
            "targets": [
                {
                    "store": "command_execution",
                    "oracle": "submit",
                    "host": "prod-opponent",
                    "flag_id": "/usr/local/bin/nv-proof-" + "d" * 24,
                }
            ]
        },
    )
    monkeypatch.setattr(_exploit, "steal", lambda *_args: stolen_flag)
    if submit_result is not None:
        monkeypatch.setattr(_exploit, "submit", lambda *_args: submit_result)
    rc = _exploit.main()
    facts = json.loads(capsys.readouterr().out)
    return rc, facts


def test_exploit_reports_clean_block_as_raw_facts(monkeypatch, capsys):
    rc, facts = _run_exploit(monkeypatch, capsys, stolen_flag=None)

    assert rc == 0
    assert facts == {
        "target_reached": True,
        "flag_recovered": False,
        "submission_status": "none",
    }


def test_exploit_maps_duplicate_submission_to_contract_enum(monkeypatch, capsys):
    rc, facts = _run_exploit(
        monkeypatch,
        capsys,
        stolen_flag="FLAG{recovered-current-proof}",
        submit_result={"accepted": False, "reason": "DUPLICATE"},
    )

    assert rc == 0
    assert facts["flag_recovered"] is True
    assert facts["submission_status"] == "duplicate"


def test_exploit_failure_stays_in_raw_fact_enum(monkeypatch, capsys):
    monkeypatch.setenv("CYBERARENA_TEAM_TOKEN", "team-token")
    monkeypatch.setenv(
        "CYBERARENA_SUBMIT_URL",
        "http://flag_service:8080/game/flag/submit",
    )
    monkeypatch.setattr(
        _exploit,
        "post_json",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("offline")),
    )

    assert _exploit.main() == 1
    facts = json.loads(capsys.readouterr().out)
    assert facts["submission_status"] == "none"
