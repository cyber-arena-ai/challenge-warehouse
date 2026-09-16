"""Behavioral tests for Navigate CMS's non-obvious challenge interfaces."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
from types import SimpleNamespace
import urllib.parse
import urllib.request

import pytest

from challenges.interface import Flag, ObservationStatus, VulboxTarget
from challenges.navigate_cms import _exploit, _http, build, checker, config
from challenges.navigate_cms.checker import NavigateChecker
from challenges.navigate_cms.flag_handler import NavigateFlagHandler
from challenges.navigate_cms.restart_handler import NavigateRestartHandler


ROUND_SEED = "01" * 32
ROTATED_SEED = "02" * 32


def _target(
    exec_in, *, host: str = "198.51.100.27", port: int = 8088,
    round_seed: str = ROUND_SEED,
):
    return VulboxTarget(
        host=host,
        ports={"service": port},
        meta={
            "exec_in_container": exec_in,
            "team_id": "victim-team",
            "round_context_seed": round_seed,
        },
    )


class PlacementRecorder:
    def __init__(self, proof: str = "") -> None:
        self.commands: list[str] = []
        self.contexts: dict[str, str] = {}
        self.history: dict[str, str] = {}
        self.history_present = True
        self.proof = proof

    def __call__(self, _host: str, command: str):
        self.commands.append(command)
        if command.startswith("test -f /var/lib/.navigate-proof.initialized"):
            if not self.history_present:
                return 45, ""
            history = "\n".join(
                " ".join(state.splitlines()) for state in self.history.values()
            )
            prefix = history + ("\n" if history else "")
            return (
                0,
                prefix
                + "--navigate-context--\n"
                + "".join(
                    name + "\n" + self.contexts[name]
                    for name in sorted(self.contexts)
                ),
            )
        if command.startswith("sh -ceu "):
            encoded = re.findall(
                r"printf %s '?([A-Za-z0-9+/=]+)'? \| base64 -d",
                command,
            )
            assert len(encoded) == 2
            state = base64.b64decode(encoded[0]).decode()
            key = state.splitlines()[0]
            self.contexts[key] = state
            if ".issued.history.new" in command and key not in self.history:
                self.history[key] = state
            return 0, ""
        if command.startswith("runuser -u www-data -- "):
            return 0, self.proof
        raise AssertionError(f"unexpected command: {command}")


def test_execute_store_recovers_old_retry_after_new_rotation_and_audits():
    flag = "FLAG{navigate-execute-proof}"
    recorder = PlacementRecorder(flag)
    first_key, first_id, _ = config.round_context(ROUND_SEED)
    fresh_key, fresh_id, _ = config.round_context(ROTATED_SEED)
    handler = NavigateFlagHandler()
    first = handler.plant(
        _target(recorder), {"command_execution": Flag(flag)}
    )["command_execution"]
    fresh = handler.plant(
        _target(recorder, round_seed=ROTATED_SEED),
        {"command_execution": Flag("FLAG{fresh-round-proof}")}
    )["command_execution"]
    retry = handler.plant(
        _target(recorder), {"command_execution": Flag(flag)}
    )["command_execution"]

    assert first == retry == "/usr/local/bin/nv-proof " + first_id
    assert fresh == "/usr/local/bin/nv-proof " + fresh_id
    assert first != fresh
    assert handler.flag_id(first) == first
    assert flag not in first
    assert len(recorder.contexts) == len(recorder.history) == 2
    assert all(flag not in state for state in recorder.contexts.values())
    assert all(flag not in state for state in recorder.history.values())
    placements = [c for c in recorder.commands if c.startswith("sh -ceu ")]
    assert len(placements) == 3
    assert f"/var/lib/navigate-proof/{first_id}.token" in placements[0]
    assert f"/var/lib/navigate-proof/{first_id}.token" in placements[2]
    assert handler.retrieve(
        _target(recorder), first, flag
    ).status is ObservationStatus.PRESENT
    assert recorder.commands[-1] == f"runuser -u www-data -- {first}"

    del recorder.contexts[first_key]
    recovered = NavigateFlagHandler().plant(
        _target(recorder), {"command_execution": Flag(flag)}
    )["command_execution"]
    assert recovered == first
    assert recorder.contexts[first_key] == recorder.history[first_key]

    mutations_before = len(
        [command for command in recorder.commands if command.startswith("sh -ceu ")]
    )
    fresh_history = recorder.history.pop(fresh_key)
    with pytest.raises(RuntimeError, match="irreconstructible"):
        NavigateFlagHandler().plant(
            _target(recorder), {"command_execution": Flag(flag)}
        )
    recorder.history[fresh_key] = fresh_history

    recorder.history_present = False
    with pytest.raises(RuntimeError, match="integrity failure"):
        NavigateFlagHandler().plant(
            _target(recorder), {"command_execution": Flag(flag)}
        )
    assert len(
        [command for command in recorder.commands if command.startswith("sh -ceu ")]
    ) == mutations_before

    recorder.history_present = True
    del recorder.history[first_key]
    with pytest.raises(RuntimeError, match="irreconstructible"):
        NavigateFlagHandler().plant(
            _target(recorder), {"command_execution": Flag(flag)}
        )
    assert len(
        [command for command in recorder.commands if command.startswith("sh -ceu ")]
    ) == mutations_before


def test_execute_placement_uses_the_supplied_proof_without_facility_auth_env(
    monkeypatch,
):
    recorder = PlacementRecorder("FLAG{navigate-execute-proof}")
    monkeypatch.delenv("CYBERARENA_FACILITY_TOKEN", raising=False)
    key, target_id, _ = config.round_context(ROUND_SEED)

    handle = NavigateFlagHandler().plant(
        _target(recorder),
        {"command_execution": Flag("FLAG{navigate-execute-proof}")},
    )["command_execution"]

    assert handle == "/usr/local/bin/nv-proof " + target_id
    assert "FLAG{navigate-execute-proof}" not in recorder.contexts[
        key
    ]


def test_round_context_is_stable_domain_separated_and_proof_independent():
    first = config.round_context(ROUND_SEED)
    assert first == config.round_context(ROUND_SEED)
    assert first != config.round_context(ROTATED_SEED)
    assert len(set(first)) == 3


def test_same_round_context_keeps_target_when_proof_value_changes():
    recorder = PlacementRecorder()
    handler = NavigateFlagHandler()
    first = handler.plant(
        _target(recorder), {"command_execution": Flag("FLAG{first-proof}")}
    )["command_execution"]
    second = handler.plant(
        _target(recorder), {"command_execution": Flag("FLAG{second-proof}")}
    )["command_execution"]

    assert first == second
    assert len(recorder.contexts) == len(recorder.history) == 1


def test_round_context_seed_is_required():
    with pytest.raises(RuntimeError, match="placement material unavailable"):
        config.round_context("")


@pytest.mark.parametrize(
    ("status", "output", "message"),
    [
        (45, "", "integrity failure"),
        (
            0,
            f"{config.round_context(ROUND_SEED)[0]} "
            f"{config.round_context(ROUND_SEED)[1]} {'0' * 64}\n"
            "--navigate-context--\n",
            "irreconstructible",
        ),
    ],
)
def test_execute_store_fails_closed_on_lost_or_tampered_retry_state(
    monkeypatch, status, output, message
):
    def exec_in(_host: str, command: str):
        assert command.startswith("test -f /var/lib/.navigate-proof.initialized")
        return status, output

    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-owned-test-secret")
    with pytest.raises(RuntimeError, match=message):
        NavigateFlagHandler().plant(
            _target(exec_in),
            {"command_execution": Flag("FLAG{navigate-execute-proof}")},
        )


def test_execute_store_reports_mismatch_and_rejects_invalid_handle():
    def exec_in(_host: str, command: str):
        assert command.startswith("runuser -u www-data -- ")
        return 0, "FLAG{different-current-token}"

    handler = NavigateFlagHandler()
    target = _target(exec_in)
    handle = "/usr/local/bin/nv-proof " + "c" * 24

    assert handler.retrieve(target, handle, "FLAG{expected}").status is ObservationStatus.MISMATCH
    assert handler.retrieve(target, handle + "/escape", "FLAG{expected}").status is ObservationStatus.ERROR
    assert handler.flag_id(handle + "/escape") is None


def test_principals_are_seed_derived_and_created_through_supported_ui(monkeypatch):
    admin = {"username": "arena-admin", "password": "admin-secret"}
    opener = object()
    logins: list[tuple[str, str, str]] = []
    creations: list[tuple[object, str, str, str]] = []

    execs: list[str] = []

    def exec_in(_host: str, command: str):
        execs.append(command)
        if command == "cat /run/navigate/admin.json":
            return 0, json.dumps(admin)
        return 0, ""

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
    provisioned = [(call[2], call[3]) for call in creations]
    assert len(provisioned) == len(seeds)
    assert provisioned == sorted(provisioned)
    assert len({username for username, _ in provisioned}) == len(provisioned)
    assert len({password for _, password in provisioned}) == len(provisioned)
    assert all(re.fullmatch(r"nv_[0-9a-f]{20}", username) for username, _ in provisioned)
    assert all(re.fullmatch(r"Nv![0-9a-f]{32}", password) for _, password in provisioned)
    seal = shlex.split(shlex.split(execs[-1])[2])
    assert config.COHORT_FILE in seal
    encoded = seal[seal.index("%s") + 1]
    assert config.sealed_cohort(
        base64.b64decode(encoded).decode()
    ) == tuple(sorted(provisioned))


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
    request_headers = []

    def request(url: str, **kwargs):
        request_headers.append(kwargs["headers"])
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

    profile = {"User-Agent": "ordinary-browser", "Accept-Language": "en-US"}
    _, session_id = _http.login(
        "http://navigate.test/navigate",
        "alice",
        "secret",
        headers=profile,
    )

    assert session_id == "session-id"
    assert len(dashboard_calls) == 2
    assert all(headers["User-Agent"] == "ordinary-browser" for headers in request_headers)
    assert request_headers[0]["Content-Type"] == "application/x-www-form-urlencoded"


def test_remembered_login_requires_persistence_and_same_identity(monkeypatch):
    class Headers:
        def __init__(self, cookies: list[str]):
            self.cookies = cookies

        def get_all(self, name: str, default=None):
            return self.cookies if name == "Set-Cookie" else default

    class Response:
        def __init__(self, status: int, body: bytes, cookies: list[str]):
            self.status = status
            self._body = body
            self.headers = Headers(cookies)

        def read(self):
            return self._body

        def info(self):
            return self.headers

    def run(cookie_attributes: str, resumed_username: str = "alice"):
        requests = []

        def request(url: str, **kwargs):
            requests.append((url, kwargs))
            if url.endswith("/login.php") and kwargs.get("data") is not None:
                form = urllib.parse.parse_qs(kwargs["data"].decode())
                assert form["login-remember"] == ["1"]
                return Response(
                    302,
                    b"",
                    [
                        "NVSID_initial=initial-session; Path=/",
                        f"navigate-user=remember-token; {cookie_attributes}",
                    ],
                )
            if url.endswith("/login.php"):
                return Response(
                    302,
                    b"",
                    ["NVSID_resumed=resumed-session; Path=/"],
                )
            body = (
                '<main id="navigate-content"></main>'
                '<a class="bold" href="?fid=2" title="User">'
                '<img src="user.png" /> '
                f"{resumed_username}</a>"
            ).encode()
            return Response(200, body, [])

        monkeypatch.setattr(_http, "request", request)
        result = _http.login(
            "http://navigate.test/navigate",
            "alice",
            "secret",
            remember=True,
        )
        return result, requests

    with pytest.raises(RuntimeError, match="no persistent cookie"):
        run("Path=/")
    with pytest.raises(RuntimeError, match="no persistent cookie"):
        run("Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/")
    for inapplicable in (
        "Max-Age=604800; Path=/elsewhere",
        "Max-Age=604800; Domain=foreign.invalid; Path=/",
        "Max-Age=604800; Secure; Path=/",
    ):
        with pytest.raises(RuntimeError, match="inapplicable cookie"):
            run(inapplicable)

    (opener, session_id), requests = run("Max-Age=604800; Path=/")
    assert session_id == "resumed-session"
    assert opener.addheaders[0][1].startswith("NVSID_resumed=resumed-session;")
    resume_opener = requests[1][1]["opener"]
    processor = next(
        handler for handler in resume_opener.handlers
        if isinstance(handler, urllib.request.HTTPCookieProcessor)
    )
    assert [cookie.name for cookie in processor.cookiejar] == ["navigate-user"]

    with pytest.raises(RuntimeError, match="wrong identity"):
        run("Max-Age=604800; Path=/", resumed_username="mallory")


def test_checker_enables_remembered_login(monkeypatch):
    observed = {}

    def login(base: str, username: str, password: str, **kwargs):
        observed["login"] = (base, username, password, kwargs)
        return object(), "session-id"

    sequence = iter((1, 3))
    monkeypatch.setattr(_http, "login", login)
    monkeypatch.setattr(
        _http,
        "ordinary_upload",
        lambda *_args, **kwargs: kwargs["on_registered"](2) or 2,
    )
    monkeypatch.setattr(
        _http, "register_upload", lambda *_args, **_kwargs: next(sequence)
    )
    monkeypatch.setattr(_http, "delete_media", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        "challenges.navigate_cms.checker._issued_cohort",
        lambda _target: (("alice", "secret"),),
    )
    result = NavigateChecker().run(_target(lambda *_args: (0, "")))

    assert result.passed is True
    assert observed["login"][3]["remember"] is True


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
        if "act=edit" in url:
            return Response(b'<input name="name" id="name" value="fresh.txt" />')
        return Response(marker)

    monkeypatch.setattr(_http, "request", request)
    _http.ordinary_upload(
        "http://navigate.test/navigate",
        urllib.request.build_opener(),
        "session-id",
        "fresh.txt",
        marker,
        headers={"User-Agent": "ordinary-browser"},
    )

    upload_url, upload = requests[0]
    assert "engine=tinymce" in upload_url
    assert b'name="file"; filename="fresh.txt"' in upload["data"]
    assert upload["headers"]["User-Agent"] == "ordinary-browser"
    assert re.fullmatch(
        r"multipart/form-data; boundary=[A-Za-z0-9_-]{16,70}",
        upload["headers"]["Content-Type"],
    )
    assert not re.search(
        r"navigate|check|probe", upload["headers"]["Content-Type"], re.IGNORECASE
    )
    properties_url, properties = requests[1]
    assert properties_url == (
        "http://navigate.test/navigate/navigate.php?fid=files&act=edit&id=17"
    )
    assert properties["headers"]["User-Agent"] == "ordinary-browser"
    download_url, download = requests[2]
    assert isinstance(download["opener"], urllib.request.OpenerDirector)
    assert download["headers"]["User-Agent"] == "ordinary-browser"
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
            urllib.request.build_opener(),
            "session-id",
            "fresh.txt",
            b"fresh-media-marker",
        )
    assert len(calls) == 1


class _Images:
    def __init__(self, error=None):
        self.error = error
        self.lookups = []

    def get(self, tag):
        self.lookups.append(tag)
        if self.error is not None:
            raise self.error
        return object()


def test_build_reuses_existing_exact_tag_with_passed_or_default_client(monkeypatch):
    tag = build.NavigateCmsChallenge().vulbox.reference
    passed_images = _Images()
    passed_client = SimpleNamespace(images=passed_images)
    default_images = _Images()
    monkeypatch.setattr(
        build.docker, "from_env", lambda: SimpleNamespace(images=default_images)
    )
    monkeypatch.setattr(
        build.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("existing image must not rebuild"),
    )

    assert build.build_image(passed_client) == tag
    assert build.build_image() == tag
    assert passed_images.lookups == [tag]
    assert default_images.lookups == [tag]


def test_build_missing_tag_uses_current_package_context(monkeypatch):
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
    images = _Images(build.docker.errors.ImageNotFound("missing"))

    assert build.build_image(SimpleNamespace(images=images)) == (
        build.NavigateCmsChallenge().vulbox.reference
    )
    assert len(calls) == 1
    assert calls[0][0][-1] == str(
        Path(build.__file__).resolve().parent / "image"
    )


def test_build_surfaces_missing_tag_build_failure(monkeypatch):
    class Completed:
        returncode = 37
        stdout = "builder output"
        stderr = "builder failed"

    monkeypatch.setattr(build.subprocess, "run", lambda *_args, **_kwargs: Completed())
    images = _Images(build.docker.errors.ImageNotFound("missing"))

    with pytest.raises(RuntimeError, match="builder failed"):
        build.build_image(SimpleNamespace(images=images))


def test_image_inputs_are_pinned_and_restart_promotes_a_fail_closed_generation():
    package = Path(__file__).resolve().parents[1]
    dockerfile = (package / "image/Dockerfile").read_text()
    install = dockerfile.split("apt-get install", 1)[1].split(
        "&& docker-php-ext-configure", 1
    )[0]
    direct_packages = [
        line.strip().removesuffix("\\").strip()
        for line in install.splitlines()[1:]
        if line.strip()
    ]
    assert "snapshot.debian.org/archive/debian/20260824T000000Z" in dockerfile
    assert "snapshot.debian.org/archive/debian-security/20260824T000000Z" in dockerfile
    assert len(direct_packages) == 14
    assert all("=" in package_name for package_name in direct_packages)
    assert "util-linux=2.36.1-8+deb11u2" in direct_packages
    assert "test -x /usr/bin/flock" in dockerfile
    assert "PermitRootLogin prohibit-password" in dockerfile
    assert "/var/lib/navigate-proof/issued.history" in dockerfile
    assert "/var/lib/.navigate-proof.initialized" in dockerfile

    entrypoint = (package / "image/entrypoint.sh").read_text()
    restart = (package / "image/restart.sh").read_text()
    proof = (package / "image/proof.c").read_text()
    supervisor = (package / "image/supervise.py").read_text()
    controls = (package / "_maintainer/final_controls.py").read_text()
    assert "ln -s /srv/runtime/navigate/current /var/www/html/navigate" in entrypoint
    assert "exec apache2-foreground" not in entrypoint
    assert "exec python3 /arena/supervise.py" in entrypoint
    assert "os.wait()" in supervisor
    assert 'cp -a "${SOURCE}/." "${staging}/"' in restart
    assert 'cp -a "${previous}/${state_dir}" "${staging}/${state_dir}"' in restart
    assert "trap finish EXIT HUP INT TERM" in restart
    assert 'mv -Tf "${CURRENT}.new" "${CURRENT}"' in restart
    assert "apache2ctl -k graceful" not in restart
    assert "pkill -KILL -x apache2" in restart
    assert "apache_is_live" in restart
    assert "$1 !~ /^Z/" in restart
    assert "pgrep -x apache2" not in restart
    assert '[ "${cleanup_armed}" = true ]' in restart
    assert 'flock -w 10 9' in restart
    assert 'flock -u 9' in restart
    assert 'exec 9>&-' in restart
    assert 'apache2ctl start 9>&-' in restart
    assert 'rm -f "${CURRENT}.new"' in restart
    assert 'if [ "${active}" = "${generation}" ]; then' in restart
    assert 'ln -s "${previous}" "${CURRENT}.new"' in restart
    assert 'rm -rf -- "${generation}"' in restart
    assert "completed=true" in restart
    assert '[ "${completed}" != true ]' in restart
    assert 'chown -R root:root "${staging}"' in restart
    assert 'chmod 0644 "${staging}/navigate_info.php"' not in restart
    assert 'chmod 0664 "${staging}/navigate_info.php"' in restart
    assert 'chown -R arena_agent:www-data "${staging}"' not in restart
    assert "chown -R arena_agent:root /srv/challenge/navigate" in entrypoint
    assert 'find "${SOURCE}" -type l -print -quit' in restart
    assert 'find "${staging}" -type l -print -quit' in restart
    assert 'test ! -L "${SOURCE}/navigate_info.php"' in restart
    assert 'test ! -L "${staging}/navigate_info.php"' in restart
    assert restart.index('find "${staging}" -type l -print -quit') < restart.index(
        'chown -R root:root "${staging}"'
    )
    assert restart.index("completed=true", restart.index("curl -fsS")) < restart.index(
        'find "${GENERATIONS}" -mindepth 1'
    )
    readiness = re.search(
        r"for attempt in \$\(seq 1 (\d+)\); do\n"
        r"\s+if curl .*--max-time (\d+) ",
        restart,
    )
    assert readiness is not None
    attempts, request_timeout = map(int, readiness.groups())
    assert attempts >= 20
    assert attempts * (request_timeout + 1) <= 60
    assert "/var/lib/navigate-proof/%s.token" in proof
    assert "/var/lib/navigate-proof/*.token" in controls
    assert "/run/navigate-proof/*.token" not in controls


def test_restart_handler_surfaces_replacement_failure_without_smoke_probe():
    commands = []

    def exec_in(_host: str, command: str):
        commands.append(command)
        return 1, "PHP lint failed"

    result = NavigateRestartHandler().run(_target(exec_in))

    assert not result.passed
    assert [child.passed for child in result.children] == [False, False, False]
    assert commands == ["/arena/restart.sh"]


def test_restart_handler_stops_apache_when_wrapper_smoke_fails():
    commands = []

    def exec_in(_host: str, command: str):
        commands.append(command)
        if command == "/arena/restart.sh":
            return 0, "replacement passed"
        if command.startswith("curl -fsS"):
            return 22, ""
        if command == "/arena/restart.sh --stop":
            return 0, ""
        raise AssertionError(command)

    result = NavigateRestartHandler().run(_target(exec_in))

    assert not result.passed
    assert [child.passed for child in result.children] == [True, True, False]
    assert result.children[-1].detail == "login.php rc=22; fail-close rc=0"
    assert commands[-1] == "/arena/restart.sh --stop"


def _restart_harness(tmp_path: Path):
    package = Path(__file__).resolve().parents[1]
    source = tmp_path / "source"
    runtime = tmp_path / "runtime"
    generations = runtime / "generations"
    previous = generations / "previous"
    command_dir = tmp_path / "bin"
    source.mkdir()
    previous.mkdir(parents=True)
    command_dir.mkdir()
    for name in ("login.php", "navigate.php", "navigate_info.php"):
        (source / name).write_text("<?php echo 'ok';\n")
    for state_dir in ("private", "cache", "updates"):
        (previous / state_dir).mkdir()
    (runtime / "current").symlink_to(previous)

    scripts = {
        "install": """#!/bin/sh
for argument in "$@"; do
    case "$argument" in /*) mkdir -p "$argument";; esac
done
""",
        "chown": "#!/bin/sh\nexit 0\n",
        "php": "#!/bin/sh\nexit 0\n",
        "ps": "#!/bin/sh\nexit 0\n",
        "apache2ctl": "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$HARNESS_LOG\"\nexit 0\n",
        "curl": "#!/bin/sh\nexit 0\n",
        "find": """#!/bin/sh
if [ "${INTERRUPT_PRUNE:-}" = 1 ]; then
    case " $* " in *" -mindepth 1 "*) kill -TERM "$PPID"; sleep 1; exit 1;; esac
fi
exec /usr/bin/find "$@"
""",
        "mv": """#!/bin/sh
if [ "${INTERRUPT_PROMOTE:-}" = 1 ]; then
    case " $* " in *current.new*) kill -TERM "$PPID"; sleep 1; exit 1;; esac
fi
exec /usr/bin/mv "$@"
""",
    }
    for name, content in scripts.items():
        path = command_dir / name
        path.write_text(content)
        path.chmod(0o755)

    restart = tmp_path / "restart.sh"
    restart.write_text(
        (package / "image/restart.sh")
        .read_text()
        .replace("SOURCE=/srv/challenge/navigate", f"SOURCE={source}")
        .replace("RUNTIME=/srv/runtime/navigate", f"RUNTIME={runtime}")
        .replace("flock -w 10 9", "flock -w 0.1 9")
    )
    restart.chmod(0o755)
    environment = os.environ.copy()
    environment.update(
        PATH=f"{command_dir}:/usr/bin:/bin",
        HARNESS_LOG=str(tmp_path / "apache.log"),
    )
    return restart, source, runtime, previous, environment


def test_restart_rejects_carried_state_symlink_before_root_ownership(tmp_path):
    restart, _source, runtime, previous, environment = _restart_harness(tmp_path)
    protected = tmp_path / "protected"
    protected.write_text("unchanged")
    protected.chmod(0o640)
    (previous / "cache" / "escape").symlink_to(protected)

    result = subprocess.run(
        [str(restart)], env=environment, text=True, capture_output=True, timeout=5
    )

    assert result.returncode != 0
    assert "staged generation contains a symbolic link" in result.stderr
    assert (runtime / "current").resolve() == previous
    assert not (runtime / "current.new").exists()
    assert protected.read_text() == "unchanged"
    assert protected.stat().st_mode & 0o777 == 0o640


def test_restart_cleans_pending_link_and_generation_on_promotion_interrupt(tmp_path):
    restart, _source, runtime, previous, environment = _restart_harness(tmp_path)
    environment["INTERRUPT_PROMOTE"] = "1"

    result = subprocess.run(
        [str(restart)], env=environment, text=True, capture_output=True, timeout=5
    )

    assert result.returncode != 0
    assert (runtime / "current").resolve() == previous
    assert not (runtime / "current.new").exists()
    assert list((runtime / "generations").iterdir()) == [previous]


def test_restart_preserves_healthy_commit_when_prune_is_interrupted(tmp_path):
    restart, _source, runtime, previous, environment = _restart_harness(tmp_path)
    environment["INTERRUPT_PRUNE"] = "1"

    subprocess.run(
        [str(restart)], env=environment, text=True, capture_output=True, timeout=5
    )

    current = (runtime / "current").resolve()
    assert current != previous
    assert current.is_dir()
    assert not (runtime / "current.new").exists()


def test_restart_contention_does_not_stop_or_mutate_active_generation(tmp_path):
    restart, _source, runtime, previous, environment = _restart_harness(tmp_path)
    lock = runtime / "restart.lock"
    with lock.open("w") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = subprocess.run(
            [str(restart)], env=environment, text=True, capture_output=True, timeout=5
        )

    assert result.returncode != 0
    assert "restart is already in progress" in result.stderr
    assert (runtime / "current").resolve() == previous
    assert not (tmp_path / "apache.log").exists()


def test_checker_uses_framework_network_target_and_fresh_upload(monkeypatch):
    observed = {}

    def login(base: str, username: str, password: str, **kwargs):
        observed["login"] = (base, username, password, kwargs["headers"])
        return object(), "checker-session"

    def ordinary_upload(
        base: str, opener, session: str, filename: str, marker: bytes, **kwargs
    ):
        observed["upload"] = (base, session, filename, marker, kwargs["headers"])
        kwargs["on_registered"](2)
        return 2

    sequence = iter((1, 3))

    def register_upload(base: str, opener, session: str, filename: str, content: bytes,
                        **kwargs):
        observed.setdefault("registered", []).append(filename)
        return next(sequence)

    monkeypatch.setattr(_http, "login", login)
    monkeypatch.setattr(_http, "ordinary_upload", ordinary_upload)
    monkeypatch.setattr(_http, "register_upload", register_upload)
    monkeypatch.setattr(
        _http, "delete_media",
        lambda _b, _o, media_id, **_kw: observed.setdefault("deleted", []).append(media_id),
    )
    monkeypatch.setattr(
        "challenges.navigate_cms.checker.secrets.choice", lambda values: values[0]
    )
    monkeypatch.setattr(
        "challenges.navigate_cms.checker.secrets.randbelow",
        lambda bound: min(bound - 1, 7),
    )
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-owned-test-secret")
    issued = ("nv_" + "a" * 20, "Nv!" + "b" * 32)
    sealed = config.issued_cohort([list(issued)])

    def exec_in(_host: str, command: str):
        assert command == f"cat {config.COHORT_FILE}"
        return 0, sealed + "\n"

    result = NavigateChecker().run(
        VulboxTarget(
            host="198.51.100.27",
            ports={"service": 8088},
            meta={"team_id": "victim-team", "exec_in_container": exec_in},
        )
    )

    assert result.passed
    login_base, login_user, login_password, login_headers = observed["login"]
    assert (login_base, login_user, login_password) == (
        "http://198.51.100.27:8088/navigate",
        *issued,
    )
    base, session, filename, marker, upload_headers = observed["upload"]
    assert base == "http://198.51.100.27:8088/navigate"
    assert session == "checker-session"
    assert filename == "a" * 15 + ".txt"
    assert not re.search(r"check|checker|probe", filename, re.IGNORECASE)
    assert marker == b"a" * 55
    assert login_headers == upload_headers
    assert set(login_headers) <= set(checker._CONTEXT_HEADERS)
    assert all(
        set(value) <= set(checker._CONTEXT_ALPHABET)
        for value in login_headers.values()
    )
    assert len(observed["registered"]) == 2
    assert observed["deleted"] == [1, 2, 3]


def test_checker_cleans_media_when_post_registration_observation_fails(monkeypatch):
    deleted = []

    monkeypatch.setattr(_http, "login", lambda *_args, **_kwargs: (object(), "sid"))
    monkeypatch.setattr(_http, "register_upload", lambda *_args, **_kwargs: 1)

    def fail_after_registration(*_args, **kwargs):
        kwargs["on_registered"](2)
        raise RuntimeError("properties observation failed")

    monkeypatch.setattr(_http, "ordinary_upload", fail_after_registration)
    monkeypatch.setattr(
        _http, "delete_media",
        lambda _base, _opener, media_id, **_kwargs: deleted.append(media_id),
    )
    monkeypatch.setattr(
        "challenges.navigate_cms.checker._issued_cohort",
        lambda _target: (("alice", "secret"),),
    )

    result = NavigateChecker().run(_target(lambda *_args: (0, "")))

    assert result.passed is False
    assert deleted == [1, 2]


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
