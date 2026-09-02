"""Handler contract: placement, the EXECUTE oracle, and principal issuing.

Runs against a scripted container and a stubbed application, so it exercises the
handler's own logic without Docker.
"""

from __future__ import annotations

import base64
import re
import secrets

import pytest

from challenges.interface import ObservationStatus, Flag, VulboxTarget
from challenges.xerte_media_upload_rce._ids import (
    CATFLAG_PATH, CHECKER_PRINCIPAL_COUNT, SERVICE_USER, checker_principals,
    decode_execute_target, pack_handle)
from challenges.xerte_media_upload_rce.flag_handler import (
    OBJECTIVE_PATH, XerteFlagHandler)

_B64_WRITE = re.compile(r"printf %s (\S+) \| base64 -d > (\S+)\.new")
_PRINTF_WRITE = re.compile(r"printf '(?:%s ?)+\\n' (.+?) > (\S+)\.new")

OWNER = "curator0a1b2c"
FLAG = "FLAG{example-round-proof}"


class FakeContainer:
    """Minimal shell: remembers files written through the handler's commands."""

    def __init__(self, *, catflag_output: str | None = None):
        self.files: dict[str, str] = {}
        self.commands: list[str] = []
        self.catflag_output = catflag_output

    def __call__(self, _host: str, command: str) -> tuple[int, str]:
        self.commands.append(command)
        if command.startswith("/arena/facility.sh credentials admin"):
            return 0, "user=siteadminx\npass=Sa1!x\n"
        if command.startswith("/arena/facility.sh credentials objective"):
            return 0, "key=objective-test-key\n"
        if command.startswith("test -s ") and " && cat " in command:
            path = command.split("test -s ", 1)[1].split(" &&", 1)[0]
            return (0, self.files[path]) if path in self.files else (1, "")
        if command.startswith(f"runuser -u {SERVICE_USER} -- {CATFLAG_PATH} "):
            operation = command.rsplit(" ", 1)[1].strip("'")
            stored = self.files.get(OBJECTIVE_PATH, "")
            if self.catflag_output is not None:
                return 0, self.catflag_output
            if stored.startswith(operation + "\n"):
                return 0, stored.split("\n", 1)[1].strip()
            return 6, ""
        if "mv -f" in command:
            self._write(command)
            return 0, ""
        return 0, ""

    def _write(self, command: str) -> None:
        encoded = _B64_WRITE.search(command)
        if encoded:
            self.files[encoded.group(2)] = base64.b64decode(encoded.group(1)).decode()
            return
        plain = _PRINTF_WRITE.search(command)
        if plain:
            self.files[plain.group(2)] = plain.group(1).strip() + "\n"


class FakeApp:
    """Xerte, as far as the handler uses it."""

    def __init__(self, *, project_id: int = 4):
        self.project_id = project_id
        self.added: list[tuple[str, str]] = []
        self.logins: list[tuple[str, str]] = []
        self.created = 0
        self.media: dict[tuple[int, str], bytes] = {}

    def install(self, monkeypatch, module):
        app = self

        class Api:
            def __init__(self, base: str):
                self.base = base

            def login(self, username, password):
                app.logins.append((username, password))
                return object()

            def add_user(self, _admin, username, password, *_a):
                app.added.append((username, password))
                return 200, b"ok"

            def create_project(self, _session, _name):
                app.created += 1
                return app.project_id

            def upload_media(self, _session, path, filename, content, **_k):
                project_id = int(
                    path.strip("/").removeprefix("USER-FILES/").split("-", 1)[0])
                app.media[(project_id, filename)] = content
                return 200, b'{"added":[{"name":"handbook.txt"}]}'

            def media_listing(self, _session, project_id):
                names = [name for (pid, name) in app.media if pid == project_id]
                return 200, " ".join(names).encode()

            def fetch_media(self, path, filename):
                project_id = int(
                    path.strip("/").removeprefix("USER-FILES/").split("-", 1)[0])
                body = app.media.get((project_id, filename))
                return (200, body) if body is not None else (404, b"")

        monkeypatch.setattr(module, "XerteApi", Api)
        monkeypatch.setattr(module, "resolve_host", lambda host: host)


@pytest.fixture
def env(monkeypatch):
    from challenges.xerte_media_upload_rce import flag_handler as module
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-test-token")
    container = FakeContainer()
    FakeApp().install(monkeypatch, module)
    target = VulboxTarget(host="prod", ports={"service": 80},
                          meta={"team_id": "victim", "exec_in_container": container})
    return XerteFlagHandler(), target, container


def test_plant_publishes_the_locator_and_hides_the_proof(env):
    handler, target, container = env
    handles = handler.plant(target, {"command": Flag(FLAG)})
    published = handler.flag_id(handles["command"])
    target_fields = decode_execute_target(published)

    assert set(target_fields) == {"v", "op"}
    assert FLAG not in published
    # the proof itself only ever reaches the root-owned objective file
    assert container.files[OBJECTIVE_PATH].endswith(FLAG + "\n")
    assert f"chmod 0600 {OBJECTIVE_PATH}.new" in " ".join(container.commands)


def test_plant_is_convergent_and_does_not_rotate_within_a_round(env):
    handler, target, _ = env
    first = handler.plant(target, {"command": Flag(FLAG)})
    second = handler.plant(target, {"command": Flag(FLAG)})
    assert first == second


def test_plant_repairs_missing_authoritative_state_instead_of_trusting_cache(env):
    handler, target, container = env
    first = handler.plant(target, {"command": Flag(FLAG)})["command"]
    del container.files[OBJECTIVE_PATH]

    repaired = handler.plant(target, {"command": Flag(FLAG)})["command"]

    assert repaired == first
    assert container.files[OBJECTIVE_PATH].endswith(FLAG + "\n")
    assert handler.retrieve(target, repaired, expected=FLAG).status is (
        ObservationStatus.PRESENT)


def test_a_new_round_rotates_the_published_operation(env):
    handler, target, _ = env
    first = handler.flag_id(handler.plant(target, {"command": Flag(FLAG)})["command"])
    second = handler.flag_id(
        handler.plant(target, {"command": Flag("FLAG{next-round}")})["command"])
    assert decode_execute_target(first)["op"] != decode_execute_target(second)["op"]


def test_retrieve_exercises_the_helper_rather_than_reading_its_file(env):
    handler, target, container = env
    handle = handler.plant(target, {"command": Flag(FLAG)})["command"]
    observation = handler.retrieve(target, handle, expected=FLAG)

    assert observation.status is ObservationStatus.PRESENT
    assert observation.value == FLAG
    helper_calls = [c for c in container.commands if c.startswith("runuser ")]
    assert len(helper_calls) == 1 and CATFLAG_PATH in helper_calls[0]
    assert not any(c.startswith(("cat " + OBJECTIVE_PATH, "head " + OBJECTIVE_PATH))
                   for c in container.commands)


def test_retrieve_reports_a_stale_operation_as_missing(env):
    handler, target, _ = env
    handler.plant(target, {"command": Flag(FLAG)})
    stale = pack_handle({"store": "command", "op": "0" * 32, "flag": FLAG})
    assert handler.retrieve(target, stale, expected=FLAG).status is (
        ObservationStatus.NOT_FOUND)


def test_retrieve_never_raises_on_a_broken_handle(env):
    handler, target, _ = env
    for bad in ("", "not-base64!", "e30"):
        assert handler.retrieve(target, bad).status is ObservationStatus.ERROR


def test_every_attacker_gets_one_distinct_seed_derived_account(env):
    handler, target, _ = env
    seeds = {f"team{i}": secrets.token_hex(32) for i in range(4)}
    granted = handler.provision_principals(target, seeds)

    assert set(granted) == set(seeds)
    assert len({p.principal_id for p in granted.values()}) == len(seeds)
    assert len({p.credentials["password"] for p in granted.values()}) == len(seeds)
    for attacker, principal in granted.items():
        assert principal.principal_id not in attacker
        assert attacker not in principal.credentials["password"]
        assert seeds[attacker][:10] not in principal.credentials["password"]


def test_checker_accounts_are_provisioned_with_the_same_ordinary_shape(
    monkeypatch,
):
    from challenges.xerte_media_upload_rce import flag_handler as module

    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-test-token")
    container = FakeContainer()
    app = FakeApp()
    app.install(monkeypatch, module)
    target = VulboxTarget(
        host="prod", ports={"service": 80},
        meta={"team_id": "victim", "exec_in_container": container})

    issued = XerteFlagHandler().provision_principals(
        target, {"attacker": secrets.token_hex(32)})
    added_users = {username for username, _password in app.added}

    assert set(issued) == {"attacker"}
    assert {username for username, _password in checker_principals("victim")} <= added_users
    assert len(app.added) == CHECKER_PRINCIPAL_COUNT + 1


def test_principal_issuing_is_deterministic_in_the_seed(env):
    handler, target, _ = env
    seeds = {"teamA": secrets.token_hex(32)}
    first = handler.provision_principals(target, seeds)
    second = handler.provision_principals(target, seeds)
    assert first["teamA"].credentials == second["teamA"].credentials
