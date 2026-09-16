from __future__ import annotations

import base64
import hashlib
import json
from io import BytesIO
from pathlib import Path
import re
import tarfile
import urllib.error
import urllib.request

import pytest

from challenges.interface import Flag, ObservationStatus, OracleKind, VulboxTarget

from challenges.opentsdb_graph_command import checker, config
from challenges.opentsdb_graph_command.challenge import OpenTSDBGraphCommandChallenge
from challenges.opentsdb_graph_command.client import OpenTSDBClient
from challenges.opentsdb_graph_command.flag_handler import OpenTSDBExecuteFlagHandler
from challenges.opentsdb_graph_command._maintainer.final_controls import (
    FIXED_SHA256,
    apply_exact_repair,
)


ROUND_SEED = "01" * 32
SECOND_ROUND_SEED = "02" * 32
THIRD_ROUND_SEED = "03" * 32


class Recorder:
    def __init__(self) -> None:
        self.commands: list[str] = []
        self.placement_state: str | None = None
        self.pending_state: str | None = None
        self.tokens: set[str] = set()
        self.interrupt_after_token = False

    def __call__(self, _host: str, command: str) -> tuple[int, str]:
        self.commands.append(command)
        if command.startswith("test -d /var/lib/opentsdb-release"):
            states = []
            if self.placement_state is not None:
                states.extend(("current", self.placement_state))
            if self.pending_state is not None:
                states.extend(("pending", self.pending_state))
            if states:
                return 0, "\n".join(states)
            return (45, "") if self.tokens else (44, "")
        if "/var/lib/opentsdb-release/current.pending.new" in command:
            encoded = re.findall(r"printf %s ([A-Za-z0-9+/=]+) \| base64 -d", command)
            assert len(encoded) == 3
            pending = base64.b64decode(encoded[0]).decode()
            assert pending == base64.b64decode(encoded[2]).decode()
            self.pending_state = pending
            _key, target_id, predecessor_id = pending.splitlines()
            self.tokens.add(target_id)
            if self.interrupt_after_token:
                self.interrupt_after_token = False
                return 1, "interrupted"
            self.placement_state = pending
            self.pending_state = None
            self.tokens = {
                value for value in (target_id, predecessor_id) if value != "-"
            }
        return 0, ""


def target(
    recorder: Recorder, *, round_seed: str | None = ROUND_SEED
) -> VulboxTarget:
    return VulboxTarget(
        host="victim",
        ports={"service": 4242},
        meta={
            "team_id": "victim-team",
            "exec_in_container": recorder,
            "round_context_seed": round_seed,
        },
    )


def test_execute_store_contract() -> None:
    challenge = OpenTSDBGraphCommandChallenge()
    spec = challenge.flag_store_specs()[0]
    assert challenge.name == "opentsdb-metrics"
    assert challenge.vulbox.reference == "cyberarena/chal-opentsdb-metrics:v1"
    assert spec.name == "command"
    assert spec.kind is OracleKind.EXECUTE
    assert spec.scope == "host.command.execute"


def test_principals_are_distinct_seed_derived_and_equal_role(monkeypatch) -> None:
    recorder = Recorder()
    handler = OpenTSDBExecuteFlagHandler()
    seeds = {"red": "a" * 64, "blue": "b" * 64}
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-owned-test-secret")
    principals = handler.provision_principals(target(recorder), seeds)
    assert set(principals) == set(seeds)
    assert len({p.principal_id for p in principals.values()}) == 2
    assert len({tuple(p.credentials.items()) for p in principals.values()}) == 2
    assert all(set(p.credentials) == {"token"} for p in principals.values())
    assert "red" not in recorder.commands[0]
    assert "blue" not in recorder.commands[0]
    encoded = re.search(r"printf %s ([A-Za-z0-9+/=]+)", recorder.commands[0])
    assert encoded is not None
    configured_text = base64.b64decode(encoded.group(1)).decode()
    configured = configured_text.splitlines()
    assert len(configured) == len(seeds)
    assert configured == sorted(configured)
    assert all(
        re.fullmatch(r"player-[0-9a-f]{12}=[0-9a-f]{64}", row)
        for row in configured
    )
    plaintext = [p.credentials["token"] for p in principals.values()]
    assert all(re.fullmatch(r"[0-9a-f]{48}", token) for token in plaintext)
    assert all(token not in configured_text for token in plaintext)
    assert all(
        hashlib.sha256(token.encode()).hexdigest() in configured_text
        for token in plaintext
    )
    assert recorder.commands[0].endswith("&& /arena/start-opentsdb.sh")

    seal = recorder.commands[1]
    assert "chown root:root" in seal and "chmod 0400" in seal
    assert seal.endswith(f"&& mv -f {config.COHORT_FILE}.new {config.COHORT_FILE}")
    sealed = re.search(r"printf %s '?([A-Za-z0-9+/=]+)'? \| base64 -d", seal)
    assert sealed is not None
    assert config.sealed_cohort(base64.b64decode(sealed.group(1)).decode()) == tuple(
        sorted(
            (p.principal_id, p.credentials["token"]) for p in principals.values()
        )
    )


COHORT = tuple(
    sorted((f"player-{index:012x}", f"{index:048x}") for index in range(1, 5))
)


def cohort_target(sealed: str | None = None) -> VulboxTarget:
    """A victim whose root-only bookkeeping holds the sealed issued cohort."""
    text = config.issued_cohort([list(a) for a in COHORT]) if sealed is None else sealed

    def exec_in(_host: str, command: str) -> tuple[int, str]:
        assert command.endswith(f" {config.COHORT_FILE}")
        return 0, text

    return VulboxTarget(
        host="victim",
        ports={"service": 4242},
        meta={"team_id": "victim-team", "exec_in_container": exec_in},
    )


def fake_client(
    constructed: list, *, legend_mode: str = "complete", denied: tuple = ()
):
    """A network-free OpenTSDB client; `denied` names tokens the victim rejects."""
    denied_tokens, denied_paths = denied or ((), ())

    class FakeClient:
        def __init__(self, host: str, port: int, token: str | None = None):
            constructed.append((host, port, token))
            self.denied = token in denied_tokens
            self.points: dict[str, int] = {}
            self.metric = ""
            self.tag = ""
            self.tag_key = ""

        def _rejected(self, path: str) -> bool:
            return self.denied and path in denied_paths

        def put(
            self,
            metric: str,
            tag: str,
            value: int,
            *,
            tag_key: str,
            timestamp: int,
        ):
            if self._rejected("/api/put"):
                return 401, "", timestamp
            self.metric, self.tag, self.tag_key = metric, tag, tag_key
            self.points[str(timestamp)] = value
            return 200, '{"success":1}', timestamp

        def query(self, metric: str, tag: str, _timestamp: int, *, tag_key: str):
            if self._rejected("/api/query"):
                return 401, ""
            assert (metric, tag, tag_key) == (self.metric, self.tag, self.tag_key)
            return 200, json.dumps([{"dps": self.points}])

        def request(self, path: str):
            if self._rejected(path):
                return 401, ""
            return 200, "OpenTSDB"

        def graph(
            self,
            metric: str,
            tag: str,
            _timestamp: int,
            *,
            tag_key: str,
            legend: str,
            dimensions: str,
        ):
            if self._rejected("/q"):
                return 401, ""
            assert (metric, tag, tag_key) == (self.metric, self.tag, self.tag_key)
            assert legend in checker._LEGENDS
            assert dimensions in checker._DIMENSIONS
            assert not re.search(r"arena|checker|probe", f"{metric} {tag} {tag_key}")
            return 200, json.dumps(
                {"plotted": len(self.points), "points": len(self.points)}
            )

        def graph_png(
            self,
            metric: str,
            tag: str,
            _timestamp: int,
            *,
            tag_key: str,
            legend: str,
            dimensions: str,
        ):
            if self._rejected("/q"):
                return 401, b""
            assert (metric, tag, tag_key) == (self.metric, self.tag, self.tag_key)
            assert legend in checker._LEGENDS
            assert dimensions in checker._DIMENSIONS
            if legend_mode == "complete":
                legend_value = checker._LEGENDS.index(legend)
            elif legend_mode == "native-alias":
                legend_value = {
                    "left": 0,
                    "right": 1,
                    "top": 1,
                    "bottom": 2,
                    "center": 3,
                    "out": 4,
                }[legend]
            elif legend_mode == "left-only":
                legend_value = int(legend == "left")
            elif legend_mode == "paired-alias":
                legend_value = int(legend in {"right", "bottom", "out"})
            else:
                legend_value = 0
            pixel = (len(self.points) * 16 + legend_value, 0, 0, 255)
            return 200, bytes(pixel) * 1024

    return FakeClient


def patch_checker(monkeypatch, client, *, point_delta: int = 0) -> None:
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-owned-test-secret")
    monkeypatch.setattr(checker, "OpenTSDBClient", client)
    monkeypatch.setattr(
        checker.OpenTSDBChecker,
        "_rendered_pixels",
        staticmethod(lambda body, _dimensions: body),
    )
    monkeypatch.setattr(checker.secrets, "choice", lambda values: values[0])
    monkeypatch.setattr(
        checker.secrets,
        "randbelow",
        lambda bound: (
            point_delta if bound == 3 else 0 if bound == len(COHORT) else 23456
        ),
    )
    monkeypatch.setattr(checker.secrets, "token_hex", lambda _count: "abc123def0")


@pytest.mark.parametrize("point_delta", (0, 1, 2))
@pytest.mark.parametrize(
    ("legend_mode", "accepted"),
    (
        ("complete", True),
        ("native-alias", True),
        ("ignored", False),
        ("left-only", False),
        ("paired-alias", False),
    ),
)
def test_checker_is_network_only_and_exercises_every_issued_principal(
    monkeypatch, point_delta: int, legend_mode: str, accepted: bool
) -> None:
    constructed: list[tuple[str, int, str | None]] = []
    patch_checker(
        monkeypatch,
        fake_client(constructed, legend_mode=legend_mode),
        point_delta=point_delta,
    )
    result = checker.OpenTSDBChecker().run(cohort_target())
    assert result.passed is accepted
    if accepted:
        assert constructed == [("victim", 4242, token) for _, token in COHORT]
    else:
        assert result.detail.startswith(f"{COHORT[0][0]}: legend positions ")


@pytest.mark.parametrize("denied_index", range(len(COHORT)))
@pytest.mark.parametrize(
    "denied_paths",
    (("/api/put",), ("/api/put", "/api/query", "/", "/q")),
    ids=("put-denied", "removed"),
)
def test_denying_any_single_issued_principal_turns_health_red(
    monkeypatch, denied_index: int, denied_paths: tuple
) -> None:
    principal, token = COHORT[denied_index]
    constructed: list[tuple[str, int, str | None]] = []
    patch_checker(
        monkeypatch, fake_client(constructed, denied=((token,), denied_paths))
    )
    result = checker.OpenTSDBChecker().run(cohort_target())
    assert result.passed is False
    assert result.detail.startswith(f"{principal}: metric put failed: 401")


@pytest.mark.parametrize("sealed", ("", "   ", "dGFtcGVyZWQ.deadbeef"))
def test_checker_refuses_a_missing_or_untrusted_issued_cohort(
    monkeypatch, sealed: str
) -> None:
    constructed: list[tuple[str, int, str | None]] = []
    patch_checker(monkeypatch, fake_client(constructed))
    result = checker.OpenTSDBChecker().run(cohort_target(sealed))
    assert result.passed is False
    assert "untrusted" in result.detail
    assert constructed == []


def test_decisive_requests_use_open_ended_participant_profiles(monkeypatch) -> None:
    class Response(BytesIO):
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.close()

    requests: list[urllib.request.Request] = []

    def urlopen(request: urllib.request.Request, *, timeout: float):
        assert timeout > 0
        requests.append(request)
        if request.full_url.endswith("&png"):
            return Response(b"png")
        return Response(b'{"success":1}')

    random_values = iter(
        (
            0, 14, 3,  # curl family and version
            1, 25, 2999, 199,  # browser family and version
            2, 8, 5,  # requests family and version
            3, 6, 9,  # wget family and version
            0, 0, 0,  # a distinct curl version
        )
    )

    def randbelow(bound: int) -> int:
        value = next(random_values)
        assert 0 <= value < bound
        return value

    monkeypatch.setattr(
        "challenges.opentsdb_graph_command.client.urllib.request.urlopen", urlopen
    )
    monkeypatch.setattr(
        "challenges.opentsdb_graph_command.client.secrets.randbelow", randbelow
    )
    monkeypatch.setattr(
        "challenges.opentsdb_graph_command.client.secrets.choice", lambda values: values[0]
    )
    curl = OpenTSDBClient("victim", 4242, "issued-token")
    browser = OpenTSDBClient("victim", 4242, "issued-token")
    requests_client = OpenTSDBClient("victim", 4242, "issued-token")
    wget = OpenTSDBClient("victim", 4242, "issued-token")
    second_curl = OpenTSDBClient("victim", 4242, "issued-token")
    curl.put("system.cpu.user", "worker-a", 1, timestamp=1)
    browser.query("system.cpu.user", "worker-a", 1)
    requests_client.request("/")
    wget.graph("system.cpu.user", "worker-a", 1)
    curl.graph_png("system.cpu.user", "worker-a", 1)

    agents = [request.get_header("User-agent") for request in requests]
    assert agents[0].startswith("curl/")
    assert agents[1].startswith("Mozilla/")
    assert agents[2].startswith("python-requests/")
    assert agents[3].startswith("Wget/")
    assert agents[4].startswith("curl/")
    assert agents[0] == agents[4]
    assert curl.user_agent != second_curl.user_agent
    assert all(agent and not agent.startswith("Python-urllib/") for agent in agents)
    assert requests[0].get_header("Accept") == "application/json"
    assert requests[1].get_header("Accept") == "application/json"
    assert requests[2].get_header("Accept").startswith("text/html")
    assert requests[3].get_header("Accept") == "application/json"
    assert requests[4].get_header("Accept").startswith("image/png")


def test_python_urllib_only_service_makes_complete_health_red(monkeypatch) -> None:
    class Response(BytesIO):
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.close()

    def python_urllib_only(request: urllib.request.Request, *, timeout: float):
        assert timeout > 0
        agent = request.get_header("User-agent")
        if agent is None or agent.startswith("Python-urllib/"):
            return Response(b'{"success":1}')
        raise urllib.error.HTTPError(request.full_url, 400, "denied", {}, BytesIO())

    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-owned-test-secret")
    monkeypatch.setattr(
        "challenges.opentsdb_graph_command.client.urllib.request.urlopen",
        python_urllib_only,
    )
    result = checker.OpenTSDBChecker().run(cohort_target())
    assert result.passed is False
    assert result.detail.startswith(f"{COHORT[0][0]}: metric put failed: 400")


def test_execute_retry_reconciles_token_rename_before_state_commit() -> None:
    recorder = Recorder()
    recorder.interrupt_after_token = True
    handler = OpenTSDBExecuteFlagHandler()
    _, target_id = config.round_context(ROUND_SEED)
    flag = Flag("FLAG{" + "A" * 32 + "}")
    with pytest.raises(RuntimeError, match="rotation failed"):
        handler.plant(target(recorder), {"command": flag})
    assert recorder.placement_state is None
    assert recorder.pending_state is not None
    assert recorder.tokens == {target_id}

    handle = handler.plant(target(recorder), {"command": flag})["command"]
    assert handler.flag_id(handle) == (
        f"/usr/local/libexec/opentsdb-release --target-{target_id}"
    )
    assert recorder.pending_state is None
    assert recorder.tokens == {target_id}
    placement = recorder.commands[1]
    pending_commit = placement.index("current.pending.new /var/lib/opentsdb-release/current.pending")
    token_commit = placement.index(
        f".token.new /var/lib/opentsdb-release/{target_id}.token"
    )
    state_commit = placement.index("current.new /var/lib/opentsdb-release/current")
    assert pending_commit < token_commit < state_commit


def test_execute_lost_response_retains_published_predecessor() -> None:
    class LostResponseRecorder(Recorder):
        lose_response = False

        def __call__(self, host: str, command: str) -> tuple[int, str]:
            result = super().__call__(host, command)
            if (
                self.lose_response
                and "/var/lib/opentsdb-release/current.pending.new" in command
                and result[0] == 0
            ):
                self.lose_response = False
                return 1, "lost response after cleanup"
            return result

    recorder = LostResponseRecorder()
    handler = OpenTSDBExecuteFlagHandler()
    _, first_id = config.round_context(ROUND_SEED)
    _, second_id = config.round_context(SECOND_ROUND_SEED)
    _, third_id = config.round_context(THIRD_ROUND_SEED)
    first_flag = Flag("FLAG{" + "A" * 32 + "}")
    first = handler.plant(target(recorder), {"command": first_flag})["command"]

    recorder.lose_response = True
    second_flag = Flag("FLAG{" + "B" * 32 + "}")
    with pytest.raises(RuntimeError, match="rotation failed"):
        handler.plant(
            target(recorder, round_seed=SECOND_ROUND_SEED),
            {"command": second_flag},
        )
    assert recorder.tokens == {first_id, second_id}
    assert handler.flag_id(first) == (
        f"/usr/local/libexec/opentsdb-release --target-{first_id}"
    )

    retry = handler.plant(
        target(recorder, round_seed=SECOND_ROUND_SEED),
        {"command": second_flag},
    )["command"]
    assert handler.flag_id(retry) == (
        f"/usr/local/libexec/opentsdb-release --target-{second_id}"
    )
    assert recorder.tokens == {first_id, second_id}

    third_flag = Flag("FLAG{" + "C" * 32 + "}")
    handler.plant(
        target(recorder, round_seed=THIRD_ROUND_SEED),
        {"command": third_flag},
    )
    assert recorder.tokens == {second_id, third_id}


def test_execute_targets_rotate_and_do_not_expose_flags() -> None:
    recorder = Recorder()
    handler = OpenTSDBExecuteFlagHandler()
    first = handler.plant(
        target(recorder), {"command": Flag("FLAG{" + "A" * 32 + "}")}
    )["command"]
    retry = handler.plant(
        target(recorder), {"command": Flag("FLAG{" + "A" * 32 + "}")}
    )["command"]
    changed_proof = handler.plant(
        target(recorder), {"command": Flag("FLAG{" + "B" * 32 + "}")}
    )["command"]
    second = handler.plant(
        target(recorder, round_seed=SECOND_ROUND_SEED),
        {"command": Flag("FLAG{" + "A" * 32 + "}")},
    )["command"]
    first_id = handler.flag_id(first)
    assert first_id == handler.flag_id(retry) == handler.flag_id(changed_proof)
    assert first_id != handler.flag_id(second)
    assert re.fullmatch(
        r"/usr/local/libexec/opentsdb-release --target-[0-9a-f]{24}", first_id or ""
    )
    decoded = base64.urlsafe_b64decode(first).decode()
    assert "FLAG{" not in decoded
    assert recorder.placement_state is not None
    assert "FLAG{" not in recorder.placement_state
    assert "chmod 0400" in recorder.commands[1]


def test_round_context_is_stable_domain_separated_and_rotates() -> None:
    key, target_id = config.round_context(ROUND_SEED)
    assert (key, target_id) == config.round_context(ROUND_SEED)
    assert (key, target_id) != config.round_context(SECOND_ROUND_SEED)
    assert len(key) == 64
    assert len(target_id) == 24
    assert key[:24] != target_id


@pytest.mark.parametrize("seed", (None, "", "g" * 64, "0" * 63))
def test_round_context_seed_is_required(seed) -> None:
    recorder = Recorder()
    with pytest.raises(RuntimeError, match="round context unavailable"):
        OpenTSDBExecuteFlagHandler().plant(
            target(recorder, round_seed=seed),
            {"command": Flag("FLAG{" + "A" * 32 + "}")},
        )
    assert recorder.commands == []


def test_cached_target_must_match_round_seed() -> None:
    recorder = Recorder()
    key, target_id = config.round_context(ROUND_SEED)
    tampered_target = "f" * 24 if target_id != "f" * 24 else "e" * 24
    recorder.placement_state = f"{key}\n{tampered_target}\n-"

    with pytest.raises(RuntimeError, match="irreconstructible"):
        OpenTSDBExecuteFlagHandler().plant(
            target(recorder),
            {"command": Flag("FLAG{" + "A" * 32 + "}")},
        )


def test_orphaned_execute_state_fails_closed(monkeypatch) -> None:
    class OrphanRecorder(Recorder):
        def __call__(self, _host: str, command: str) -> tuple[int, str]:
            if command.startswith("test -d /var/lib/opentsdb-release"):
                return 45, ""
            return super().__call__(_host, command)

    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-owned-test-secret")
    with pytest.raises(RuntimeError, match="placement-state integrity"):
        OpenTSDBExecuteFlagHandler().plant(
            target(OrphanRecorder()),
            {"command": Flag("FLAG{" + "A" * 32 + "}")},
        )


def test_missing_execute_proof_is_an_integrity_failure() -> None:
    class MissingRecorder(Recorder):
        def __call__(self, _host: str, command: str) -> tuple[int, str]:
            return (0, "") if command == "true" else (1, "")

    handle = base64.urlsafe_b64encode(
        json.dumps({"target_id": "a" * 24}).encode()
    ).decode()
    observation = OpenTSDBExecuteFlagHandler().retrieve(
        target(MissingRecorder()), handle, expected="FLAG{missing}"
    )
    assert observation.status is ObservationStatus.NOT_FOUND


def test_retained_control_reconstructs_exact_upstream_repair() -> None:
    package = Path(__file__).resolve().parents[1]
    archive = package / "image/opentsdb-22b27ea30a859a6dbdcd65fcdf61190d46e1b677.tar"
    with tarfile.open(archive) as source_archive:
        member = source_archive.extractfile("opentsdb/src/tsd/GraphHandler.java")
        assert member is not None
        fixed = apply_exact_repair(member.read())
    assert hashlib.sha256(fixed).hexdigest() == FIXED_SHA256


def test_runtime_dependencies_and_restart_failure_are_pinned_and_fail_closed() -> None:
    package = Path(__file__).resolve().parents[1]
    dockerfile = (package / "image/Dockerfile").read_text()
    install = dockerfile.split("apt-get install", 1)[1].split("&& rm", 1)[0]
    direct_packages = [
        line.strip().removesuffix("\\").strip()
        for line in install.splitlines()[1:]
        if line.strip()
    ]
    assert len(direct_packages) == 12
    assert all("=" in package_name for package_name in direct_packages)

    restart = (package / "image/restart.sh").read_text()
    start = (package / "image/start-opentsdb.sh").read_text()
    assert "trap fail_closed ERR" in restart
    assert "trap - ERR" in restart
    assert "/arena/start-opentsdb.sh --stop" in restart
    assert "exit 1" in restart
    assert "stop_opentsdb || true" in start
    assert "pgrep -f '[n]et.opentsdb.tools.TSDMain'" in start


def test_auth_plugin_compares_digests_and_retains_no_presented_token() -> None:
    package = Path(__file__).resolve().parents[1]
    plugin = (package / "image/ArenaAuthentication.java").read_text()
    assert 'MessageDigest.getInstance("SHA-256")' in plugin
    assert "usersByDigest.get(digest(token))" in plugin
    assert "usersByToken" not in plugin
    assert "private final String token" not in plugin
    assert "getToken() { return new byte[0]; }" in plugin
