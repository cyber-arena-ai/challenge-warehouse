from __future__ import annotations

from challenges.caddy_nextcloud_sso import _ids, checker
from challenges.interface import CheckResult, VulboxTarget


def test_guarded_lifecycle_matches_objective_owner_transition_shape(monkeypatch):
    team_id = "victim-team"
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-test-token")
    pairs = [_ids.checker_pair_seed(team_id)]
    while len(pairs) < checker.CHECKER_HISTORY_MAX:
        pairs.append(_ids.checker_pair_successor(team_id, pairs[-1][1][0]))
    files = {
        target: (owner, body, 0)
        for owner, control, shadow in pairs
        for target, body in (control, shadow)
    }
    events = []
    guarded_reads = []
    ordinary_reads = []
    transitions = []
    run = 0

    class GuardedClient:
        def __init__(self, slot):
            self.slot = slot

        def webdav(self, method, target, data=None, **_kwargs):
            nonlocal run
            if method == "GET":
                guarded_reads.append((run, self.slot, target))
                return (200, files[target][1]) if target in files else (404, b"")
            if method == "PUT":
                events.append((run, self.slot, method, target))
                identity = _ids.checker_document_identity(team_id, target)
                assert identity is not None and identity[0] == self.slot
                files[target] = (self.slot, data, run)
                return 201, b""
            if method == "DELETE":
                events.append((run, self.slot, method, target))
                identity = _ids.checker_document_identity(team_id, target)
                assert identity is not None and identity[0] == self.slot
                existed = target in files
                files.pop(target, None)
                return (204 if existed else 404), b""
            raise AssertionError(method)

    class OrdinaryClient:
        def webdav(self, method, target, **_kwargs):
            assert method == "GET"
            ordinary_reads.append((run, target))
            return 404, b""

    clients = [GuardedClient(slot) for slot in range(4)]
    monkeypatch.setattr(
        checker, "_listed_guarded_targets", lambda _client: tuple(files),
    )
    choices = iter(index % 2 for index in range(48))
    monkeypatch.setattr(checker.secrets, "randbelow", lambda _limit: next(choices))

    for run in range(1, 25):
        prior = _ids.checker_pair_chain(team_id, list(files))
        successor = _ids.checker_pair_successor(team_id, prior[-1][1])
        result = checker._guarded_lifecycle(team_id, [OrdinaryClient()], clients)
        assert result.passed
        event = [item for item in events if item[0] == run]
        deletes = [item for item in event if item[2] == "DELETE"]
        puts = [item for item in event if item[2] == "PUT"]
        assert len(deletes) == len(puts) == 2
        assert {item[1] for item in deletes} == {prior[0][0]}
        assert {item[1] for item in puts} == {successor[0]}
        assert {item[3] for item in deletes} == set(prior[0][1:])
        assert {item[3] for item in puts} == {
            successor[1][0], successor[2][0],
        }
        transitions.append((deletes[0][1], puts[0][1]))
        assert len(_ids.checker_pair_chain(team_id, list(files))) == (
            checker.CHECKER_HISTORY_MAX)

    assert {old == new for old, new in transitions} == {False, True}
    shadow_targets = {
        target for target in files
        if _ids.checker_document_identity(team_id, target)[1] == "shadow"
    }
    assert shadow_targets.isdisjoint(
        {target for _event, _slot, target in guarded_reads}
        | {target for _event, target in ordinary_reads}
    )


def test_history_reads_controls_but_never_shadow_decoys(monkeypatch):
    team_id = "victim-team"
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-test-token")
    owner, control, shadow = _ids.checker_pair_seed(team_id)
    cover = _ids._checker_document_from_material(
        team_id, 1, "cover", b"authenticated-checker-cover")
    records = (control[0], shadow[0], cover[0])
    reads = []

    class Client:
        def __init__(self, slot):
            self.slot = slot

        def webdav(self, method, target, **_kwargs):
            assert method == "GET"
            reads.append(target)
            return 200, _ids.checker_document_body(team_id, self.slot, target)

    monkeypatch.setattr(checker, "_listed_guarded_targets", lambda _client: records)

    grouped = checker._authenticated_guarded_documents(
        team_id, [Client(slot) for slot in range(4)])

    assert set(reads) == {control[0], cover[0]}
    assert shadow[0] not in reads
    assert grouped[(owner, "control")] == [control[0]]
    assert grouped[(owner, "shadow")] == [shadow[0]]
    assert grouped[(1, "cover")] == [cover[0]]


def test_pair_queue_repairs_interrupted_root_and_tail_operations(monkeypatch):
    team_id = "victim-team"
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-test-token")
    pairs = [_ids.checker_pair_seed(team_id)]
    while len(pairs) < checker.CHECKER_HISTORY_MAX:
        pairs.append(_ids.checker_pair_successor(team_id, pairs[-1][1][0]))
    files = {
        target: (owner, body)
        for owner, control, shadow in pairs
        for target, body in (control, shadow)
    }
    successor = _ids.checker_pair_successor(team_id, pairs[-1][1][0])
    assert successor == _ids.checker_pair_successor(team_id, pairs[-1][1][0])
    files.pop(pairs[0][1][0])
    files[successor[2][0]] = (successor[0], successor[2][1])
    events = []

    class Client:
        def __init__(self, owner):
            self.owner = owner

        def webdav(self, method, target, data=None, **_kwargs):
            events.append((self.owner, method, target))
            if method == "GET":
                return (200, files[target][1]) if target in files else (404, b"")
            if method == "PUT":
                files[target] = (self.owner, data)
                return 204, b""
            if method == "DELETE":
                existed = target in files
                files.pop(target, None)
                return (204 if existed else 404), b""
            raise AssertionError(method)

    clients = [Client(owner) for owner in range(4)]
    monkeypatch.setattr(
        checker, "_listed_guarded_targets", lambda _client: tuple(files))
    monkeypatch.setattr(checker.secrets, "randbelow", lambda _limit: 0)

    queue, covers = checker._reconciled_state(team_id, clients)

    assert len(queue) == checker.CHECKER_HISTORY_MAX
    assert covers == {owner: () for owner in range(4)}
    assert {pairs[0][1][0], pairs[0][2][0]}.isdisjoint(files)
    assert {successor[1][0], successor[2][0]} <= set(files)
    assert (pairs[0][0], "DELETE", pairs[0][2][0]) in events
    assert {
        owner for owner, method, target in events
        if method == "PUT" and target in {successor[1][0], successor[2][0]}
    } == {successor[0]}


def test_checker_documents_look_like_ordinary_user_content():
    names = [checker._document_name() for _ in range(40)]
    bodies = [checker._document_body() for _ in range(40)]

    assert all(name.endswith(".txt") and 4 < len(name) <= 80 for name in names)
    assert all("checker" not in name.lower() and "arena" not in name.lower()
               for name in names)
    assert all(len(body) > 20 and b" " in body and body[-1:] in b".?!"
               for body in bodies)
    assert all(b"checker" not in body.lower() and b"arena" not in body.lower()
               for body in bodies)


def test_checker_uses_only_public_native_requests(monkeypatch):
    files = {"ordinary": {}, "guarded": {}}

    class Client:
        def __init__(self, _base, username, _password):
            self.role = username
            self.username = username

        def login(self, **_kwargs):
            return True

        def webdav(self, method, name, data=None, **_kwargs):
            if self.role == "ordinary" and name.startswith("Guarded/"):
                return 404, b""
            bucket = files[self.role]
            if method == "PUT":
                bucket[name] = data
                return 201, b""
            if method == "GET":
                return (200, bucket[name]) if name in bucket else (404, b"")
            if method == "DELETE":
                existed = name in bucket
                bucket.pop(name, None)
                return (204 if existed else 404), b""
            raise AssertionError(method)

        def request(self, method, _path, **_kwargs):
            assert method == "PROPFIND"
            names = "".join(
                "<d:response><d:href>/remote.php/dav/files/guarded/"
                f"{name}</d:href></d:response>"
                for name in files["guarded"]
            )
            raw = (
                '<d:multistatus xmlns:d="DAV:">'
                '<d:response><d:href>/remote.php/dav/files/guarded/Guarded/'
                '</d:href></d:response>'
                + names
                + "</d:multistatus>"
            ).encode()
            return 207, raw, ""

    monkeypatch.setattr(
        checker, "_issued_principals",
        lambda _target: (("ordinary", "secret"),),
    )
    monkeypatch.setattr(
        checker, "guarded_principals",
        lambda _team: (("guarded", "secret"),) * 4,
    )
    monkeypatch.setattr(checker, "NextcloudClient", Client)
    monkeypatch.setattr(checker, "resolve_host", lambda host: host)
    monkeypatch.setattr(checker, "unauthenticated_status", lambda _base: 401)
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-test-token")
    target = VulboxTarget(
        host="victim", ports={"service": 8080},
        meta={
            "team_id": "victim-team",
            "exec_in_container": lambda *_args: (_ for _ in ()).throw(
                AssertionError("checker used infrastructure exec")
            ),
        },
    )

    result = checker.CaddyNextcloudChecker().run(target)

    assert result.passed is True


def test_checker_exercises_every_issued_identity_and_detects_one_denial(
    monkeypatch,
):
    issued = (("issued-a", "secret-a"), ("issued-b", "secret-b"))
    guarded = tuple((f"guarded-{slot}", "secret") for slot in range(4))
    events = []
    deny = None

    class Client:
        def __init__(self, _base, username, _password):
            self.username = username
            self.files = {}

        def login(self, **_kwargs):
            events.append((self.username, "login"))
            return self.username != deny

        def webdav(self, method, target, data=None, **_kwargs):
            events.append((self.username, method))
            if method == "PUT":
                self.files[target] = data
                return 201, b""
            if method == "GET":
                return ((200, self.files[target]) if target in self.files
                        else (404, b""))
            if method == "DELETE":
                self.files.pop(target, None)
                return 204, b""
            raise AssertionError(method)

    def guarded_check(_team, ordinary_clients, guarded_clients):
        assert {client.username for client in ordinary_clients} == {
            "issued-a", "issued-b",
        }
        assert {client.username for client in guarded_clients} == {
            account[0] for account in guarded
        }
        return CheckResult("team_folder_boundary", True)

    monkeypatch.setattr(checker, "_issued_principals", lambda _target: issued)
    monkeypatch.setattr(checker, "guarded_principals", lambda _team: guarded)
    monkeypatch.setattr(checker, "NextcloudClient", Client)
    monkeypatch.setattr(checker, "resolve_host", lambda host: host)
    monkeypatch.setattr(checker, "unauthenticated_status", lambda _base: 401)
    monkeypatch.setattr(checker, "_guarded_lifecycle", guarded_check)
    target = VulboxTarget(
        host="victim", ports={"service": 8080}, meta={"team_id": "victim-team"},
    )

    assert checker.CaddyNextcloudChecker().run(target).passed is True
    for username, _password in issued:
        assert [event for event in events if event[0] == username] == [
            (username, "login"), (username, "PUT"), (username, "GET"),
            (username, "DELETE"), (username, "GET"),
        ]

    events.clear()
    deny = "issued-b"
    result = checker.CaddyNextcloudChecker().run(target)
    assert result.passed is False
    assert result.children[-1].name == "sso_login"
    assert result.children[-1].detail == "issued=1/2, guarded=4/4"
