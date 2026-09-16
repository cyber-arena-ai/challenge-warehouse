from __future__ import annotations

from challenges.interface import VulboxTarget
from challenges.grafana_protected_contact_point import checker


def test_checker_uses_only_external_native_workflows(monkeypatch) -> None:
    record = {
        "uid": "cp-" + "a" * 24,
        "name": "Operations alerts 1234",
        "settings": {"url": "http://192.168.21.22:8123/hooks/" + "c" * 24},
    }
    updates: list[tuple[bool, dict]] = []

    def principals(_team_id: str, authority: str):
        marker = "1" if authority == "ordinary" else "2"
        return (("arena_" + marker * 20, "Gr!" + marker * 40),)

    class Client:
        def __init__(self, _base: str, username: str, _password: str):
            self.guarded = username == "arena_" + "2" * 20

        def contact_points(self):
            return 200, [record.copy()]

        def contact_point(self, uid: str):
            return (200, record.copy()) if uid == record["uid"] else (200, None)

        def update_contact_point(self, uid: str, document: dict):
            assert uid == record["uid"]
            updates.append((self.guarded, document.copy()))
            record.update(document)
            return 202

    monkeypatch.setattr(checker, "checker_principals", principals)
    monkeypatch.setattr(
        checker,
        "checker_contacts",
        lambda _team_id: ((record["uid"], record["name"], record["settings"]["url"]),),
    )
    monkeypatch.setattr(checker, "GrafanaClient", Client)
    target = VulboxTarget(
        host="prod",
        ports={"service": 3000},
        meta={
            "team_id": "victim",
            "exec_in_container": lambda *_args: (_ for _ in ()).throw(
                AssertionError("checker must not use infrastructure execution")
            ),
        },
    )

    assert checker.GrafanaChecker().run(target).passed
    assert [guarded for guarded, _document in updates] == [True, False]
    assert updates[1][1]["settings"] == updates[0][1]["settings"]
    assert "checker" not in str(record["name"]).lower()
    assert "arena" not in str(record["name"]).lower()


def test_checker_generated_names_use_ordinary_contact_shape() -> None:
    names = [checker._ordinary_name() for _ in range(20)]
    assert all("checker" not in name.lower() and "arena" not in name.lower()
               for name in names)


def test_checker_name_always_differs_from_current(monkeypatch) -> None:
    calls = iter(["Operations alerts 1234", "Support webhook 5678"])
    monkeypatch.setattr(
        checker, "contact_details", lambda _material: ("cp-" + "a" * 24, next(calls), "")
    )

    assert checker._ordinary_name("Operations alerts 1234") == "Support webhook 5678"
