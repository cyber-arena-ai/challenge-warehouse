from __future__ import annotations

import re

from challenges.interface import VulboxTarget
from challenges.xerte_media_upload_rce import checker


def test_checker_is_network_only_and_keeps_restart_state_in_the_poller(
    monkeypatch,
):
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-test-token")

    class FakeApp:
        def __init__(self):
            self.next_project = 1
            self.projects: dict[int, str] = {}
            self.media: dict[tuple[int, str], bytes] = {}
            self.project_names: list[str] = []
            self.media_names: list[str] = []
            self.media_bodies: list[bytes] = []

        def install(self):
            app = self

            class Api:
                def __init__(self, _base: str):
                    pass

                def login(self, username: str, _password: str):
                    return username

                def create_project(self, session: str, name: str):
                    app.project_names.append(name)
                    project_id = app.next_project
                    app.next_project += 1
                    app.projects[project_id] = session
                    return project_id

                def upload_media(self, session: str, path: str, filename: str,
                                 content: bytes):
                    app.media_names.append(filename)
                    app.media_bodies.append(content)
                    project_id = int(
                        path.strip("/").removeprefix("USER-FILES/").split("-", 1)[0])
                    assert app.projects[project_id] == session
                    app.media[(project_id, filename)] = content
                    return 200, b'{"added":true}'

                def fetch_media(self, path: str, filename: str):
                    project_id = int(
                        path.strip("/").removeprefix("USER-FILES/").split("-", 1)[0])
                    body = app.media.get((project_id, filename))
                    return (200, body) if body is not None else (404, b"")

                def media_listing(self, session: str, project_id: int):
                    if app.projects.get(project_id) != session:
                        return 200, b""
                    names = [name for (pid, name) in app.media if pid == project_id]
                    return 200, " ".join(names).encode()

            monkeypatch.setattr(checker, "XerteApi", Api)

    app = FakeApp()
    app.install()
    target = VulboxTarget(
        host="victim", ports={"service": 80},
        meta={
            "team_id": "victim",
            "exec_in_container": lambda *_args: (_ for _ in ()).throw(
                AssertionError("checker must not exec in production")),
        },
    )
    probe = checker.XerteChecker()

    first = probe.run(target)
    projects_after_first = app.next_project
    second = probe.run(target)

    assert first.passed and second.passed
    assert projects_after_first == 4
    assert app.next_project == 6
    assert len(probe._anchors) == 1
    assert all(re.fullmatch(r"[0-9a-f]{24}", name)
               for name in app.project_names)
    assert all(re.fullmatch(r"[0-9a-f]{24}\.txt", name)
               for name in app.media_names)
    assert all(len(body) == 18 for body in app.media_bodies)
