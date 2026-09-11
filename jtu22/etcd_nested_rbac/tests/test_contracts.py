from __future__ import annotations

from pathlib import Path

from challenges.interface import ObservationStatus, VulboxTarget

from jtu22.etcd_nested_rbac import flag_handler

ROOT = Path(__file__).parents[1]


def test_flag_plant_rotates_application_context_and_rejects_bad_handles(monkeypatch):
    commands: list[str] = []

    def execute(_host: str, command: str) -> tuple[int, str]:
        commands.append(command)
        return 0, ""

    monkeypatch.setattr(flag_handler.secrets, "token_hex", lambda _n: "a" * 20)
    target = VulboxTarget("prod", {}, {"exec_in_container": execute})
    handler = flag_handler.EtcdFlagHandler()
    handle = handler.plant_one(target, "FLAG{rotating}")

    assert handle == (
        "/services/production/aaaaaaaaaaaaaaaaaaaa/"
        "credentials/database-password"
    )
    assert handler.flag_id(handle) == handle
    assert "FLAG{rotating}" not in commands[0]
    assert commands[0].startswith(
        "/arena/store.py replace-prefix /services/production/ "
    )
    assert handler.flag_id("/services/operations/current-flag") is None
    assert handler.retrieve(target, "not/a/generated/key").status is ObservationStatus.ERROR


def test_image_provenance_and_restart_order_are_explicit():
    dockerfile = (ROOT / "image" / "Dockerfile").read_text()
    restart = (ROOT / "image" / "restart.sh").read_text()

    assert "c22bcad7820f81ff1c143d87e7b7e8724c637f71" in dockerfile
    assert "@sha256:ab3d6955bbc813a0f3fdf220c1d817dd89c0b3f283777db8ece4a32fe7858edd" in dockerfile
    assert "test \"$(git rev-parse HEAD)\" = \"${ETCD_COMMIT}\"" in dockerfile
    assert "GOPROXY=off" in restart and "./build" in restart
    assert restart.index("./build") < restart.index("kill \"$old_pid\"")
    assert restart.index("kill -0 \"$old_pid\"") < restart.index("install -o root")
    assert restart.index("install -o root") < restart.index("/arena/start.sh")
    assert "old process did not exit" in restart
    assert "etcd-restart: compile ok" in restart
    assert "etcd-restart: process started" in restart
    assert "etcd-restart: service ready" in restart


def test_flag_store_replace_prefix_removes_stale_records_before_put():
    store = (ROOT / "image" / "store.py").read_text()
    assert 'result = _command("del", prefix, "--prefix")' in store
    assert 'result = _command("put", replacement_key, value)' in store
