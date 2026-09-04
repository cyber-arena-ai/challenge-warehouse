from __future__ import annotations

from challenges.interface import ObservationStatus, VulboxTarget

from jt.caddy_nextcloud_sso._ids import STORE_GUARDED_FILE, pack_handle
from jt.caddy_nextcloud_sso.flag_handler import CaddyNextcloudFlagHandler


def target(exec_in_container) -> VulboxTarget:
    return VulboxTarget(
        host="prod", ports={"service": 8080},
        meta={"exec_in_container": exec_in_container},
    )


def test_retrieve_never_raises_when_exec_bridge_raises():
    def raised(_host: str, _command: str):
        raise RuntimeError("transport failed")

    handle = pack_handle({
        "store": STORE_GUARDED_FILE,
        "target": "Guarded/" + "a" * 24 + ".txt",
        "flag": "FLAG{expected}",
    })
    result = CaddyNextcloudFlagHandler().retrieve(target(raised), handle)
    assert result.status is ObservationStatus.ERROR
    assert result.value is None


def test_retrieve_rejects_malformed_handle_without_exec():
    called = False

    def unexpected(_host: str, _command: str):
        nonlocal called
        called = True
        return 0, ""

    result = CaddyNextcloudFlagHandler().retrieve(target(unexpected), "not-a-handle")
    assert result.status is ObservationStatus.ERROR
    assert called is False
