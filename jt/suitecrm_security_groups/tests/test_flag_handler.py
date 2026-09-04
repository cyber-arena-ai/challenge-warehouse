from __future__ import annotations

from challenges.interface import ObservationStatus, VulboxTarget

from jt.suitecrm_security_groups._ids import STORE_PRIVATE_NOTE, pack_handle
from jt.suitecrm_security_groups.flag_handler import SuiteCrmFlagHandler


def test_retrieve_converts_exec_failure_to_error() -> None:
    def raising_exec(_host: str, _command: str) -> tuple[int, str]:
        raise OSError("container unavailable")

    handle = pack_handle({
        "store": STORE_PRIVATE_NOTE,
        "target": "12345678-1234-1234-1234-123456789abc",
        "flag": "FLAG{EXPECTED}",
    })
    target = VulboxTarget(
        "prod",
        {"service": 8080},
        {"exec_in_container": raising_exec},
    )

    observation = SuiteCrmFlagHandler().retrieve(target, handle)

    assert observation.status is ObservationStatus.ERROR
    assert observation.detail == "guarded read exec raised"
