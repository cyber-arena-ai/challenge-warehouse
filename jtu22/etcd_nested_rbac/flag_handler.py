"""Plant the rotating flag as a protected etcd configuration secret."""

from __future__ import annotations

import base64
import re
import secrets
import shlex

from challenges.interface import (
    FlagObservation,
    ObservationStatus,
    SingleFlagHandler,
    VulboxTarget,
    exec_read_observe,
)

FLAG_KEY_RE = re.compile(
    r"/services/production/[a-f0-9]{20}/credentials/database-password"
)
FLAG_PREFIX = "/services/production/"


class EtcdFlagHandler(SingleFlagHandler):
    @property
    def name(self) -> str:
        return "etcd-nested-rbac-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ()

    def plant_one(self, target: VulboxTarget, flag: str) -> str:
        key = (
            f"{FLAG_PREFIX}{secrets.token_hex(10)}"
            "/credentials/database-password"
        )
        encoded = base64.urlsafe_b64encode(flag.encode()).decode()
        rc, output = target.meta["exec_in_container"](
            target.host,
            f"/arena/store.py replace-prefix {shlex.quote(FLAG_PREFIX)} "
            f"{shlex.quote(key)} {shlex.quote(encoded)}",
        )
        if rc != 0:
            raise RuntimeError(
                f"etcd flag plant failed: rc={rc}, out={(output or '')[-300:]!r}"
            )
        return key

    def retrieve(
        self,
        target: VulboxTarget,
        handle: str,
        expected: str | None = None,
    ) -> FlagObservation:
        if FLAG_KEY_RE.fullmatch(handle) is None:
            return FlagObservation(ObservationStatus.ERROR, detail="bad handle")
        return exec_read_observe(
            target,
            f"/arena/store.py retrieve {shlex.quote(handle)}",
            expected,
            read_error_status=ObservationStatus.NOT_FOUND,
        )

    def flag_id(self, handle: str) -> str | None:
        return handle if FLAG_KEY_RE.fullmatch(handle) else None
