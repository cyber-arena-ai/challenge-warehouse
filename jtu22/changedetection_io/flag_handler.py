"""Plant one rotating flag as a private local operator report.

The changedetection.io process can read this report, but the HTTP service never
serves it directly. Recovering it remotely therefore proves host-file read
capability through the application's XPath watch processor.
"""

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

REPORT_DIR = "/var/lib/changedetection/private/reports"
HANDLE_RE = re.compile(
    rf"host\.file:({re.escape(REPORT_DIR)}/[a-f0-9]{{20}}-operator-report\.txt)"
)


class ChangedetectionIoFlagHandler(SingleFlagHandler):
    @property
    def name(self) -> str:
        return "changedetection-io-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ()

    def plant_one(self, target: VulboxTarget, flag: str) -> str:
        exec_in = target.meta["exec_in_container"]
        path = f"{REPORT_DIR}/{secrets.token_hex(10)}-operator-report.txt"
        encoded = base64.urlsafe_b64encode(flag.encode()).decode()
        rc, output = exec_in(
            target.host,
            f"/arena/flag_store.py plant {shlex.quote(path)} {shlex.quote(encoded)}",
        )
        if rc != 0:
            raise RuntimeError(
                "changedetection.io flag plant failed: "
                f"rc={rc}, out={(output or '')[-300:]!r}"
            )
        return f"host.file:{path}"

    def retrieve(
        self,
        target: VulboxTarget,
        handle: str,
        expected: str | None = None,
    ) -> FlagObservation:
        match = HANDLE_RE.fullmatch(handle)
        if match is None:
            return FlagObservation(ObservationStatus.ERROR, detail="bad handle")
        return exec_read_observe(
            target,
            f"/arena/flag_store.py retrieve {shlex.quote(match.group(1))}",
            expected,
            read_error_status=ObservationStatus.NOT_FOUND,
        )

    def flag_id(self, handle: str) -> str | None:
        """Surface the report path as the round's public attack locator."""
        match = HANDLE_RE.fullmatch(handle)
        return match.group(1) if match else None
