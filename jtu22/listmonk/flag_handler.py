"""Plant two rotating Listmonk capability flags out of band.

``secret.credential.read`` is both the first flag and the live secret for the
restricted S3-compatible account named in Listmonk's protected settings.
``storage.private_object.read`` is stored in the private object that account may
read.  Recovering the second flag therefore proves that the leaked credential
was used, rather than merely disclosed.
"""

from __future__ import annotations

import base64
import shlex
from collections.abc import Mapping

from challenges.interface import (
    Flag,
    FlagHandler,
    FlagObservation,
    ObservationStatus,
    VulboxTarget,
    exec_read_observe,
)

CREDENTIAL_STORE = "secret.credential.read"
OBJECT_STORE = "storage.private_object.read"
CREDENTIAL_HANDLE = "settings:upload.s3.aws_secret_access_key"
OBJECT_HANDLE = "s3:arena-media-prod/campaign-archives/quarterly-subscriber-audit.txt"


def _encoded(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode()).decode()


class ListmonkFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "listmonk-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        # Plant/retrieve use the privileged exec bridge, not public ports.
        return ()

    def plant(
        self, target: VulboxTarget, flags: Mapping[str, Flag]
    ) -> Mapping[str, str]:
        exec_in = target.meta["exec_in_container"]
        handles: dict[str, str] = {}
        commands = {
            CREDENTIAL_STORE: (
                "plant-credential",
                CREDENTIAL_HANDLE,
            ),
            OBJECT_STORE: ("plant-object", OBJECT_HANDLE),
        }
        for store, flag in flags.items():
            if store not in commands:
                raise RuntimeError(f"unknown Listmonk flag store: {store}")
            action, handle = commands[store]
            rc, out = exec_in(
                target.host,
                f"/arena/flag_store.py {action} {shlex.quote(_encoded(flag.value))}",
            )
            if rc != 0:
                raise RuntimeError(
                    f"Listmonk {store} plant failed on {target.host}: "
                    f"rc={rc}, out={out[-400:]!r}"
                )
            handles[store] = handle
        return handles

    def retrieve(
        self,
        target: VulboxTarget,
        handle: str,
        expected: str | None = None,
    ) -> FlagObservation:
        commands = {
            CREDENTIAL_HANDLE: "/arena/flag_store.py retrieve-credential",
            OBJECT_HANDLE: "/arena/flag_store.py retrieve-object",
        }
        command = commands.get(handle)
        if command is None:
            return FlagObservation(ObservationStatus.ERROR, detail="bad handle")
        return exec_read_observe(
            target,
            command,
            expected,
            read_error_status=ObservationStatus.ERROR,
        )
