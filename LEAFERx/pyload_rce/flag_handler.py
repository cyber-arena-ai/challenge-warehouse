"""Native restricted users and rotating pyLoad execution proofs."""

from __future__ import annotations

import base64
import json
import re
import shlex
from collections.abc import Mapping
from typing import Any

from challenges.interface import (
    Flag,
    FlagHandler,
    FlagObservation,
    ObservationStatus,
    VulboxTarget,
    exec_read_observe,
)

from ._ids import (
    STORE,
    derive,
    pack_handle,
    target_id,
    target_locator,
    unpack_handle,
)

PRIVATE_DIR = "/var/lib/pyload-arena"
PROOF_DIR = f"{PRIVATE_DIR}/proofs"
JOURNAL_PATH = f"{PRIVATE_DIR}/objective-journal.json"
ISSUED_PATH = f"{PRIVATE_DIR}/objective-issued"
ISSUED_VALUE = "pyload-command-objective-v1"
PROOF_HELPER = "/usr/local/bin/pyload-proof"
_CONTEXT_RE = re.compile(r"[0-9a-f]{64}")


def _empty_journal() -> dict[str, Any]:
    return {"v": 1, "current": None, "previous": None, "pending": None}


class PyloadFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "pyload-download-manager-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ()

    @staticmethod
    def _exec(target: VulboxTarget, command: str) -> str:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            raise RuntimeError("no facility exec bridge")
        rc, output = exec_in(target.host, command)
        if rc != 0:
            raise RuntimeError("private pyLoad state operation failed")
        return output or ""

    def _read_file_state(self, target: VulboxTarget, path: str) -> str:
        quoted = shlex.quote(path)
        return self._exec(
            target,
            f"if [ ! -e {quoted} ]; then printf missing; "
            f"elif [ -f {quoted} ]; then printf 'file\\n'; cat {quoted}; "
            "else printf invalid; fi",
        )

    @staticmethod
    def _generation(value: object) -> dict[str, str] | None:
        if value is None:
            return None
        if (
            not isinstance(value, dict)
            or set(value) != {"context", "proof", "target"}
            or not isinstance(value.get("context"), str)
            or _CONTEXT_RE.fullmatch(value["context"]) is None
            or not isinstance(value.get("proof"), str)
            or not value["proof"]
            or "\n" in value["proof"]
            or target_locator(value.get("target")) is None
        ):
            raise RuntimeError("objective journal is malformed")
        return value

    def _load_journal(self, target: VulboxTarget) -> dict[str, Any]:
        marker = self._read_file_state(target, ISSUED_PATH)
        if marker == "missing":
            issued = False
        elif marker == f"file\n{ISSUED_VALUE}\n":
            issued = True
        else:
            raise RuntimeError("objective issuance marker is malformed")

        state = self._read_file_state(target, JOURNAL_PATH)
        if state == "missing":
            if issued:
                raise RuntimeError("objective journal is missing after issuance")
            return _empty_journal()
        if not state.startswith("file\n"):
            raise RuntimeError("objective journal is malformed")
        try:
            journal = json.loads(state.removeprefix("file\n"))
        except json.JSONDecodeError as error:
            raise RuntimeError("objective journal is malformed") from error
        if (
            not isinstance(journal, dict)
            or set(journal) != {"v", "current", "previous", "pending"}
            or journal.get("v") != 1
        ):
            raise RuntimeError("objective journal is malformed")
        generations = {
            slot: self._generation(journal.get(slot))
            for slot in ("current", "previous", "pending")
        }
        if all(
            generation is None for generation in generations.values()
        ):
            raise RuntimeError("objective journal is malformed")
        if not issued and (
            generations["previous"] is not None
            or sum(
                generations[slot] is not None for slot in ("current", "pending")
            )
            != 1
        ):
            raise RuntimeError("objective journal is malformed")
        return journal

    def _write_private_json(
        self, target: VulboxTarget, path: str, value: Mapping[str, Any]
    ) -> None:
        raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
        encoded = base64.b64encode(raw).decode()
        temporary = shlex.quote(path + ".next")
        quoted = shlex.quote(path)
        self._exec(
            target,
            "set -eu; umask 077; "
            f"printf %s {shlex.quote(encoded)} | base64 -d > {temporary}; "
            f"chmod 0600 {temporary}; sync -f {temporary}; "
            f"mv -f {temporary} {quoted}; sync -f {shlex.quote(PRIVATE_DIR)}",
        )

    def _write_journal(self, target: VulboxTarget, journal: Mapping[str, Any]) -> None:
        self._write_private_json(target, JOURNAL_PATH, journal)

    def _mark_issued(self, target: VulboxTarget) -> None:
        temporary = shlex.quote(ISSUED_PATH + ".next")
        path = shlex.quote(ISSUED_PATH)
        self._exec(
            target,
            "set -eu; umask 077; "
            f"printf '%s\\n' {shlex.quote(ISSUED_VALUE)} > {temporary}; "
            f"chmod 0600 {temporary}; sync -f {temporary}; "
            f"mv -f {temporary} {path}; sync -f {shlex.quote(PRIVATE_DIR)}",
        )

    def _write_proof(self, target: VulboxTarget, target_name: str, proof: str) -> None:
        locator = target_locator(target_name)
        if locator is None:
            raise RuntimeError("invalid execution target")
        encoded = base64.b64encode(proof.encode()).decode()
        path = f"{PROOF_DIR}/{locator}"
        temporary = f"{PROOF_DIR}/.{locator}.next"
        self._exec(
            target,
            "set -eu; install -d -o root -g pyload -m 0710 "
            f"{shlex.quote(PROOF_DIR)}; umask 077; "
            f"printf %s {shlex.quote(encoded)} | base64 -d > {shlex.quote(temporary)}; "
            f"chown root:root {shlex.quote(temporary)}; chmod 0400 {shlex.quote(temporary)}; "
            f"sync -f {shlex.quote(temporary)}; "
            f"mv -f {shlex.quote(temporary)} {shlex.quote(path)}; "
            f"sync -f {shlex.quote(PROOF_DIR)}",
        )

    def _delete_proof(self, target: VulboxTarget, target_name: str) -> None:
        locator = target_locator(target_name)
        if locator is None:
            raise RuntimeError("invalid execution target")
        self._exec(
            target,
            f"rm -f {shlex.quote(f'{PROOF_DIR}/{locator}')} && "
            f"sync -f {shlex.quote(PROOF_DIR)}",
        )

    def plant(
        self, target: VulboxTarget, flags: Mapping[str, Flag]
    ) -> Mapping[str, str]:
        if set(flags) != {STORE}:
            raise ValueError(f"expected exactly the {STORE!r} store")
        proof = flags[STORE].value
        if (
            not isinstance(proof, str)
            or not proof
            or "\n" in proof
            or len(proof) > 512
        ):
            raise ValueError("invalid execution proof shape")
        seed = target.meta.get("round_context_seed")
        if not isinstance(seed, str):
            raise ValueError("round_context_seed is required")
        wanted_target = target_id(seed)
        context = derive(seed, "command:generation").hex()
        wanted = {"context": context, "proof": proof, "target": wanted_target}
        journal = self._load_journal(target)
        current = self._generation(journal.get("current"))
        pending = self._generation(journal.get("pending"))

        same_context = current is not None and current["context"] == context
        if same_context and current != wanted:
            raise RuntimeError("round context was reused with different proof state")

        previous = self._generation(journal.get("previous"))
        if previous is not None and not same_context:
            self._delete_proof(target, previous["target"])
            journal["previous"] = None
            self._write_journal(target, journal)

        if pending is not None and pending != wanted:
            self._delete_proof(target, pending["target"])
            journal["pending"] = wanted if current is None else None
            self._write_journal(target, journal)
            pending = journal["pending"]

        if same_context:
            if pending is not None:
                raise RuntimeError("objective journal is malformed")
            self._write_proof(target, wanted_target, proof)
            observed = self.retrieve(target, pack_handle(wanted_target, proof), proof)
            if observed.status is not ObservationStatus.PRESENT:
                raise RuntimeError(
                    f"current execution target verification failed: {observed.status.value}"
                )
            self._mark_issued(target)
            return {STORE: pack_handle(wanted_target, proof)}

        if pending is None:
            journal["pending"] = wanted
            self._write_journal(target, journal)
        self._write_proof(target, wanted_target, proof)
        observed = self.retrieve(target, pack_handle(wanted_target, proof), proof)
        if observed.status is not ObservationStatus.PRESENT:
            raise RuntimeError(
                f"staged execution target verification failed: {observed.status.value}"
            )
        self._write_journal(
            target,
            {"v": 1, "current": wanted, "previous": current, "pending": None},
        )
        self._mark_issued(target)
        return {STORE: pack_handle(wanted_target, proof)}

    def retrieve(
        self, target: VulboxTarget, handle: str, expected: str | None = None
    ) -> FlagObservation:
        value = unpack_handle(handle)
        if value is None:
            return FlagObservation(ObservationStatus.ERROR, detail="invalid handle")
        locator = target_locator(value["target"])
        if locator is None:
            return FlagObservation(ObservationStatus.ERROR, detail="invalid target")
        wanted = expected if expected is not None else value["proof"]
        if not isinstance(wanted, str) or not wanted:
            return FlagObservation(
                ObservationStatus.ERROR, detail="invalid expected value"
            )
        return exec_read_observe(
            target,
            f"runuser -u pyload -- {PROOF_HELPER} {shlex.quote(locator)}",
            wanted,
        )

    def flag_id(self, handle: str) -> str | None:
        value = unpack_handle(handle)
        return value["target"] if value is not None else None
