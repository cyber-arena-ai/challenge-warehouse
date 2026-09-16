"""Rotating service-context proof and normal-User provisioning."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import shlex
import time
from collections.abc import Mapping

from challenges.interface import (
    BaselinePrincipal,
    Flag,
    FlagHandler,
    FlagObservation,
    ObservationStatus,
    VulboxTarget,
    exec_read_observe,
)

from . import _http
from .config import COHORT_FILE, issued_cohort, round_context

STORE = "command_execution"
PROOF_OPERATION = "/usr/local/bin/nv-proof"
PROOF_PREFIX = PROOF_OPERATION + " "
PROOF_DIR = "/var/lib/navigate-proof"
CONTEXT_DIR = f"{PROOF_DIR}/contexts"
ISSUED_HISTORY = f"{PROOF_DIR}/issued.history"
CURRENT_CONTEXT = f"{PROOF_DIR}/current"
INITIALIZED_MARKER = "/var/lib/.navigate-proof.initialized"
_TARGET_RE = re.compile(r"^[0-9a-f]{24}$")
_RECORD_RE = re.compile(r"^([0-9a-f]{64}) ([0-9a-f]{24}) ([0-9a-f]{64})$")
_CONTEXT_DELIMITER = "--navigate-context--"


class NavigateFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "navigate-cms-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def plant(self, target: VulboxTarget,
              flags: Mapping[str, Flag]) -> Mapping[str, str]:
        if set(flags) != {STORE}:
            raise ValueError(f"expected only {STORE!r}")
        flag = flags[STORE].value
        seed = target.meta.get("round_context_seed")
        key, target_id, mac = round_context(seed)
        current = self._placement_context(target, key, target_id, mac)
        if current is not None and current != target_id:
            raise RuntimeError("Navigate placement state is irreconstructible")
        exec_in = target.meta["exec_in_container"]
        token = f"{PROOF_DIR}/{target_id}.token"
        context = f"{CONTEXT_DIR}/{key}"
        staged_history = f"{PROOF_DIR}/.issued.history.new"
        staged_token = f"{PROOF_DIR}/.{key}.token.new"
        staged_current = f"{PROOF_DIR}/.current.new"
        encoded_flag = base64.b64encode(flag.encode()).decode()
        state = "\n".join(
            (key, target_id, mac, "")
        )
        encoded_state = base64.b64encode(state.encode()).decode()
        history_update = ""
        if current is None:
            history_update = (
                f"cp {ISSUED_HISTORY} {staged_history}; "
                f"printf '%s %s %s\\n' {shlex.quote(key)} "
                f"{shlex.quote(target_id)} "
                f"{shlex.quote(mac)} "
                f">> {staged_history}; "
                f"chown root:root {staged_history}; "
                f"chmod 0600 {staged_history}; "
                f"mv -f {staged_history} {ISSUED_HISTORY}; "
            )
        cmd = (
            "sh -ceu "
            + shlex.quote(
                f"rm -f {context}.new {staged_history} "
                f"{staged_token} {staged_current}; "
                f"printf %s {shlex.quote(encoded_state)} | base64 -d "
                f"> {context}.new; "
                f"chown root:root {context}.new; "
                f"chmod 0600 {context}.new; "
                + history_update
                + f"mv -f {context}.new {context}; "
                f"printf %s {shlex.quote(encoded_flag)} | base64 -d "
                f"> {staged_token}; "
                f"printf '%s\\n' {shlex.quote(target_id)} > {staged_current}; "
                f"chown root:root {staged_token}; "
                f"chown root:root {staged_current}; "
                f"chmod 0400 {staged_token}; "
                f"chmod 0400 {staged_current}; "
                f"mv -f {staged_token} {shlex.quote(token)}; "
                f"mv -f {staged_current} {CURRENT_CONTEXT}; "
                f"find {PROOF_DIR} -maxdepth 1 -type f -name '*.token' "
                f"! -name '{target_id}.token' -delete"
            )
        )
        rc, _ = exec_in(target.host, cmd)
        if rc != 0:
            raise RuntimeError("Navigate command-execution proof plant failed")
        return {STORE: PROOF_PREFIX + target_id}

    @staticmethod
    def _placement_context(
        target: VulboxTarget, key: str, expected_target: str, expected_mac: str,
    ) -> str | None:
        command = (
            f"test -f {INITIALIZED_MARKER} || exit 45; "
            f"test ! -L {INITIALIZED_MARKER} || exit 45; "
            f"[ \"$(stat -c '%u:%g:%a' {INITIALIZED_MARKER})\" "
            f"= '0:0:400' ] || exit 45; "
            f"for directory in {PROOF_DIR} {CONTEXT_DIR}; do "
            "test -d \"$directory\" || exit 45; "
            "test ! -L \"$directory\" || exit 45; "
            "[ \"$(stat -c '%u:%g:%a' \"$directory\")\" = '0:0:700' ] "
            "|| exit 45; done; "
            f"test -f {ISSUED_HISTORY} || exit 45; "
            f"test ! -L {ISSUED_HISTORY} || exit 45; "
            f"[ \"$(stat -c '%u:%g:%a' {ISSUED_HISTORY})\" = '0:0:600' ] "
            "|| exit 45; "
            f"cat {ISSUED_HISTORY}; "
            f"printf '%s\\n' {_CONTEXT_DELIMITER}; "
            f"for name in $(find {CONTEXT_DIR} -mindepth 1 -maxdepth 1 "
            "-printf '%f\\n' | sort); do "
            "base=${name%.new}; "
            "case \"$name\" in \"$base\"|\"$base.new\") ;; *) exit 45;; esac; "
            "case \"$base\" in *[!0-9a-f]*|'') exit 45;; esac; "
            "[ \"${#base}\" -eq 64 ] || exit 45; "
            f"saved={CONTEXT_DIR}/$name; "
            "test -f \"$saved\" || exit 45; "
            "test ! -L \"$saved\" || exit 45; "
            "test -s \"$saved\" || exit 45; "
            "[ \"$(wc -l < \"$saved\")\" -eq 3 ] || exit 45; "
            "[ \"$(stat -c '%u:%g:%a' \"$saved\")\" = '0:0:600' ] "
            "|| exit 45; "
            "[ \"$(sed -n '1p' \"$saved\")\" = \"$base\" ] || exit 45; "
            "printf '%s\\n' \"$name\"; cat \"$saved\"; done"
        )
        exec_in = target.meta["exec_in_container"]
        rc, output = exec_in(target.host, command)
        if rc != 0:
            raise RuntimeError("Navigate placement-state integrity failure")
        lines = (output or "").splitlines()
        if lines.count(_CONTEXT_DELIMITER) != 1:
            raise RuntimeError("Navigate placement state is irreconstructible")
        split = lines.index(_CONTEXT_DELIMITER)
        records: dict[str, tuple[str, str]] = {}
        targets: set[str] = set()
        for line in lines[:split]:
            match = _RECORD_RE.fullmatch(line)
            if match is None:
                raise RuntimeError("Navigate placement state is irreconstructible")
            record_key, target_id, mac = match.groups()
            if record_key in records or target_id in targets:
                raise RuntimeError("Navigate placement state is irreconstructible")
            records[record_key] = (target_id, mac)
            targets.add(target_id)

        context_lines = lines[split + 1:]
        if len(context_lines) % 4:
            raise RuntimeError("Navigate placement state is irreconstructible")
        contexts: dict[str, tuple[str, str]] = {}
        pending: dict[str, tuple[str, str]] = {}
        for offset in range(0, len(context_lines), 4):
            name, context_key, context_target, context_mac = context_lines[offset:offset + 4]
            is_pending = name.endswith(".new")
            if (
                not re.fullmatch(r"[0-9a-f]{64}", context_key)
                or not _TARGET_RE.fullmatch(context_target)
                or not re.fullmatch(r"[0-9a-f]{64}", context_mac)
                or name != context_key + (".new" if is_pending else "")
            ):
                raise RuntimeError("Navigate placement state is irreconstructible")
            candidate = context_target, context_mac
            collection = pending if is_pending else contexts
            if context_key in collection:
                raise RuntimeError("Navigate placement state is irreconstructible")
            collection[context_key] = candidate

        for context_key, candidate in contexts.items():
            if records.get(context_key) != candidate:
                raise RuntimeError("Navigate placement state is irreconstructible")
        for context_key, candidate in pending.items():
            recorded = records.get(context_key)
            if (
                (recorded is not None and recorded != candidate)
                or (context_key in contexts and contexts[context_key] != candidate)
                or (recorded is None and context_key != key)
                or (recorded is None and candidate[0] in targets)
            ):
                raise RuntimeError("Navigate placement state is irreconstructible")

        issued = records.get(key)
        recovered_pending = False
        if issued is None and key in pending:
            issued = pending[key]
            recovered_pending = True
        if issued is None:
            return None
        target_id, mac = issued
        if (
            not hmac.compare_digest(target_id, expected_target)
            or not hmac.compare_digest(mac, expected_mac)
        ):
            raise RuntimeError("Navigate placement state is irreconstructible")
        cached = contexts.get(key)
        if cached is not None and (
            not hmac.compare_digest(cached[0], target_id)
            or not hmac.compare_digest(cached[1], mac)
        ):
            raise RuntimeError("Navigate placement state is irreconstructible")

        reconciliation: list[str] = []
        if recovered_pending:
            staged_history = f"{PROOF_DIR}/.issued.history.reconcile"
            reconciliation.extend((
                f"cp {ISSUED_HISTORY} {staged_history}",
                f"printf '%s %s %s\\n' {shlex.quote(key)} "
                f"{shlex.quote(target_id)} {shlex.quote(mac)} >> {staged_history}",
                f"chown root:root {staged_history}",
                f"chmod 0600 {staged_history}",
                f"mv -f {staged_history} {ISSUED_HISTORY}",
            ))
        for context_key in sorted(pending):
            pending_path = f"{CONTEXT_DIR}/{context_key}.new"
            final_path = f"{CONTEXT_DIR}/{context_key}"
            if context_key in contexts:
                reconciliation.append(f"rm -f {pending_path}")
            else:
                reconciliation.append(f"mv -f {pending_path} {final_path}")
        if reconciliation:
            reconcile_rc, _ = exec_in(
                target.host, " && ".join(reconciliation))
            if reconcile_rc != 0:
                raise RuntimeError("Navigate placement-state reconciliation failed")
        return target_id

    def retrieve(self, target: VulboxTarget, handle: str,
                 expected: str | None = None) -> FlagObservation:
        if not handle.startswith(PROOF_PREFIX):
            return FlagObservation(ObservationStatus.ERROR, detail="invalid proof handle")
        target_id = handle[len(PROOF_PREFIX):]
        if not _TARGET_RE.fullmatch(target_id):
            return FlagObservation(ObservationStatus.ERROR, detail="invalid proof handle")
        if not expected:
            return FlagObservation(ObservationStatus.ERROR, detail="missing expected token")
        try:
            return exec_read_observe(
                target,
                "runuser -u www-data -- "
                f"{shlex.quote(PROOF_OPERATION)} {shlex.quote(target_id)}",
                expected,
            )
        except Exception:
            return FlagObservation(ObservationStatus.ERROR, detail="proof execution failed")

    def flag_id(self, handle: str) -> str | None:
        if not handle.startswith(PROOF_PREFIX):
            return None
        target_id = handle[len(PROOF_PREFIX):]
        return handle if _TARGET_RE.fullmatch(target_id) else None

    def provision_principals(
        self, target: VulboxTarget, seeds: Mapping[str, str],
    ) -> Mapping[str, BaselinePrincipal]:
        exec_in = target.meta["exec_in_container"]
        rc, raw = exec_in(target.host, "cat /run/navigate/admin.json")
        if rc != 0:
            raise RuntimeError("Navigate administration bootstrap unavailable")
        try:
            admin = json.loads(raw)
            admin_user = admin["username"]
            admin_password = admin["password"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise RuntimeError("Navigate administration bootstrap invalid") from exc

        base = f"http://{target.host}:{target.ports['service']}/navigate"
        deadline = time.monotonic() + 90
        while True:
            try:
                opener, _ = _http.login(base, admin_user, admin_password)
                break
            except (OSError, RuntimeError):
                if time.monotonic() >= deadline:
                    raise RuntimeError("Navigate supported administration unavailable")
                time.sleep(1)

        result: dict[str, BaselinePrincipal] = {}
        accounts: list[tuple[str, str]] = []
        for team_id, seed in sorted(seeds.items()):
            digest = hashlib.sha256(seed.encode()).hexdigest()
            username = "nv_" + digest[:20]
            password = "Nv!" + digest[20:52]
            accounts.append((username, password))
            result[team_id] = BaselinePrincipal(
                principal_id=username,
                credentials={"username": username, "password": password},
            )

        if len({username for username, _ in accounts}) != len(accounts):
            raise RuntimeError("Navigate principal identity collision")
        if len({password for _, password in accounts}) != len(accounts):
            raise RuntimeError("Navigate principal credential collision")
        for username, password in sorted(accounts):
            try:
                _http.create_user(opener, base, username, password)
                _http.login(base, username, password)
            except RuntimeError as exc:
                raise RuntimeError("normal User provisioning failed") from exc
        self._seal_cohort(target, accounts)
        return result

    @staticmethod
    def _seal_cohort(
        target: VulboxTarget, accounts: list[tuple[str, str]],
    ) -> None:
        """Record the issued cohort under the facility seal health verifies."""
        sealed = issued_cohort([list(account) for account in accounts])
        staged = f"{COHORT_FILE}.new"
        cmd = (
            "sh -ceu "
            + shlex.quote(
                f"rm -f {staged}; "
                f"printf %s {shlex.quote(base64.b64encode(sealed.encode()).decode())} "
                f"| base64 -d > {staged}; "
                f"chown root:root {staged}; "
                f"chmod 0400 {staged}; "
                f"mv -f {staged} {COHORT_FILE}"
            )
        )
        rc, _ = target.meta["exec_in_container"](target.host, cmd)
        if rc != 0:
            raise RuntimeError("Navigate issued cohort seal failed")
