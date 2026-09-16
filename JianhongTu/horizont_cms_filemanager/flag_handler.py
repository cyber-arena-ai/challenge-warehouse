"""Baseline Editor provisioning and rotating command-execution proof."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import shlex
from collections.abc import Mapping

from challenges.interface import (
    BaselinePrincipal,
    FlagObservation,
    ObservationStatus,
    SingleFlagHandler,
    VulboxTarget,
    exec_read_observe,
)

from ._client import ensure_editor, file_manager
from .cohort import COHORT_PATH, format_identity, seal_issued_cohort


ADMIN_USERNAME = "arena_admin"
ADMIN_PASSWORD_PATH = "/var/lib/horizont/admin-password"
PROOF_DIR = "/var/lib/horizont/proofs"
PLACEMENT_DIR = "/var/lib/horizont/placements"
ISSUED_HISTORY_PATH = "/var/lib/horizont/placement-history"
INITIALIZED_PATH = "/var/lib/horizont/.placement-initialized"
PROOF_HELPER = "/usr/local/bin/horizont-proof"
_LOCATOR_RE = re.compile(r"[a-f0-9]{24}")


def _identity(seed: str) -> tuple[str, str]:
    digest = hashlib.sha256(("horizont-editor:" + seed).encode()).hexdigest()
    return format_identity(digest)


def _round_context(round_context_seed: str) -> tuple[str, str]:
    if not isinstance(round_context_seed, str) or not re.fullmatch(
        r"[0-9a-f]{64}", round_context_seed
    ):
        raise ValueError("round context seed is unavailable")
    key = bytes.fromhex(round_context_seed)
    placement = hmac.new(
        key,
        b"horizont-cms-filemanager:default:placement-cache:v1",
        hashlib.sha256,
    ).hexdigest()
    locator = hmac.new(
        key,
        b"horizont-cms-filemanager:default:execute-locator:v1",
        hashlib.sha256,
    ).hexdigest()[:24]
    return placement, locator


class HorizontCmsExecuteFlagHandler(SingleFlagHandler):
    @property
    def name(self) -> str:
        return "horizont-cms-filemanager-execute-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def plant_one(self, target: VulboxTarget, value: str) -> str:
        placement_key, candidate_locator = _round_context(
            target.meta.get("round_context_seed", "")
        )
        encoded = base64.b64encode(value.encode()).decode()
        command = (
            "bash -ceu "
            + shlex.quote(
                f"""
install -d -o root -g root -m 0700 {PROOF_DIR} {PLACEMENT_DIR}
placement={PLACEMENT_DIR}/$1
candidate=$2
history={ISSUED_HISTORY_PATH}
initialized={INITIALIZED_PATH}
if [ ! -e "$history" ]; then
    [ ! -e "$initialized" ] && [ ! -L "$initialized" ] || exit 35
    tmp="$history.$$.new"
    trap 'rm -f "$tmp"' EXIT
    : > "$tmp"
    chown root:root "$tmp"
    chmod 0600 "$tmp"
    ln "$tmp" "$history" 2>/dev/null || true
    rm -f "$tmp"
    trap - EXIT
fi
[ -f "$history" ] && [ ! -L "$history" ] || exit 35
[ "$(stat -c '%u:%g:%a' "$history")" = "0:0:600" ] || exit 35
if [ ! -e "$initialized" ]; then
    [ ! -L "$initialized" ] && [ ! -s "$history" ] || exit 36
else
    [ -f "$initialized" ] && [ ! -L "$initialized" ] || exit 36
    [ "$(stat -c '%u:%g:%a' "$initialized")" = "0:0:600" ] || exit 36
fi
known=0
grep -Fqx "$1" "$history" && known=1
locator=''
if [ -e "$placement" ]; then
    [ -f "$placement" ] && [ ! -L "$placement" ] || exit 31
    locator="$(cat "$placement")"
    [ "$locator" = "$candidate" ] || exit 39
else
    locator="$candidate"
    if [ "$known" -eq 1 ]; then
        [ -f "{PROOF_DIR}/$locator" ] && [ ! -L "{PROOF_DIR}/$locator" ] || exit 37
    fi
    tmp="$placement.$$"
    printf '%s\n' "$locator" > "$tmp"
    chown root:root "$tmp"
    chmod 0600 "$tmp"
    if ! ln "$tmp" "$placement" 2>/dev/null; then
        [ -f "$placement" ] && [ ! -L "$placement" ] || exit 32
        locator="$(cat "$placement")"
    fi
    rm -f "$tmp"
fi
case "$locator" in
    *[!0-9a-f]*|'') exit 33 ;;
esac
[ "${{#locator}}" -eq 24 ] || exit 34
proof={PROOF_DIR}/$locator
tmp="$proof.$$"
printf %s "$3" | base64 -d > "$tmp"
chown root:root "$tmp"
chmod 0400 "$tmp"
mv -f "$tmp" "$proof"
find {PROOF_DIR} -mindepth 1 -maxdepth 1 -type f ! -name "$locator" -delete
if [ ! -e "$initialized" ]; then
    tmp="$initialized.$$.new"
    trap 'rm -f "$tmp"' EXIT
    : > "$tmp"
    chown root:root "$tmp"
    chmod 0600 "$tmp"
    ln "$tmp" "$initialized" 2>/dev/null || true
    rm -f "$tmp"
    trap - EXIT
fi
[ -f "$initialized" ] && [ ! -L "$initialized" ] || exit 38
[ "$(stat -c '%u:%g:%a' "$initialized")" = "0:0:600" ] || exit 38
if [ "$known" -eq 0 ]; then
    tmp="$history.$$.next"
    {{ tail -n 63 "$history"; printf '%s\n' "$1"; }} > "$tmp"
    chown root:root "$tmp"
    chmod 0600 "$tmp"
    mv -f "$tmp" "$history"
fi
find {PLACEMENT_DIR} -mindepth 1 -maxdepth 1 -type f ! -name "$1" -delete
printf %s "$locator"
"""
            )
            + " -- "
            + " ".join(
                shlex.quote(value)
                for value in (placement_key, candidate_locator, encoded)
            )
        )
        rc, output = target.meta["exec_in_container"](target.host, command)
        locator = (output or "").strip()
        if rc != 0 or not _LOCATOR_RE.fullmatch(locator):
            raise RuntimeError("HorizontCMS execution-proof plant failed")
        return locator

    def retrieve(
        self, target: VulboxTarget, handle: str, expected: str | None = None
    ) -> FlagObservation:
        if not _LOCATOR_RE.fullmatch(handle):
            return FlagObservation(ObservationStatus.ERROR, detail="invalid locator")
        return exec_read_observe(
            target,
            f"runuser -u www-data -- {PROOF_HELPER} {handle}",
            expected,
        )

    def flag_id(self, handle: str) -> str | None:
        if not _LOCATOR_RE.fullmatch(handle):
            return None
        return f"{PROOF_HELPER} {handle}"

    def _admin_password(self, target: VulboxTarget) -> str:
        rc, output = target.meta["exec_in_container"](
            target.host, f"cat {ADMIN_PASSWORD_PATH}"
        )
        password = (output or "").strip()
        if rc != 0 or not password:
            raise RuntimeError("HorizontCMS bootstrap administrator is unavailable")
        return password

    def provision_principals(
        self, target: VulboxTarget, seeds: Mapping[str, str]
    ) -> Mapping[str, BaselinePrincipal]:
        base_url = f"http://{target.host}:{target.ports['service']}"
        admin_password = self._admin_password(target)
        assignments = [(*_identity(seed), attacker) for attacker, seed in seeds.items()]
        issued: dict[str, BaselinePrincipal] = {}
        cohort: list[tuple[str, str]] = []
        for username, password, attacker in sorted(assignments):
            session = ensure_editor(
                base_url,
                ADMIN_USERNAME,
                admin_password,
                username,
                password,
                f"Editor {username[-6:]}",
            )
            file_manager(session)
            cohort.append((username, password))
            issued[attacker] = BaselinePrincipal(
                principal_id=username,
                credentials={"username": username, "password": password},
            )
        self._seal_cohort(target, cohort)
        return issued

    @staticmethod
    def _seal_cohort(target: VulboxTarget, accounts: list[tuple[str, str]]) -> None:
        sealed = seal_issued_cohort(accounts)
        encoded = base64.b64encode(sealed.encode()).decode()
        staged = f"{COHORT_PATH}.new"
        command = (
            "sh -ceu "
            + shlex.quote(
                f"rm -f {staged}; "
                f"trap 'rm -f {staged}' EXIT; "
                f"printf %s {shlex.quote(encoded)} | base64 -d > {staged}; "
                f"chown root:root {staged}; chmod 0400 {staged}; "
                f"mv -f {staged} {COHORT_PATH}; trap - EXIT"
            )
        )
        rc, _ = target.meta["exec_in_container"](target.host, command)
        if rc != 0:
            raise RuntimeError("HorizontCMS issued cohort seal failed")
