"""Per-attacker XMPP identities and rotating service-execution proofs."""

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

from ._health_identity import (
    ISSUED_COHORT_STATE,
    checker_principal_pools,
    seal_issued_cohort,
)
from .challenge import FACILITY_CLIENT


PROOF_DIR = "/var/lib/openfire-arena/proofs"
PROOF_HELPER = "/usr/local/bin/openfire-proof"
PLANT_CACHE = "/var/lib/openfire-arena/plant-state"
_LOCATOR_RE = re.compile(r"[a-f0-9]{24}")


def _identity(seed: str) -> tuple[str, str]:
    username = "user" + hashlib.sha256(("xmpp-user:" + seed).encode()).hexdigest()[:16]
    password = "Of9!" + hashlib.sha256(("xmpp-password:" + seed).encode()).hexdigest()[:28]
    return username, password


def _round_context(round_context_seed: str) -> tuple[str, str]:
    if not isinstance(round_context_seed, str) or not re.fullmatch(
        r"[0-9a-f]{64}", round_context_seed
    ):
        raise ValueError("round context seed is unavailable")
    key = bytes.fromhex(round_context_seed)
    cache_key = hmac.new(
        key,
        b"openfire-server:default:placement-cache:v1",
        hashlib.sha256,
    ).hexdigest()
    locator = hmac.new(
        key,
        b"openfire-server:default:execute-locator:v1",
        hashlib.sha256,
    ).hexdigest()[:24]
    return cache_key, locator


class OpenfireExecuteFlagHandler(SingleFlagHandler):
    @property
    def name(self) -> str:
        return "openfire-server-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def plant_one(self, target: VulboxTarget, value: str) -> str:
        cache_key, candidate = _round_context(
            target.meta.get("round_context_seed", "")
        )
        encoded = base64.b64encode(value.encode()).decode()
        rc, output = target.meta["exec_in_container"](
            target.host,
            f"install -d -o root -g root -m 0700 {PLANT_CACHE}; "
            f"cache={PLANT_CACHE}/{cache_key}; "
            f"initialized={PLANT_CACHE}/.initialized; "
            f"candidate={candidate}; "
            'if [ ! -e "$cache" ]; then '
            "proof_count=0; candidate_present=0; "
            f"if [ -d {PROOF_DIR} ]; then "
            f"for proof in {PROOF_DIR}/*; do "
            '[ -f "$proof" ] || continue; '
            'proof_count=$((proof_count + 1)); '
            '[ "${proof##*/}" != "$candidate" ] || candidate_present=1; '
            "done; fi; "
            'if [ "$candidate_present" -eq 1 ] && [ "$proof_count" -eq 1 ]; then :; '
            'elif [ "$candidate_present" -eq 0 ] && [ "$proof_count" -eq 1 ]; then :; '
            'elif [ "$candidate_present" -eq 0 ] && [ "$proof_count" -eq 0 ] '
            '&& [ ! -e "$initialized" ]; then :; '
            "else exit 47; fi; "
            'case "$candidate" in *[!0-9a-f]*|"") exit 48 ;; esac; '
            '[ "${#candidate}" -eq 24 ] || exit 48; '
            'tmp="$cache.$$.new"; trap \'rm -f "$tmp"\' EXIT; '
            'printf %s "$candidate" > "$tmp"; '
            'chown root:root "$tmp"; chmod 0600 "$tmp"; '
            'ln "$tmp" "$cache" 2>/dev/null || true; '
            'rm -f "$tmp"; trap - EXIT; '
            "fi; "
            'test -s "$cache" || exit 45; '
            '[ "$(cat "$cache")" = "$candidate" ] || exit 48; '
            'touch "$initialized"; chown root:root "$initialized"; '
            'chmod 0600 "$initialized"; cat "$cache"',
        )
        if rc != 0:
            raise RuntimeError("Openfire execution target state is unreadable")
        locator = (output or "").strip()
        if not _LOCATOR_RE.fullmatch(locator):
            raise RuntimeError("Openfire execution target state is invalid")
        command = (
            f"install -d -o root -g openfire -m 0710 {PROOF_DIR} && "
            f"find {PROOF_DIR} -mindepth 1 -maxdepth 1 -type f -delete && "
            f"printf %s {shlex.quote(encoded)} | base64 -d > {PROOF_DIR}/{locator} && "
            f"chown root:root {PROOF_DIR}/{locator} && chmod 0400 {PROOF_DIR}/{locator} && "
            f"find {PLANT_CACHE} -mindepth 1 -maxdepth 1 -type f "
            f"! -name {shlex.quote(cache_key)} ! -name .initialized -delete"
        )
        rc, _ = target.meta["exec_in_container"](target.host, command)
        if rc != 0:
            raise RuntimeError("Openfire execution-proof plant failed")
        return locator

    def retrieve(
        self, target: VulboxTarget, handle: str, expected: str | None = None
    ) -> FlagObservation:
        if not _LOCATOR_RE.fullmatch(handle):
            return FlagObservation(ObservationStatus.ERROR, detail="invalid locator")
        return exec_read_observe(
            target,
            f"runuser -u openfire -- {PROOF_HELPER} {handle}",
            expected,
        )

    def flag_id(self, handle: str) -> str | None:
        return handle if _LOCATOR_RE.fullmatch(handle) else None

    def provision_principals(
        self, target: VulboxTarget, seeds: Mapping[str, str]
    ) -> Mapping[str, BaselinePrincipal]:
        pools = checker_principal_pools(target)
        principals: list[tuple[str, str, str, str | None]] = []
        principals.extend(
            (username, password, "administrator", None)
            for username, password in pools["administrator"]
        )
        principals.extend(
            (username, password, "ordinary", None)
            for username, password in pools["ordinary"]
        )
        for attacker, seed in seeds.items():
            username, password = _identity(seed)
            principals.append((username, password, "ordinary", attacker))
        usernames = [username for username, *_ in principals]
        if len(usernames) != len(set(usernames)):
            raise RuntimeError("Openfire principal identity collision")

        issued: dict[str, BaselinePrincipal] = {}
        for username, password, role, attacker in sorted(
            principals, key=lambda principal: principal[0]
        ):
            command = " ".join(
                shlex.quote(part)
                for part in (
                    FACILITY_CLIENT,
                    "ensure-principal",
                    username,
                    password,
                    role,
                )
            )
            rc, output = target.meta["exec_in_container"](target.host, command)
            if rc != 0:
                raise RuntimeError(
                    "Openfire principal setup failed: "
                    f"{(output or f'rc={rc}')[-300:]}"
                )
            if attacker is not None:
                issued[attacker] = BaselinePrincipal(
                    principal_id=username,
                    credentials={"username": username, "password": password},
                )

        sealed = seal_issued_cohort(
            (principal.credentials["username"], principal.credentials["password"])
            for principal in issued.values()
        )
        staged = f"{ISSUED_COHORT_STATE}.new"
        rc, _ = target.meta["exec_in_container"](
            target.host,
            f"printf %s {shlex.quote(sealed)} > {staged} && "
            f"chown root:root {staged} && chmod 0400 {staged} && "
            f"mv -f {staged} {ISSUED_COHORT_STATE}",
        )
        if rc != 0:
            raise RuntimeError("Openfire issued principal cohort could not be sealed")
        return issued
