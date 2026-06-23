"""FunctionalityTest for certified-transparency.

Exercises the full legitimate flow the way the upstream checker does, condensed
to what proves the service works end-to-end across BOTH daemons:

  * http leaf  — log :3000 get-pubkey + get-sth and monitor :3001 get-pubkey
                 all return well-formed responses (service reachable + alive).
  * checker leaf — a complete register -> get-proof -> claim round-trip:
        sign-entry (SOT) -> add claiming leaf -> add a second leaf with a known
        marker in data_private/data_public -> get-entry-and-proof -> claim-private
        (SOT) AND claim-public (signed claiming leaf) both return the marker.

The claim endpoints make the monitor verify the STH signature + the Merkle proof
hash-chain internally, so this passes only when signing/proofs are intact — and,
crucially, it keeps passing after the legitimate defense fix (which only changes
how the STH checksum is *computed*, not whether honest proofs validate).

CheckResult tree: http + checker.
"""
from __future__ import annotations

import logging
import os
import secrets
from hashlib import sha3_256

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from . import _ed25519 as ed, _net
from ._api import Api, ApiError, TreeLeafProof

log = logging.getLogger(__name__)


class CertifiedTransparencyFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "certified-transparency-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service", "monitor")

    def run(self, target: VulboxTarget) -> CheckResult:
        ip = _net.resolve(target)
        api = Api(ip)
        try:
            ok_http, http_detail = self._check_http(api)
            http = CheckResult(name="http", passed=ok_http, detail=http_detail[-200:])
            if not ok_http:
                return CheckResult(name="certified-transparency", passed=False, children=[http])

            ok_chk, chk_detail = self._check_roundtrip(api)
            checker = CheckResult(name="checker", passed=ok_chk, detail=chk_detail[-200:])
            return CheckResult(
                name="certified-transparency",
                passed=http.passed and checker.passed,
                children=[http, checker],
            )
        finally:
            api.close()

    def _check_http(self, api: Api) -> tuple[bool, str]:
        try:
            pk_log = api.get_pubkey()
            if len(pk_log) != 32:
                return False, f"log pubkey wrong size {len(pk_log)}"
            sth = api.get_sth()
            if len(sth) < 8 + 15 + 32:
                return False, "sth too short"
            pk_mon = api.get_pubkey(from_monitor=True)
            if pk_mon != pk_log:
                return False, "monitor pubkey != log pubkey"
            return True, "log+monitor pubkey/sth OK"
        except (ApiError, OSError) as e:
            return False, f"http error: {type(e).__name__}: {e}"

    def _check_roundtrip(self, api: Api) -> tuple[bool, str]:
        try:
            marker = "chk_" + secrets.token_hex(12)
            content_hash = os.urandom(32)

            sot = api.sign_entry({"content_hash": content_hash, "name": "checker"})

            seed, pubkey = ed.keypair()
            claim_index = api.add_entry({
                "content_hash": content_hash, "name": "checker",
                "pubkey": pubkey, "data_private": "", "data_public": "",
            })
            while claim_index < 2:
                claim_index = api.add_entry({
                    "content_hash": content_hash, "name": "checker",
                    "pubkey": pubkey, "data_private": "", "data_public": "",
                })

            target_index = api.add_entry({
                "content_hash": content_hash, "name": "checker-target",
                "pubkey": ed.keypair()[1],
                "data_private": marker, "data_public": marker,
            })

            flag_proof = api.get_entry_proof(target_index)

            got_priv = api.claim_private(sot, flag_proof)
            if got_priv != marker:
                return False, f"private claim mismatch: {got_priv!r}"

            claim_proof = api.get_entry_proof(claim_index)
            sig = ed.sign(seed, sha3_256(TreeLeafProof.from_binary(claim_proof).leaf).digest())
            got_pub = api.claim_public(claim_proof, flag_proof, sig)
            if got_pub != marker:
                return False, f"public claim mismatch: {got_pub!r}"

            return True, "sign/add/proof/claim-private/claim-public round-trip OK"
        except (ApiError, OSError, ValueError) as e:
            return False, f"protocol error: {type(e).__name__}: {e}"
