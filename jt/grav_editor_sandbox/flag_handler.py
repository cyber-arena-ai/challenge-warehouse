"""Flag handler for grav-editor-sandbox — two independently-scored stores.

  jwt_secret (READ, secret.credential.read)
      The flag IS the site's real API signing credential. It is planted into
      ``plugins.api.auth.jwt_secret`` through the supported authorized config
      operation. Retrieval asks Grav to issue a fresh token and verifies its
      signature against the expected credential; the config API itself masks
      secrets. The public locator is the logical config key — a target, not a
      path, and never the value.

  command (EXECUTE, host.command.execute)
      The flag lives in one root-only file that also carries a fresh, unguessable
      operation id. Only ``/usr/local/bin/catflag`` — root-owned, setuid, callable
      only by the service account — can turn that id back into the flag, so a
      direct read of the backing file by UID 1001 fails and reaching execution in
      the service context is the only way to the value. ``retrieve`` audits the
      MECHANISM by invoking the same helper as the same account, so deleting the
      helper fails the audit instead of quietly denying every capture.

All facility work runs INSIDE prod over the privileged docker-exec bridge, driven
by a per-box, root-only facility-admin credential the entrypoint generated. The
script sources that credential in-container, so the password never enters a
command line, a handle, an event, an error, or this process.
"""

from __future__ import annotations

import base64
import json
import secrets
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

from ._ids import (
    JWT_TARGET,
    STORE_COMMAND,
    STORE_JWT,
    catflag_command,
    derive_principal,
    pack_handle,
    public_flag_id,
    unpack_handle,
)

OBJECTIVE_PATH = "/var/lib/arena/command/objective"
OBJECTIVE_DIR = "/var/lib/arena/command"

# Mint an access token from the root-only facility credential. Sourcing the file
# in-container is what keeps the password off every command line and out of this
# process; `php` parses the response because the API's JSON shape is not
# reliably greppable.
_PRELUDE = """
set -eu
. /arena/secrets/facility.env
API=http://127.0.0.1:8080/api/v1
PUBLIC_HOST=$(printf %s '@@PUBLIC_HOST_B64@@' | base64 -d)
TOK=$(printf '{"username":"%s","password":"%s"}' "$FACILITY_USER" "$FACILITY_PASS" \
  | curl -sS --max-time 25 -X POST -H 'Content-Type: application/json' \
      -H "Host: $PUBLIC_HOST" \
      --data-binary @- "$API/auth/token" \
  | php -r 'echo json_decode(stream_get_contents(STDIN), true)["data"]["access_token"] ?? "";')
[ -n "$TOK" ] || { echo AUTH_FAIL; exit 0; }
"""

_PLANT_JWT = _PRELUDE + """
BODY=$(mktemp)
trap 'rm -f "$BODY"' EXIT
printf %s '@@BODY_B64@@' | base64 -d > "$BODY"
CODE=$(curl -sS --max-time 25 -o /dev/null -w '%{http_code}' -X PATCH \
  -H 'Content-Type: application/json' -H "Authorization: Bearer $TOK" \
  -H "Host: $PUBLIC_HOST" \
  --data-binary @"$BODY" "$API/config/plugins/api")
[ "$CODE" = 200 ] || { echo "HTTP $CODE"; exit 0; }
echo OK
"""

_VERIFY_JWT = _PRELUDE + """
printf '%s\n%s' '@@EXPECTED_B64@@' "$TOK" \
  | php -r '
      require "/srv/challenge/grav/user/plugins/api/vendor/autoload.php";
      $secret = base64_decode(trim(fgets(STDIN)), true);
      $token = trim(stream_get_contents(STDIN));
      if ($secret === false || $secret === "" || $token === "") {
          echo "ERROR\n";
          exit;
      }
      try {
          $decoded = Firebase\\JWT\\JWT::decode(
              $token, new Firebase\\JWT\\Key($secret, "HS256"));
          echo (($decoded->type ?? null) === "access") ? "PRESENT\n" : "ERROR\n";
      } catch (Throwable) {
          echo "MISMATCH\n";
      }
  '
"""

# One atomic rename publishes the operation id and the flag together, so a plant
# is all-or-nothing and a re-plant converges instead of leaving a half state.
_PLANT_COMMAND = """
set -eu
D=@@DIR@@
mkdir -p "$D"
chown root:root "$D"
chmod 0700 "$D"
NEW="$D/.objective.new"
printf %s '@@OBJECTIVE_B64@@' | base64 -d > "$NEW"
chown root:root "$NEW"
chmod 0600 "$NEW"
mv -f "$NEW" @@OBJECTIVE@@
echo OK
"""

_CREATE_USER = """
BODY=$(mktemp)
printf %s '@@BODY_B64@@' | base64 -d > "$BODY"
CODE=$(curl -sS --max-time 25 -o /dev/null -w '%{http_code}' -X POST \
  -H 'Content-Type: application/json' -H "Authorization: Bearer $TOK" \
  -H "Host: $PUBLIC_HOST" \
  --data-binary @"$BODY" "$API/users")
rm -f "$BODY"
echo "USER @@USERNAME@@ $CODE"
"""

# The least-privilege content-editor grant. Identical for every attacker (AUTH-1)
# and for the checker's own account: page read/write and login, nothing else.
EDITOR_ACCESS = {
    "api": {"access": True, "pages": {"read": True, "write": True}},
    "site": {"login": True},
}


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def _json_b64(payload: dict) -> str:
    return _b64(json.dumps(payload))


class GravEditorSandboxFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "grav-editor-sandbox-flag-handler"

    # ── plant ───────────────────────────────────────────────────────────
    def plant(self, target: VulboxTarget, flags: Mapping[str, Flag]) -> Mapping[str, str]:
        exec_in = target.meta["exec_in_container"]
        handles: dict[str, str] = {}

        if STORE_JWT in flags:
            value = flags[STORE_JWT].value
            script = _PLANT_JWT.replace(
                "@@BODY_B64@@",
                _json_b64({"auth": {"jwt_secret": value}}),
            ).replace("@@PUBLIC_HOST_B64@@", _b64(target.host))
            self._expect_ok(exec_in, target.host, script, STORE_JWT)
            handles[STORE_JWT] = pack_handle(
                {"store": STORE_JWT, "target": JWT_TARGET, "flag": value})

        if STORE_COMMAND in flags:
            value = flags[STORE_COMMAND].value
            operation = secrets.token_hex(16)
            script = (
                _PLANT_COMMAND
                .replace("@@DIR@@", OBJECTIVE_DIR)
                .replace("@@OBJECTIVE@@", OBJECTIVE_PATH)
                .replace("@@OBJECTIVE_B64@@", _b64(f"{operation}\n{value}\n"))
            )
            self._expect_ok(exec_in, target.host, script, STORE_COMMAND)
            handles[STORE_COMMAND] = pack_handle(
                {"store": STORE_COMMAND, "op": operation, "flag": value})

        if STORE_JWT in flags:
            # Grav's API saves the new signing setting immediately, but the
            # main `grav.config` snapshot used by rendered pages is process
            # local. Finish the SETUP-time rotation through the challenge's
            # existing restart path so the newly published READ target and the
            # application view become current together, before LIVE.
            rc, _ = exec_in(target.host, "/arena/restart.sh flag-rotation")
            if rc != 0:
                raise RuntimeError(f"{self.name}: jwt_secret reload failed: rc={rc}")

        return handles

    def _expect_ok(self, exec_in, host: str, script: str, store: str) -> None:
        rc, out = exec_in(host, script)
        tail = (out or "").strip().splitlines()[-1:] or [""]
        if rc != 0 or tail[0] != "OK":
            # `tail` carries only our own sentinels (OK / AUTH_FAIL / HTTP <code>).
            raise RuntimeError(
                f"{self.name}: {store} plant failed: rc={rc} status={tail[0]!r}")

    # ── retrieve ────────────────────────────────────────────────────────
    def retrieve(self, target: VulboxTarget, handle: str,
                 expected: str | None = None) -> FlagObservation:
        """Pure, read-only, never-raising observation of one store, by handle."""
        payload = unpack_handle(handle)
        if payload is None:
            return FlagObservation(ObservationStatus.ERROR, detail="unreadable handle")
        wanted = expected if expected is not None else payload.get("flag")
        store = payload.get("store")
        if store == STORE_JWT:
            return self._observe_jwt(target, wanted)
        if store == STORE_COMMAND:
            return self._observe_command(target, payload.get("op"), wanted)
        return FlagObservation(ObservationStatus.ERROR, detail="unknown store")

    def _observe_jwt(self, target: VulboxTarget, expected: str | None) -> FlagObservation:
        if expected is None:
            return FlagObservation(ObservationStatus.ERROR,
                                   detail="expected credential unavailable")
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            return FlagObservation(ObservationStatus.ERROR, detail="no exec_in_container")
        script = _VERIFY_JWT.replace("@@EXPECTED_B64@@", _b64(expected))
        script = script.replace("@@PUBLIC_HOST_B64@@", _b64(target.host))
        try:
            rc, out = exec_in(target.host, script)
        except Exception:  # noqa: BLE001 — retrieve must never raise
            return FlagObservation(ObservationStatus.ERROR, detail="credential check exec raised")
        if rc != 0:
            return FlagObservation(ObservationStatus.ERROR, detail=f"credential check rc={rc}")
        line = ((out or "").strip().splitlines() or [""])[-1]
        if line == "AUTH_FAIL":
            return FlagObservation(ObservationStatus.AUTH_REJECTED,
                                   detail="facility credential rejected")
        if line == "PRESENT":
            return FlagObservation(ObservationStatus.PRESENT, value=expected)
        if line == "MISMATCH":
            return FlagObservation(ObservationStatus.MISMATCH)
        return FlagObservation(ObservationStatus.ERROR,
                               detail="unrecognised credential check result")

    def _observe_command(self, target: VulboxTarget, operation: str | None,
                         expected: str | None) -> FlagObservation:
        """Audit the MECHANISM: run the current helper as the service account and
        require it to reveal the flag. A helper the defender removed, broke, or
        detached from this round's operation id fails here — exactly as it would
        fail an attacker who reached execution."""
        if not operation:
            return FlagObservation(ObservationStatus.ERROR, detail="handle carries no operation")
        try:
            command = catflag_command(operation)
        except ValueError:
            return FlagObservation(ObservationStatus.ERROR, detail="invalid operation id")
        return exec_read_observe(target, command, expected)

    # ── baseline principals ─────────────────────────────────────────────
    def provision_principals(self, target: VulboxTarget,
                             seeds: Mapping[str, str]) -> Mapping[str, BaselinePrincipal]:
        """One equal, least-privilege content-editor account per attacker, created
        once per match through the supported ``/api/v1/users`` operation.

        Identity and secret are derived from that attacker's own seed alone, so no
        team can compute another's login. All accounts are created by a single
        authenticated pass; anything short of every account landing raises, so a
        match never starts half-provisioned.
        """
        exec_in = target.meta["exec_in_container"]
        if not seeds:
            return {}

        principals: dict[str, BaselinePrincipal] = {}
        blocks = [_PRELUDE.replace("@@PUBLIC_HOST_B64@@", _b64(target.host))]
        for attacker, seed in sorted(seeds.items()):
            username, password = derive_principal(seed)
            principals[attacker] = BaselinePrincipal(
                principal_id=username,
                credentials={"username": username, "password": password},
            )
            blocks.append(
                _CREATE_USER
                .replace("@@USERNAME@@", username)
                .replace("@@BODY_B64@@", _json_b64({
                    "username": username,
                    "password": password,
                    "email": f"{username}@editor-sandbox.invalid",
                    "fullname": "Content Editor",
                    "title": "Content Editor",
                    "access": EDITOR_ACCESS,
                }))
            )
        rc, out = exec_in(target.host, "".join(blocks))
        results = {}
        for raw in (out or "").splitlines():
            parts = raw.strip().split()
            if len(parts) == 3 and parts[0] == "USER":
                results[parts[1]] = parts[2]
        if rc != 0 or "AUTH_FAIL" in (out or ""):
            raise RuntimeError(f"{self.name}: principal provisioning could not authenticate")
        # Report the failing USERNAMES and status codes only — never a credential.
        failed = sorted(
            p.principal_id for p in principals.values()
            if results.get(p.principal_id) != "201"
        )
        if failed:
            detail = ", ".join(f"{u}={results.get(u, 'no-result')}" for u in failed)
            raise RuntimeError(f"{self.name}: principal creation failed: {detail}")
        return principals

    # ── attack info ─────────────────────────────────────────────────────
    def flag_id(self, handle: str) -> str | None:
        """The public per-round locator: the logical config key for the READ
        store, this round's operation id for the EXECUTE store. Never the flag,
        never the facility credential, never planting state."""
        try:
            return public_flag_id(handle)
        except Exception:  # noqa: BLE001 — the framework treats a throw as None
            return None
