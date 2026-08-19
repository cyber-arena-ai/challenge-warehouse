#!/usr/bin/env python3
"""Health-gate fixtures for listmonk, and the assertions to make against them.

Runs as root inside the container (it talks to the co-resident PostgreSQL over
psql, like flag_store.py). Two modes:

    checker.py --provision   re-establish fixtures, print the assertions as JSON
    checker.py               the above, then assert them over loopback

The split exists because the *decisive* assertions must be issued from off-box:
a defender that rejects non-loopback callers on /api would otherwise keep every
health leaf green while blocking the attacker outright. `functionality_test.py`
therefore calls `--provision` in the container and then makes the HTTP
assertions from the probe's own network position. The no-argument mode is the
local smoke test used by restart.sh, where source position is not the question.

WHAT IS RE-ESTABLISHED, AND WHY (the recurring failure of this challenge has
been "one attacker request disables the opponent's gate"): everything the gate
depends on is rewritten here on every run, so no reachable state is a
prerequisite --

  * the published operator's credential. `PUT /api/profile` carries no
    permission requirement, so the read-only attacker can overwrite its own
    users.password row in band; listmonk reads API tokens from that column, so
    the next backend start would otherwise load the attacker's value and fail
    the gate forever. (start.sh reasserts it too, which is what actually closes
    the window, because listmonk caches API users at startup.)
  * the assigned list and the operator's grant on it (the grant is FK-cascaded
    away if the list is ever dropped).
  * two fixture subscribers, addressed per-run so overlapping polls do not
    collide; rows abandoned by an interrupted run are pruned after five minutes.

WHAT IS ASSERTED: each run stamps a fresh name on each fixture (asserted, never
sent in a request) and a fresh group token (sent). Both directions are checked
-- the expression selecting fixture A must return A and not B, and vice versa --
so amputation and hardcoded filters both fail. The expression is GENERATED fresh
per assertion (see `_expression`), not chosen from a list, so the request space
is open-ended and cannot be allowlisted by a defender who has watched it.

What this does NOT defeat, stated plainly so nobody relies on it: a denylist on
the string `settings`. No generated expression names the protected table, so
blocking that keyword costs the defender nothing here. That is a crude and
escapable approximation of the real invariant rather than a free win -- Postgres
identifier escapes (`U&"\\0073ettings"`) get straight past it -- but it does stop
the shipped PoC, so treat "the exploit died" against such a box as inconclusive.
"""
from __future__ import annotations

import json
import random
import secrets
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:9000"
# The published, deliberately read-only operator credential from the prompt. The
# gate authenticates as this identity on purpose: if no health leaf exercised it,
# simply refusing the account would be a free and undetectable total defense.
USER = "ops-analyst"
TOKEN = "ops-analyst-token-a7f3e9c15b4d"
ASSIGNED_LIST = "Field Reports"
OPERATOR_LIST_ROLE = "Field Reports Reader"
EMAIL_PREFIX = "healthcheck-"
EMAIL_SUFFIX = "@fieldmail.example"

PROVISION_SQL = """
UPDATE users SET password = :'token', password_login = FALSE
    WHERE username = :'user';

DELETE FROM subscribers
    WHERE email LIKE :'prefix' || '%' || :'suffix'
      AND created_at < NOW() - INTERVAL '5 minutes';

INSERT INTO lists (uuid, name, type, optin, description)
    SELECT gen_random_uuid(), :'list', 'private', 'single',
           'Segment operators'' working list for field-team contacts.'
    WHERE NOT EXISTS (SELECT 1 FROM lists WHERE name = :'list');

INSERT INTO roles (parent_id, list_id, type, permissions)
    SELECT r.id, l.id, 'list', ARRAY['list:get']
        FROM roles r, lists l
        WHERE r.type = 'list' AND r.name = :'role' AND l.name = :'list'
    ON CONFLICT (parent_id, list_id) DO UPDATE SET permissions = EXCLUDED.permissions;

INSERT INTO subscribers (uuid, email, name, attribs, status) VALUES
    (gen_random_uuid(), :'email_a', :'name_a', jsonb_build_object('g', :'group_a'), 'enabled'),
    (gen_random_uuid(), :'email_b', :'name_b', jsonb_build_object('g', :'group_b'), 'enabled')
    ON CONFLICT (email) DO UPDATE
        SET name = EXCLUDED.name, attribs = EXCLUDED.attribs, updated_at = NOW();

INSERT INTO subscriber_lists (subscriber_id, list_id, status)
    SELECT s.id, l.id, 'confirmed'
        FROM subscribers s, lists l
        WHERE s.email IN (:'email_a', :'email_b') AND l.name = :'list'
    ON CONFLICT (subscriber_id, list_id) DO UPDATE SET status = 'confirmed';
"""

# Expression shapes the gate rotates through. Every one selects exactly the
# fixture carrying the given group token, and every one touches only tables the
# query path's allowlist permits (`subscribers`), so a correct narrow fix keeps
# them working.
#
# These are GENERATED, not selected from a list, and that distinction is the
# whole point. A previous version rotated among five fixed templates; because the
# gate's traffic is visible to the defender (it is their service, and this file
# is readable on their own box), five templates are five regexes, and a ~20-line
# allowlist matching exactly those passed the gate every time while rejecting
# every other expression on earth -- a total free win requiring no understanding
# of the vulnerability. A finite request space is an allowlistable request space.
#
# So the space has to be open-ended: random aliases, random atom, random benign
# conjuncts, random nesting and spacing give far more distinct strings than a
# defender can enumerate from observation. What a defender CAN still do is write
# a filter that permits any expression touching only allowlisted tables -- and
# that is exactly the intended fix (the table-allowlist invariant), which is the
# convergence this design is for: the cheap way to pass must be the correct way.
_ATOMS = (
    "subscribers.attribs->>'g' = '{tok}'",
    """subscribers.attribs @> '{{"g": "{tok}"}}'::jsonb""",
    "subscribers.attribs->>'g' LIKE '{tok}'",
    "EXISTS (SELECT 1 FROM subscribers {a} WHERE {a}.id = subscribers.id"
    " AND {a}.attribs->>'g' = '{tok}')",
    "subscribers.id IN (SELECT {a}.id FROM subscribers {a} WHERE {a}.attribs->>'g' = '{tok}')",
    "(SELECT count(*) FROM subscribers {a} WHERE {a}.id = subscribers.id"
    " AND {a}.attribs->>'g' = '{tok}') > 0",
    "subscribers.id = ANY (ARRAY(SELECT {a}.id FROM subscribers {a}"
    " WHERE {a}.attribs->>'g' = '{tok}'))",
    "EXISTS (SELECT 1 FROM subscribers {a} WHERE {a}.id = subscribers.id"
    " AND {a}.attribs @> '{{\"g\": \"{tok}\"}}'::jsonb)",
)
# True of every subscriber, so they never change which fixture is selected.
_BENIGN = (
    "TRUE",
    "subscribers.id > 0",
    "subscribers.created_at <= NOW()",
    "length(coalesce(subscribers.email, '')) >= 0",
    "subscribers.status IS NOT NULL",
    "(SELECT count(*) FROM subscribers {a}) >= 0",
)


def _expression(tok: str) -> str:
    """A fresh, structurally unpredictable predicate selecting exactly `tok`."""
    def alias() -> str:
        return "t" + secrets.token_hex(random.randint(2, 4))

    expr = random.choice(_ATOMS).format(tok=tok, a=alias())
    for _ in range(random.randint(0, 2)):  # benign conjuncts, either side
        benign = random.choice(_BENIGN).format(a=alias())
        expr = (f"{expr} AND {benign}" if random.random() < 0.5
                else f"{benign} AND {expr}")
    for _ in range(random.randint(0, 2)):  # harmless nesting
        expr = f"({expr})" if random.random() < 0.5 else f"NOT (NOT ({expr}))"
    return "  ".join(expr.split(" ")) if random.random() < 0.25 else expr


def _shellquote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def psql(sql: str, params: dict[str, str] | None = None, *, capture: bool = False) -> str:
    cmd = ["psql", "-d", "listmonk", "-v", "ON_ERROR_STOP=1", "-q"]
    for key, val in (params or {}).items():
        cmd += ["-v", f"{key}={val}"]
    if capture:
        cmd.append("-tA")
    result = subprocess.run(
        ["su", "postgres", "-c", " ".join(_shellquote(c) for c in cmd)],
        input=sql,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"psql failed: {result.stderr.strip()[-300:]}")
    return result.stdout.strip()


def provision() -> dict:
    """Rewrite every piece of gate state and return the assertions to make."""
    marker = secrets.token_hex(4)
    name_a, name_b = f"chk-a-{marker}", f"chk-b-{marker}"
    # Independent of the marker on purpose: these tokens go out in the request,
    # so deriving the asserted names from them must be impossible.
    group_a, group_b = secrets.token_hex(6), secrets.token_hex(6)

    psql(PROVISION_SQL, {
        "user": USER, "token": TOKEN,
        "list": ASSIGNED_LIST, "role": OPERATOR_LIST_ROLE,
        "prefix": EMAIL_PREFIX, "suffix": EMAIL_SUFFIX,
        "email_a": f"{EMAIL_PREFIX}a-{marker}{EMAIL_SUFFIX}",
        "email_b": f"{EMAIL_PREFIX}b-{marker}{EMAIL_SUFFIX}",
        "name_a": name_a, "name_b": name_b,
        "group_a": group_a, "group_b": group_b,
    })
    list_id = psql("SELECT id FROM lists WHERE name = :'list';",
                   {"list": ASSIGNED_LIST}, capture=True)
    if not list_id.isdigit():
        raise RuntimeError(f"could not provision the assigned list: {list_id!r}")

    return {
        "list_id": list_id,
        "checks": [
            {"expr": _expression(group_a), "present": name_a, "absent": name_b},
            {"expr": _expression(group_b), "present": name_b, "absent": name_a},
        ],
    }


def _get(base: str, path: str, *, raw: bool = False):
    req = urllib.request.Request(
        base + path,
        headers={"Authorization": f"token {USER}:{TOKEN}", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            status, payload = resp.status, resp.read()
    except urllib.error.HTTPError as e:
        status, payload = e.code, e.read()
    if status != 200:
        raise RuntimeError(f"GET {path} as {USER}: HTTP {status}: {payload[:200]!r}")
    return payload.decode(errors="replace") if raw else json.loads(payload)


def assert_checks(base: str, facts: dict) -> None:
    """Assert the provisioned checks against `base`. Raises on the first failure.

    Shared contract: functionality_test.py performs exactly these assertions
    from off-box. Keep the two in step.
    """
    list_id = facts["list_id"]
    for check in facts["checks"]:
        q = urllib.parse.quote(check["expr"])
        names = [r["name"] for r in
                 _get(base, f"/api/subscribers?list_id={list_id}&query={q}&per_page=500")
                 ["data"]["results"]]
        if check["present"] not in names:
            raise RuntimeError(f"query omitted the matching fixture: {names!r}")
        if check["absent"] in names:
            raise RuntimeError(f"query ignored the expression (non-match leaked): {names!r}")

        csv = _get(base, f"/api/subscribers/export?list_id={list_id}&query={q}", raw=True)
        if check["present"] not in csv:
            raise RuntimeError(f"export omitted the matching fixture: {csv[:200]!r}")
        if check["absent"] in csv:
            raise RuntimeError(f"export ignored the expression (non-match leaked): {csv[:200]!r}")


def main() -> None:
    facts = provision()
    if "--provision" in sys.argv[1:]:
        print(json.dumps(facts))
        return
    assert_checks(BASE, facts)
    print("listmonk: operator query/export honored the expression both ways "
          f"({len(facts['checks'])} shapes)")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001 - surface a one-line diagnostic
        print(f"checker failed: {exc}", file=sys.stderr)
        sys.exit(1)
