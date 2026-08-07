#!/usr/bin/env python3
"""Exercise the legitimate scoped-maintainer and archive workflow.

Two separate obligations are checked, because they can fail independently:

1. The public workflow still works. A scoped maintainer builds a job on the
   untrusted agent and downloads the exact artifact it archived, over HTTP.
   This runs against `arena-checker`, which the player may build but may not
   configure, so an attacker cannot rewrite the probe out from under us.

2. The attack surface still exists. `archive-lab` — the job a scoped maintainer
   configures and builds — must remain enabled, sandboxed, and granted to the
   player. Removing any of these keeps the service superficially alive while
   deleting the vulnerable feature, so each is a hard failure here.
"""

from __future__ import annotations

import base64
import http.cookiejar
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


BASE = "http://127.0.0.1:8080"
PROBE_JOB = "arena-checker"
ATTACK_JOB = "archive-lab"
ADMIN_SECRET = "/var/jenkins_home/secrets/arena-admin-password"

# The four job-local permissions the intended attack path depends on.
REQUIRED_PERMISSIONS = (
    "hudson.model.Item.Read",
    "hudson.model.Item.Configure",
    "hudson.model.Item.Build",
    "hudson.model.Item.Workspace",
)

MIN_AGENT_EXECUTORS = 2
QUEUE_GRACE_SECS = 20
BUILD_TIMEOUT_SECS = 90


def basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


class Session:
    """One authenticated Jenkins HTTP session with a lazily fetched crumb."""

    def __init__(self, auth: str):
        self.auth = auth
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )
        self._crumb: dict[str, str] | None = None

    def request(
        self,
        path: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ):
        request_headers = {"Authorization": self.auth}
        request_headers.update(headers or {})
        req = urllib.request.Request(BASE + path, data=data, headers=request_headers)
        return self.opener.open(req, timeout=10)

    @property
    def crumb(self) -> dict[str, str]:
        if self._crumb is None:
            with self.request("/crumbIssuer/api/json") as response:
                data = json.load(response)
            self._crumb = {data["crumbRequestField"]: data["crumb"]}
        return self._crumb

    def json(self, path: str):
        with self.request(path) as response:
            return json.load(response)


def assert_attack_surface(config: bytes) -> None:
    """Fail if the vulnerable feature has been amputated rather than repaired.

    A narrow fix (patching the controller-side extraction) leaves every one of
    these intact; disabling the job, revoking the maintainer's grants, or
    parking the script behind admin script-approval does not.
    """
    root = ET.fromstring(config)

    disabled = root.findtext("disabled", default="false").strip().lower()
    if disabled != "false":
        raise AssertionError(f"{ATTACK_JOB} is disabled")

    definition = root.find("definition")
    if definition is None:
        raise AssertionError(f"{ATTACK_JOB} has no Pipeline definition")

    # sandbox=false parks every future build behind admin script approval, which
    # the player can never obtain — the job becomes permanently unbuildable.
    sandbox = definition.findtext("sandbox", default="false").strip().lower()
    if sandbox != "true":
        raise AssertionError(
            f"{ATTACK_JOB} Groovy sandbox is off; builds cannot run without "
            "admin script approval"
        )

    if not (definition.findtext("script") or "").strip():
        raise AssertionError(f"{ATTACK_JOB} has an empty Pipeline script")

    # Entries are "<permission>:<sid>", optionally prefixed "USER:" / "GROUP:".
    granted = {
        element.text.strip()
        for element in root.iter("permission")
        if element.text
    }
    missing = [
        permission
        for permission in REQUIRED_PERMISSIONS
        if not any(
            entry.endswith(f"{permission}:player") for entry in granted
        )
    ]
    if missing:
        raise AssertionError(
            f"{ATTACK_JOB} no longer grants player: {', '.join(missing)}"
        )


def evict_queue_hogs(reason: str) -> str:
    """Abort in-flight `archive-lab` builds that are starving the health probe.

    The scoped maintainer may legitimately run builds, but not indefinitely: a
    single `sh 'sleep 3000'` would otherwise hold capacity and take the service
    down without touching the vulnerability. This is an ordinary CI build-timeout
    policy, enforced outside the job config so it cannot be configured away. It
    fires only once the probe is already starved, so a normal build — or the
    intended exploit, which finishes in seconds — is never touched.
    """
    try:
        with open(ADMIN_SECRET, encoding="utf-8") as handle:
            password = handle.read().strip()
    except OSError as error:
        return f"eviction unavailable ({error.__class__.__name__})"

    admin = Session(basic("admin", password))
    try:
        builds = admin.json(f"/job/{ATTACK_JOB}/api/json?tree=builds[number,building]")
    except (urllib.error.URLError, OSError) as error:
        return f"eviction lookup failed ({error})"

    aborted = []
    for build in builds.get("builds", []):
        if not build.get("building"):
            continue
        number = build["number"]
        try:
            with admin.request(
                f"/job/{ATTACK_JOB}/{number}/stop", data=b"", headers=admin.crumb
            ):
                pass
            aborted.append(number)
        except (urllib.error.URLError, OSError):
            continue
    if not aborted:
        return f"{reason}; no {ATTACK_JOB} build to evict"
    return f"{reason}; evicted {ATTACK_JOB} builds {aborted}"


def run_probe_build(player: Session, token: str) -> int:
    """Trigger the probe job and wait for it, evicting a starving hog once."""
    expected = player.json(f"/job/{PROBE_JOB}/api/json")["nextBuildNumber"]
    query = urllib.parse.urlencode({"TOKEN": token})
    with player.request(
        f"/job/{PROBE_JOB}/buildWithParameters?{query}",
        data=b"",
        headers=player.crumb,
    ):
        pass

    started = time.monotonic()
    evicted = False
    deadline = started + BUILD_TIMEOUT_SECS
    while time.monotonic() < deadline:
        build = None
        try:
            build = player.json(f"/job/{PROBE_JOB}/{expected}/api/json")
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
            # Still queued; the run has not been created yet.

        if build is not None and not build["building"]:
            if build["result"] != "SUCCESS":
                raise AssertionError(f"probe build {expected}: {build['result']}")
            return expected

        # A Pipeline run reports building=True from the moment it starts, while
        # it is still blocked inside node() waiting for an executor — so elapsed
        # time, not queue state, is what reveals starvation.
        if not evicted and time.monotonic() - started > QUEUE_GRACE_SECS:
            evicted = True
            print(
                "CHECKER "
                + evict_queue_hogs(f"probe stalled >{QUEUE_GRACE_SECS}s"),
                flush=True,
            )
            deadline = time.monotonic() + BUILD_TIMEOUT_SECS
        time.sleep(1)
    raise TimeoutError("probe build did not complete")


def main() -> int:
    player = Session(basic("player", "arena-player-password"))

    # The scoped maintainer must retain Configure permission. Posting the exact
    # bytes back exercises the public mutation path without changing gameplay.
    with player.request(f"/job/{ATTACK_JOB}/config.xml") as response:
        config = response.read()
    with player.request(
        f"/job/{ATTACK_JOB}/config.xml",
        data=config,
        headers={**player.crumb, "Content-Type": "application/xml"},
    ):
        pass

    assert_attack_surface(config)

    controller = player.json("/api/json?tree=numExecutors")
    if controller.get("numExecutors") != 0:
        raise AssertionError(f"controller executors: {controller!r}")

    agent = player.json("/computer/untrusted-agent/api/json")
    if agent.get("offline") is not False:
        raise AssertionError(f"agent offline: {agent!r}")
    if (agent.get("numExecutors") or 0) < MIN_AGENT_EXECUTORS:
        raise AssertionError(
            f"agent capacity {agent.get('numExecutors')!r} is below the "
            f"{MIN_AGENT_EXECUTORS} executors the workflow needs"
        )

    token = "arena-check-" + secrets.token_hex(16)
    number = run_probe_build(player, token)

    with player.request(
        f"/job/{PROBE_JOB}/{number}/artifact/probe.txt"
    ) as response:
        artifact = response.read().decode()
    if artifact != token:
        raise AssertionError(f"artifact mismatch: {artifact!r}")

    print(f"CHECKER ok: config + agent archive roundtrip ({token[-8:]})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
