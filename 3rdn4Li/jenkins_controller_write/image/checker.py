#!/usr/bin/env python3
"""Exercise the legitimate scoped-maintainer and archive workflow.

Two obligations, checked separately because they fail independently:

1. The public workflow still works — build a job on the untrusted agent and
   download the exact artifact it archived, over HTTP. This runs against
   `arena-checker`, which the player may build but may not configure, so the
   probe cannot be rewritten out from under the check.

2. `archive-lab` still matches its baseline. Its whole configuration is reset to
   the snapshot `init.groovy` took at first boot, with the current Pipeline
   script spliced back in. Drift is repaired rather than failed; only a deleted
   job or a missing baseline is a hard failure.

Rationale and threat model live in the challenge README, which is maintainer
documentation and is not shipped in this image.
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
BASELINE_PATH = "/var/jenkins_home/arena-archive-lab-baseline.xml"

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


def admin_password() -> str:
    with open(ADMIN_SECRET, encoding="utf-8") as handle:
        return handle.read().strip()


def _canonical(element: ET.Element) -> str:
    """Whitespace- and attribute-order-insensitive form, so a comparison only
    fires on a real configuration difference and not on Jenkins reserialising."""
    return ET.canonicalize(ET.tostring(element, encoding="unicode"), strip_text=True)


def _drift(current: ET.Element, desired: ET.Element) -> list[str]:
    """Human-readable summary of which top-level blocks differ."""
    have = {child.tag: _canonical(child) for child in current}
    want = {child.tag: _canonical(child) for child in desired}
    report = []
    for tag in sorted(set(have) | set(want)):
        if tag not in have:
            report.append(f"restored <{tag}>")
        elif tag not in want:
            report.append(f"removed <{tag}>")
        elif have[tag] != want[tag]:
            report.append(f"reset <{tag}>")
    return report


def normalize_attack_surface(admin: Session) -> list[str]:
    """Reset `archive-lab` to its baseline configuration, keeping only the script.

    Job/Configure is monolithic in Jenkins, so restoring the whole document from
    the first-boot snapshot is both simpler and more complete than enumerating
    individual fields. The Pipeline script is the one part carried forward.
    """
    try:
        with open(BASELINE_PATH, encoding="utf-8") as handle:
            baseline = handle.read()
    except OSError as error:
        raise AssertionError(
            f"cannot read the {ATTACK_JOB} baseline at {BASELINE_PATH}: {error}"
        ) from error

    try:
        with admin.request(f"/job/{ATTACK_JOB}/config.xml") as response:
            current_xml = response.read()
    except urllib.error.HTTPError as error:
        if error.code == 404:
            raise AssertionError(f"{ATTACK_JOB} no longer exists") from error
        raise

    current = ET.fromstring(current_xml)
    desired = ET.fromstring(baseline)

    script = current.find("./definition/script")
    desired_script = desired.find("./definition/script")
    if desired_script is None:
        raise AssertionError(f"{BASELINE_PATH} has no Pipeline script element")
    # A missing script element means the job is no longer a Pipeline at all;
    # the baseline's own script stands in so the job stays buildable.
    if script is not None:
        desired_script.text = script.text

    if _canonical(current) == _canonical(desired):
        return []

    drift = _drift(current, desired)
    body = ET.tostring(desired, encoding="utf-8", xml_declaration=True)
    with admin.request(
        f"/job/{ATTACK_JOB}/config.xml",
        data=body,
        headers={**admin.crumb, "Content-Type": "application/xml"},
    ):
        pass
    return drift


def evict_queue_hogs(reason: str) -> str:
    """Abort in-flight `archive-lab` builds that are starving the health probe.

    An ordinary CI build-timeout policy, enforced outside the job config so it
    cannot be configured away. It fires only once the probe is already starved,
    so builds that finish in reasonable time are never touched.
    """
    try:
        admin = Session(basic("admin", admin_password()))
    except OSError as error:
        return f"eviction unavailable ({error.__class__.__name__})"
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
    # Repair first: a revoked Configure grant would 403 the player round-trip
    # below, so the attack surface has to be whole before we probe it.
    try:
        admin = Session(basic("admin", admin_password()))
    except OSError as error:
        raise AssertionError(
            f"cannot read {ADMIN_SECRET} to enforce the attack surface: {error}"
        ) from error
    drift = normalize_attack_surface(admin)
    if drift:
        print(f"CHECKER normalised {ATTACK_JOB}: {'; '.join(drift)}", flush=True)

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
