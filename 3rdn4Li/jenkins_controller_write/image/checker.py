#!/usr/bin/env python3
"""Exercise the legitimate scoped-maintainer and archive workflow."""

from __future__ import annotations

import base64
import http.cookiejar
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request


BASE = "http://127.0.0.1:8080"
AUTH = "Basic " + base64.b64encode(
    b"player:arena-player-password"
).decode()


def main() -> int:
    cookies = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))

    def request(
        path: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ):
        request_headers = {"Authorization": AUTH}
        request_headers.update(headers or {})
        req = urllib.request.Request(BASE + path, data=data, headers=request_headers)
        return opener.open(req, timeout=10)

    with request("/crumbIssuer/api/json") as response:
        crumb_data = json.load(response)
    crumb = {crumb_data["crumbRequestField"]: crumb_data["crumb"]}

    # The scoped maintainer must retain Configure permission. Posting the exact
    # bytes back exercises the public mutation path without changing gameplay.
    with request("/job/archive-lab/config.xml") as response:
        config = response.read()
    with request(
        "/job/archive-lab/config.xml",
        data=config,
        headers={**crumb, "Content-Type": "application/xml"},
    ):
        pass

    with request("/api/json?tree=numExecutors") as response:
        controller = json.load(response)
    if controller.get("numExecutors") != 0:
        raise AssertionError(f"controller executors: {controller!r}")
    with request("/computer/untrusted-agent/api/json") as response:
        agent = json.load(response)
    if agent.get("offline") is not False:
        raise AssertionError(f"agent offline: {agent!r}")

    token = "arena-check-" + secrets.token_hex(16)
    with request("/job/arena-checker/api/json") as response:
        expected_build = json.load(response)["nextBuildNumber"]
    query = urllib.parse.urlencode({"TOKEN": token})
    with request(
        f"/job/arena-checker/buildWithParameters?{query}", data=b"", headers=crumb
    ):
        pass

    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            with request(f"/job/arena-checker/{expected_build}/api/json") as response:
                build = json.load(response)
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
            time.sleep(1)
            continue
        if not build["building"]:
            if build["result"] != "SUCCESS":
                raise AssertionError(
                    f"checker build {expected_build}: {build['result']}"
                )
            break
        time.sleep(1)
    else:
        raise TimeoutError("checker build did not complete")

    with request(
        f"/job/arena-checker/{expected_build}/artifact/probe.txt"
    ) as response:
        artifact = response.read().decode()
    if artifact != token:
        raise AssertionError(f"artifact mismatch: {artifact!r}")
    print(f"CHECKER ok: config + agent archive roundtrip ({token[-8:]})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
