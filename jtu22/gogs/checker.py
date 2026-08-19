"""External randomized checker for the complete legitimate Gogs workflow."""

from __future__ import annotations

import ipaddress
import socket
import subprocess

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._gogs import (
    GogsClient,
    assert_rebased_tip,
    push_fixture,
    random_marker,
    random_password,
    random_slug,
)


def _connectable(host: str, port: int) -> bool:
    try:
        socket.create_connection((host, port), 3).close()
        return True
    except OSError:
        return False


def resolve_host(target: VulboxTarget) -> str | None:
    host = target.host
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return host if _connectable(host, target.ports["service"]) else None
    if _connectable(host, target.ports["service"]):
        return host
    try:
        output = subprocess.run(
            [
                "docker",
                "inspect",
                "-f",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
                host,
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        ).stdout.split()
        return next(
            (
                address
                for address in output
                if _connectable(address, target.ports["service"])
            ),
            None,
        )
    except Exception:  # noqa: BLE001 - Docker is absent in facility pollers
        return None


class GogsChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "gogs-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        username = random_slug()
        password = random_password()
        repo = random_slug()
        base_branch = random_slug(12)
        head_branch = random_slug(12)
        base_file = random_slug(10) + ".txt"
        feature_file = random_slug(10) + ".txt"
        feature_marker = random_marker()
        base_marker = random_marker()
        host = resolve_host(target)
        if host is None:
            return CheckResult("checker", False, "public service unreachable")
        base = f"http://{host}:{target.ports['service']}"
        client = GogsClient(base)
        try:
            client.sign_up(username, password)
            client.login(username, password)
            client.assert_ordinary()
            client.create_repo(username, repo)
            client.enable_rebase(username, repo)
            history = push_fixture(
                base,
                username,
                password,
                repo,
                feature_marker,
                base_branch=base_branch,
                head_branch=head_branch,
                base_marker=base_marker,
                base_file=base_file,
                feature_file=feature_file,
            )
            client.create_pr(username, repo, base_branch, head_branch)
            status = client.merge_pr(username, repo)
            if status != 200:
                raise RuntimeError(f"normal rebase merge returned HTTP {status}")
            if (
                client.raw(username, repo, base_branch, feature_file).strip()
                != feature_marker
            ):
                raise RuntimeError(
                    "merged public result did not match the fresh canary"
                )
            base_content = client.raw(
                username, repo, base_branch, base_file
            ).splitlines()
            if base_marker not in base_content:
                raise RuntimeError("rebase discarded the fresh base-side canary")
            assert_rebased_tip(
                base,
                username,
                password,
                repo,
                base_branch,
                expected_parent=history.base_tip,
            )
        except Exception as error:  # noqa: BLE001 - a broken workflow is a red checker
            return CheckResult(
                "checker", False, f"{type(error).__name__}: {error}"[-300:]
            )
        return CheckResult(
            "checker",
            True,
            "fresh randomized repo/push/PR/rebase, ancestry, and content passed",
        )
