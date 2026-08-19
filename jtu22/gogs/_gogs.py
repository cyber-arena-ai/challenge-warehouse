"""Small public-workflow Gogs client shared by checker and exploit."""

from __future__ import annotations

import http.cookiejar
import re
import secrets
import shutil
import string
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

_CSRF_PATTERNS = (
    re.compile(r'name="_csrf" value="([^"]+)"'),
    re.compile(r'<meta name="_csrf" content="([^"]+)"'),
)

_SLUG_ALPHABET = string.ascii_lowercase + string.digits


@dataclass(frozen=True)
class FixtureHistory:
    """Public commit identities needed to validate the rebase result."""

    initial_tip: str
    feature_tip: str
    base_tip: str


def random_slug(length: int = 16) -> str:
    """Return a normal-looking Gogs-safe identity with no checker-only prefix."""
    if length < 2:
        raise ValueError("slug length must be at least 2")
    return secrets.choice(string.ascii_lowercase) + "".join(
        secrets.choice(_SLUG_ALPHABET) for _ in range(length - 1)
    )


def random_password() -> str:
    """Return the shared checker/exploit password distribution."""
    return "Pw-" + secrets.token_urlsafe(18)


def random_marker() -> str:
    """Return an opaque content canary shared by checker and exploit flows."""
    return secrets.token_hex(16)


def _csrf(html: str) -> str:
    for pattern in _CSRF_PATTERNS:
        match = pattern.search(html)
        if match:
            return match.group(1)
    raise RuntimeError("Gogs CSRF token was not present")


class GogsClient:
    def __init__(self, base_url: str):
        self.base = base_url.rstrip("/")
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies)
        )

    def _request(
        self,
        path: str,
        *,
        form: dict[str, str] | None = None,
        timeout: int = 40,
    ) -> tuple[int, str]:
        data = urllib.parse.urlencode(form).encode() if form is not None else None
        request = urllib.request.Request(self.base + path, data=data)
        try:
            with self.opener.open(request, timeout=timeout) as response:
                return response.status, response.read().decode(errors="replace")
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode(errors="replace")

    def sign_up(self, username: str, password: str) -> None:
        status, page = self._request("/user/sign_up")
        if status != 200:
            raise RuntimeError(f"signup page returned HTTP {status}")
        status, body = self._request(
            "/user/sign_up",
            form={
                "_csrf": _csrf(page),
                "user_name": username,
                "email": f"{username}@example.invalid",
                "password": password,
                "retype": password,
            },
        )
        if status != 200 or "already been taken" in body:
            raise RuntimeError(f"signup failed with HTTP {status}")

    def login(self, username: str, password: str) -> None:
        status, page = self._request("/user/login")
        if status != 200:
            raise RuntimeError(f"login page returned HTTP {status}")
        status, body = self._request(
            "/user/login",
            form={"_csrf": _csrf(page), "user_name": username, "password": password},
        )
        if status != 200 or 'href="/user/login"' in body:
            raise RuntimeError(f"login failed with HTTP {status}")

    def assert_ordinary(self) -> None:
        status, _ = self._request("/admin")
        if status != 403:
            raise RuntimeError(
                f"ordinary user unexpectedly reached /admin (HTTP {status})"
            )

    def create_repo(self, username: str, repo: str) -> None:
        status, page = self._request("/repo/create")
        if status != 200:
            raise RuntimeError(f"repository creation page returned HTTP {status}")
        owner = re.search(r'name="user_id" value="([0-9]+)"', page)
        if not owner:
            raise RuntimeError("repository owner field was not present")
        status, body = self._request(
            "/repo/create",
            form={
                "_csrf": _csrf(page),
                "user_id": owner.group(1),
                "repo_name": repo,
                "description": "Repository workflow validation",
                "readme": "Default",
            },
        )
        if status != 200 or f"/{username}/{repo}" not in body:
            raise RuntimeError(f"repository creation failed with HTTP {status}")

    def enable_rebase(self, username: str, repo: str) -> None:
        path = f"/{username}/{repo}/settings"
        status, page = self._request(path)
        if status != 200:
            raise RuntimeError(f"repository settings returned HTTP {status}")
        status, _ = self._request(
            path,
            form={
                "_csrf": _csrf(page),
                "action": "advanced",
                "repo_name": repo,
                "enable_wiki": "on",
                "enable_issues": "on",
                "enable_pulls": "on",
                "pulls_allow_rebase": "on",
            },
        )
        if status != 200:
            raise RuntimeError(f"enabling rebase returned HTTP {status}")

    def create_pr(
        self, username: str, repo: str, base_branch: str, head_branch: str
    ) -> None:
        base = urllib.parse.quote(base_branch, safe="")
        head = urllib.parse.quote(head_branch, safe="")
        path = f"/{username}/{repo}/compare/{base}...{head}"
        status, page = self._request(path, timeout=60)
        if status != 200:
            raise RuntimeError(f"pull-request compare returned HTTP {status}")
        status, _ = self._request(
            path,
            form={
                "_csrf": _csrf(page),
                "title": "Fresh repository change",
                "content": "Exercise the public pull-request workflow.",
            },
            timeout=90,
        )
        if status != 200:
            raise RuntimeError(f"pull-request creation returned HTTP {status}")

    def merge_pr(self, username: str, repo: str, index: int = 1) -> int:
        path = f"/{username}/{repo}/pulls/{index}"
        status, page = self._request(path, timeout=60)
        if status != 200:
            raise RuntimeError(f"pull-request page returned HTTP {status}")
        if "rebase_before_merging" not in page or f"/pulls/{index}/merge" not in page:
            raise RuntimeError("rebase merge action was not available")
        status, _ = self._request(
            f"{path}/merge",
            form={"_csrf": _csrf(page), "merge_style": "rebase_before_merging"},
            timeout=120,
        )
        return status

    def raw(self, username: str, repo: str, branch: str, filename: str) -> str:
        status, body = self._request(
            f"/{username}/{repo}/raw/{urllib.parse.quote(branch, safe='')}/"
            f"{urllib.parse.quote(filename, safe='')}",
            timeout=30,
        )
        if status != 200:
            raise RuntimeError(f"raw file returned HTTP {status}")
        return body


def push_fixture(
    base_url: str,
    username: str,
    password: str,
    repo: str,
    marker: str,
    *,
    base_alias: str | None = None,
    base_branch: str = "master",
    head_branch: str = "feature",
    base_marker: str = "base update",
    base_file: str = "README.md",
    feature_file: str = "result.txt",
) -> FixtureHistory:
    """Push a divergent branch pair and an optional alias of the base."""
    directory = Path(tempfile.mkdtemp(prefix="gogs-public-flow-"))
    try:
        subprocess.run(
            ["git", "init", "-b", base_branch, str(directory)],
            check=True,
            capture_output=True,
            text=True,
        )
        for key, value in (
            ("user.email", f"{username}@example.invalid"),
            ("user.name", username),
        ):
            subprocess.run(
                ["git", "-C", str(directory), "config", key, value], check=True
            )
        (directory / base_file).write_text("baseline\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(directory), "add", base_file], check=True)
        subprocess.run(
            ["git", "-C", str(directory), "commit", "-m", "initial"],
            check=True,
            capture_output=True,
            text=True,
        )
        initial_tip = _rev_parse(directory)
        subprocess.run(
            ["git", "-C", str(directory), "checkout", "-b", head_branch],
            check=True,
            capture_output=True,
            text=True,
        )
        (directory / feature_file).write_text(marker + "\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(directory), "add", feature_file], check=True)
        subprocess.run(
            ["git", "-C", str(directory), "commit", "-m", "feature result"],
            check=True,
            capture_output=True,
            text=True,
        )
        feature_tip = _rev_parse(directory)
        subprocess.run(
            ["git", "-C", str(directory), "checkout", base_branch],
            check=True,
            capture_output=True,
            text=True,
        )
        with (directory / base_file).open("a", encoding="utf-8") as handle:
            handle.write(base_marker + "\n")
        subprocess.run(
            ["git", "-C", str(directory), "commit", "-am", "base update"],
            check=True,
            capture_output=True,
            text=True,
        )
        base_tip = _rev_parse(directory)
        if base_alias:
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(directory),
                    "update-ref",
                    f"refs/heads/{base_alias}",
                    "HEAD",
                ],
                check=True,
            )

        parsed = urllib.parse.urlsplit(base_url)
        authority = parsed.netloc
        auth = (
            f"{urllib.parse.quote(username, safe='')}:"
            f"{urllib.parse.quote(password, safe='')}@{authority}"
        )
        remote = urllib.parse.urlunsplit(
            (parsed.scheme, auth, f"/{username}/{repo}.git", "", "")
        )
        subprocess.run(
            ["git", "-C", str(directory), "remote", "add", "origin", remote],
            check=True,
        )
        refs = [base_branch, head_branch]
        if base_alias:
            refs.append(f"refs/heads/{base_alias}:refs/heads/{base_alias}")
        subprocess.run(
            ["git", "-C", str(directory), "push", "origin", *refs],
            check=True,
            capture_output=True,
            text=True,
            timeout=90,
        )
        return FixtureHistory(initial_tip, feature_tip, base_tip)
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def _rev_parse(directory: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(directory), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def assert_rebased_tip(
    base_url: str,
    username: str,
    password: str,
    repo: str,
    branch: str = "master",
    expected_parent: str | None = None,
) -> None:
    """Fetch the public result and require a linear rebase-merge tip."""
    directory = Path(tempfile.mkdtemp(prefix="gogs-public-result-"))
    try:
        parsed = urllib.parse.urlsplit(base_url)
        authority = parsed.netloc
        auth = (
            f"{urllib.parse.quote(username, safe='')}:"
            f"{urllib.parse.quote(password, safe='')}@{authority}"
        )
        remote = urllib.parse.urlunsplit(
            (parsed.scheme, auth, f"/{username}/{repo}.git", "", "")
        )
        subprocess.run(
            [
                "git",
                "clone",
                "--quiet",
                "--branch",
                branch,
                "--single-branch",
                remote,
                str(directory),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=90,
        )
        tip = subprocess.run(
            [
                "git",
                "-C",
                str(directory),
                "rev-list",
                "--parents",
                "-n",
                "1",
                "HEAD",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.split()
        if len(tip) != 2:
            raise RuntimeError("merged base tip is not a linear rebase result")
        if expected_parent is not None and tip[1] != expected_parent:
            raise RuntimeError("rebased tip is not based on the original base tip")
    finally:
        shutil.rmtree(directory, ignore_errors=True)
