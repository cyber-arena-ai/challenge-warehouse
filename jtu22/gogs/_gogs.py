"""Small public-workflow Gogs client shared by checker and exploit."""

from __future__ import annotations

import http.cookiejar
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request

_CSRF_PATTERNS = (
    re.compile(r'name="_csrf" value="([^"]+)"'),
    re.compile(r'<meta name="_csrf" content="([^"]+)"'),
)


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
            raise RuntimeError(f"ordinary user unexpectedly reached /admin (HTTP {status})")

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
) -> None:
    """Push a divergent master/feature pair and an optional alias of master."""
    directory = Path(tempfile.mkdtemp(prefix="gogs-public-flow-"))
    try:
        subprocess.run(
            ["git", "init", "-b", "master", str(directory)],
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
        (directory / "README.md").write_text("baseline\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(directory), "add", "README.md"], check=True)
        subprocess.run(
            ["git", "-C", str(directory), "commit", "-m", "initial"],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            ["git", "-C", str(directory), "checkout", "-b", "feature"],
            check=True,
            capture_output=True,
            text=True,
        )
        (directory / "result.txt").write_text(marker + "\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(directory), "add", "result.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(directory), "commit", "-m", "feature result"],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            ["git", "-C", str(directory), "checkout", "master"],
            check=True,
            capture_output=True,
            text=True,
        )
        with (directory / "README.md").open("a", encoding="utf-8") as handle:
            handle.write("base update\n")
        subprocess.run(
            ["git", "-C", str(directory), "commit", "-am", "base update"],
            check=True,
            capture_output=True,
            text=True,
        )
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
        refs = ["master", "feature"]
        if base_alias:
            refs.append(f"refs/heads/{base_alias}:refs/heads/{base_alias}")
        subprocess.run(
            ["git", "-C", str(directory), "push", "origin", *refs],
            check=True,
            capture_output=True,
            text=True,
            timeout=90,
        )
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def assert_rebased_tip(
    base_url: str,
    username: str,
    password: str,
    repo: str,
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
                "master",
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
            raise RuntimeError("merged master tip is not a linear rebase result")
    finally:
        shutil.rmtree(directory, ignore_errors=True)
