"""Small Gogs client for ordinary repository-owner workflows."""

from __future__ import annotations

import http.cookiejar
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request


_CSRF = re.compile(r'name="_csrf" value="([^"]+)"')


class HTTPFailure(RuntimeError):
    def __init__(self, operation: str, status: int, detail: str = ""):
        super().__init__(f"{operation} returned HTTP {status}: {detail[:160]}")
        self.status = status


def _token(page: str) -> str:
    match = _CSRF.search(page)
    if not match:
        raise RuntimeError("Gogs CSRF token is absent")
    return match.group(1)


class GogsClient:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )

    def request(
        self,
        path: str,
        *,
        form: dict[str, str] | None = None,
        data: object | None = None,
        headers: dict[str, str] | None = None,
        timeout: int = 40,
    ) -> tuple[int, str]:
        body = None
        request_headers = dict(headers or {})
        if form is not None:
            body = urllib.parse.urlencode(form).encode()
        elif data is not None:
            body = json.dumps(data).encode()
            request_headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base + path, data=body, headers=request_headers
        )
        try:
            with self.opener.open(request, timeout=timeout) as response:
                return response.status, response.read().decode(errors="replace")
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode(errors="replace")

    def sign_up(
        self, username: str, password: str, *, email: str | None = None
    ) -> None:
        status, page = self.request("/user/sign_up")
        if status != 200:
            raise HTTPFailure("signup page", status, page)
        status, body = self.request(
            "/user/sign_up",
            form={
                "_csrf": _token(page),
                "user_name": username,
                "email": email or f"{username}@example.invalid",
                "password": password,
                "retype": password,
            },
        )
        if status != 200 or "already been taken" in body:
            raise HTTPFailure("signup", status, body)

    def login(self, username: str, password: str) -> None:
        status, page = self.request("/user/login")
        if status != 200:
            raise HTTPFailure("login page", status, page)
        status, body = self.request(
            "/user/login",
            form={"_csrf": _token(page), "user_name": username, "password": password},
        )
        if status != 200 or 'href="/user/login"' in body:
            raise HTTPFailure("login", status, body)

    def assert_ordinary(self) -> None:
        status, body = self.request("/admin")
        if status != 403:
            raise HTTPFailure("ordinary-user boundary", status, body)

    def user_exists(self, username: str) -> bool:
        status, body = self.request(f"/api/v1/users/{urllib.parse.quote(username)}")
        if status not in (200, 404):
            raise HTTPFailure("user lookup", status, body)
        return status == 200

    def create_token(self, username: str, password: str, name: str) -> str:
        del username, password
        path = "/user/settings/applications"
        status, page = self.request(path)
        if status != 200:
            raise HTTPFailure("token settings", status, page)
        status, body = self.request(
            path,
            form={"_csrf": _token(page), "name": name},
        )
        if status != 200:
            raise HTTPFailure("token creation", status, body)
        tokens = [
            value
            for value in re.findall(r"\b[0-9a-f]{40}\b", body)
            if value != "e3bb4165dceb96b66053a067f9f3584302413a0e"
        ]
        if len(tokens) != 1:
            raise RuntimeError("token creation omitted token value")
        return tokens[0]

    def create_repo(
        self,
        username: str,
        repo: str,
        *,
        private: bool = False,
        description: str = "Software delivery notes",
    ) -> None:
        status, page = self.request("/repo/create")
        if status != 200:
            raise HTTPFailure("repository creation page", status, page)
        owner = re.search(r'name="user_id" value="([0-9]+)"', page)
        if not owner:
            raise RuntimeError("repository owner is absent")
        form = {
            "_csrf": _token(page),
            "user_id": owner.group(1),
            "repo_name": repo,
            "description": description,
            "readme": "Default",
        }
        if private:
            form["private"] = "on"
        status, body = self.request("/repo/create", form=form)
        if status != 200 or f"/{username}/{repo}" not in body:
            raise HTTPFailure("repository creation", status, body)

    def configure_pulls(self, username: str, repo: str) -> None:
        path = f"/{username}/{repo}/settings"
        status, page = self.request(path)
        if status != 200:
            raise HTTPFailure("repository settings", status, page)
        status, body = self.request(
            path,
            form={
                "_csrf": _token(page),
                "action": "advanced",
                "repo_name": repo,
                "enable_wiki": "on",
                "enable_issues": "on",
                "enable_pulls": "on",
                "pulls_allow_rebase": "on",
            },
        )
        if status != 200:
            raise HTTPFailure("pull workflow settings", status, body)

    def create_pr(
        self,
        username: str,
        repo: str,
        base: str,
        head: str,
        *,
        title: str = "Integrate current changes",
        content: str = "Review and integrate the proposed repository update.",
    ) -> None:
        compare = (
            f"/{username}/{repo}/compare/{urllib.parse.quote(base, safe='')}..."
            f"{urllib.parse.quote(head, safe='')}"
        )
        status, page = self.request(compare, timeout=60)
        if status != 200:
            raise HTTPFailure("pull request comparison", status, page)
        status, body = self.request(
            compare,
            form={
                "_csrf": _token(page),
                "title": title,
                "content": content,
            },
            timeout=90,
        )
        if status != 200:
            raise HTTPFailure("pull request creation", status, body)

    def merge_pr(
        self, username: str, repo: str, style: str, index: int = 1
    ) -> int:
        path = f"/{username}/{repo}/pulls/{index}"
        status, page = self.request(path, timeout=60)
        if status != 200:
            raise HTTPFailure("pull request page", status, page)
        status, _ = self.request(
            path + "/merge",
            form={"_csrf": _token(page), "merge_style": style},
            timeout=120,
        )
        return status

    def raw(self, username: str, repo: str, branch: str, filename: str) -> str:
        status, body = self.request(
            f"/{username}/{repo}/raw/{urllib.parse.quote(branch, safe='')}/"
            f"{urllib.parse.quote(filename, safe='')}",
            timeout=30,
        )
        if status != 200:
            raise HTTPFailure("raw repository content", status, body)
        return body

    def delete_repo(self, username: str, repo: str) -> None:
        path = f"/{username}/{repo}/settings"
        status, page = self.request(path)
        if status == 404:
            return
        if status != 200:
            raise HTTPFailure("repository deletion page", status, page)
        status, body = self.request(
            path,
            form={
                "_csrf": _token(page),
                "action": "delete",
                "repo_name": repo,
            },
        )
        if status != 200:
            raise HTTPFailure("repository deletion", status, body)

    def delete_account(self, password: str) -> None:
        status, page = self.request("/user/settings/delete")
        if status != 200:
            raise HTTPFailure("account deletion page", status, page)
        status, body = self.request(
            "/user/settings/delete",
            form={"_csrf": _token(page), "password": password},
        )
        if status != 200:
            raise HTTPFailure("account deletion", status, body)


def _remote(base: str, username: str, password: str, repo: str) -> str:
    parsed = urllib.parse.urlsplit(base)
    authority = (
        f"{urllib.parse.quote(username, safe='')}:"
        f"{urllib.parse.quote(password, safe='')}@{parsed.netloc}"
    )
    return urllib.parse.urlunsplit(
        (parsed.scheme, authority, f"/{username}/{repo}.git", "", "")
    )


def _git(directory: Path, *args: str, timeout: int = 90) -> str:
    return subprocess.run(
        ["git", "-C", str(directory), *args],
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    ).stdout.strip()


def push_fixture(
    base: str,
    username: str,
    token: str,
    repo: str,
    *,
    base_branch: str,
    head_branch: str,
    base_file: str,
    feature_file: str,
    base_content: str,
    feature_content: str,
    base_alias: str | None = None,
    author_name: str | None = None,
    author_email: str | None = None,
    initial_message: str = "Initial revision",
    feature_message: str = "Feature revision",
    base_message: str = "Base revision",
) -> dict[str, str]:
    directory = Path(tempfile.mkdtemp(prefix="gogs-flow-"))
    try:
        subprocess.run(
            ["git", "init", "-b", base_branch, str(directory)],
            check=True,
            capture_output=True,
            text=True,
        )
        _git(
            directory,
            "config",
            "user.email",
            author_email or f"{username}@example.invalid",
        )
        _git(directory, "config", "user.name", author_name or username)
        (directory / base_file).write_text("initial\n")
        _git(directory, "add", base_file)
        _git(directory, "commit", "-m", initial_message)
        initial = _git(directory, "rev-parse", "HEAD")
        _git(directory, "checkout", "-b", head_branch)
        (directory / feature_file).write_text(feature_content + "\n")
        _git(directory, "add", feature_file)
        _git(directory, "commit", "-m", feature_message)
        feature = _git(directory, "rev-parse", "HEAD")
        _git(directory, "checkout", base_branch)
        (directory / base_file).write_text(base_content + "\n")
        _git(directory, "commit", "-am", base_message)
        base_tip = _git(directory, "rev-parse", "HEAD")
        if base_alias:
            _git(directory, "update-ref", f"refs/heads/{base_alias}", "HEAD")
        _git(directory, "remote", "add", "origin", _remote(base, username, token, repo))
        refs = [base_branch, head_branch]
        if base_alias:
            refs.append(f"refs/heads/{base_alias}:refs/heads/{base_alias}")
        _git(directory, "push", "origin", *refs, timeout=120)
        return {"initial": initial, "feature": feature, "base": base_tip}
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def result_history(
    base: str, username: str, token: str, repo: str, branch: str
) -> list[str]:
    directory = Path(tempfile.mkdtemp(prefix="gogs-result-"))
    try:
        subprocess.run(
            [
                "git",
                "clone",
                "--quiet",
                "--branch",
                branch,
                "--single-branch",
                _remote(base, username, token, repo),
                str(directory),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
        return _git(directory, "rev-list", "--parents", "-n", "1", "HEAD").split()
    finally:
        shutil.rmtree(directory, ignore_errors=True)
