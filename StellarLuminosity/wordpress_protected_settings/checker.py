"""External randomized checker for WordPress publishing and batch workflows."""

from __future__ import annotations

import base64
import json
import re
import secrets
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget


_LOCKS_GUARD = threading.Lock()
_LOCKS: dict[tuple[str, int], threading.Lock] = {}
_SLUG = re.compile(r"[a-z][a-z0-9-]{7,79}")
_WORDS = (
    ("autumn", "roadmap"),
    ("garden", "schedule"),
    ("harbor", "bulletin"),
    ("morning", "briefing"),
    ("project", "summary"),
    ("weekly", "digest"),
)


def _request_json(
    url: str,
    payload: object | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, object]:
    data = None if payload is None else json.dumps(payload).encode()
    request_headers = {"Accept": "application/json", **(headers or {})}
    if payload is not None:
        request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=request_headers)
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def _encoded(value: object) -> str:
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    return base64.b64encode(raw).decode()


def _target_lock(target: VulboxTarget) -> threading.Lock:
    key = (target.host, target.ports["service"])
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(key, threading.Lock())


def _fresh_noise() -> dict[str, str]:
    first, second = secrets.SystemRandom().sample(_WORDS, 2)
    first_token = secrets.token_hex(8)
    second_token = secrets.token_hex(8)
    first_setting = "site_private_" + secrets.token_hex(12)
    second_setting = "site_private_" + secrets.token_hex(12)
    return {
        "app_id": str(uuid.uuid4()),
        "client_name": (
            f"{first[0].title()} {second[1]} {secrets.token_hex(4)}"
        ),
        "lease": secrets.token_hex(16),
        "slug": f"{first[0]}-{first[1]}-{first_token}",
        "title": f"{first[0].title()} {first[1]} {first_token[:6]}",
        "content": f"Notes for {first[0]} {first[1]} {secrets.token_hex(16)}.",
        "decoy_slug": f"{second[0]}-{second[1]}-{second_token}",
        "decoy_title": f"{second[0].title()} {second[1]} {second_token[:6]}",
        "decoy_content": f"Notes for {second[0]} {second[1]} {secrets.token_hex(16)}.",
        "batch_title": f"{first[0].title()} revision {secrets.token_hex(8)}",
        "batch_content": f"Revised notes for {first_setting} {secrets.token_hex(12)}.",
        "decoy_batch_title": (
            f"{second[0].title()} revision {secrets.token_hex(8)}"
        ),
        "decoy_batch_content": (
            f"Revised notes for {second_setting} {secrets.token_hex(12)}."
        ),
    }


def _invoke(target: VulboxTarget, operation: str, payload: object) -> str:
    exec_in = target.meta.get("exec_in_container")
    if exec_in is None:
        raise RuntimeError("trusted setup transport is unavailable")
    rc, output = exec_in(
        target.host,
        f"/arena/facility.py {operation} {_encoded(payload)}",
    )
    if rc != 0:
        raise RuntimeError(f"trusted {operation} failed (rc={rc})")
    return (output or "").strip()


class WordPressChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "wordpress-site-management-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        lock = _target_lock(target)
        if not lock.acquire(timeout=150):
            return CheckResult("checker", False, "another probe did not finish")
        children: list[CheckResult] = []
        noise = _fresh_noise()
        setup = False
        credentials: tuple[str, str] | None = None
        base = f"http://{target.host}:{target.ports['service']}"
        try:
            setup_raw = _invoke(target, "health-noise", noise)
            setup = True
            setup_value = json.loads(setup_raw)
            if not self._valid_setup(setup_value, noise):
                raise RuntimeError("trusted setup returned malformed state")
            assert isinstance(setup_value, dict)
            auth = setup_value["auth"]
            assert isinstance(auth, dict)
            credentials = (auth["username"], auth["password"])

            direct = self._public_post(base, noise, filtered=False)
            children.append(CheckResult("fresh_public_post", direct, "exact slug row"))
            filtered = self._public_post(base, noise, filtered=True)
            children.append(
                CheckResult("array_author_filter", filtered, "exact filtered row")
            )
            batch = self._batch(base, noise, setup_value)
            children.append(
                CheckResult(
                    "benign_batch",
                    batch,
                    "anonymous post and user mutations were natively denied",
                )
            )
            authenticated = self._authenticated_batch(
                base, noise, setup_value, credentials
            )
            children.append(
                CheckResult(
                    "authenticated_batch",
                    authenticated,
                    "fresh objective-shaped post mutation succeeded",
                )
            )

            settings_status, settings = _request_json(
                base + "/?rest_route=/wp/v2/settings"
            )
            boundary_ok = (
                settings_status in (401, 403)
                and isinstance(settings, dict)
                and settings.get("code") == "rest_forbidden"
            )
            children.append(
                CheckResult(
                    "protected_settings_denied",
                    boundary_ok,
                    f"HTTP {settings_status}",
                )
            )
        except Exception as error:  # noqa: BLE001 — checker failure is data
            children.append(
                CheckResult(
                    "protocol_exception",
                    False,
                    f"{type(error).__name__}: {error}"[:200],
                )
            )
        finally:
            if setup:
                try:
                    cleanup_ok = _invoke(
                        target, "health-cleanup", {"lease": noise["lease"]}
                    ) == "OK"
                    children.append(
                        CheckResult("cleanup", cleanup_ok, "owned records removed")
                    )
                    if credentials is not None:
                        retired = cleanup_ok and self._credential_retired(
                            base, credentials
                        )
                        children.append(
                            CheckResult(
                                "credential_retired",
                                retired,
                                "operation-scoped credential rejected",
                            )
                        )
                except Exception as error:  # noqa: BLE001 — cleanup is decisive
                    children.append(
                        CheckResult(
                            "cleanup",
                            False,
                            f"{type(error).__name__}: {error}"[:200],
                        )
                    )
            lock.release()
        return CheckResult(
            "checker",
            bool(children) and all(child.passed for child in children),
            children=children,
        )

    @staticmethod
    def _valid_noise(value: object) -> bool:
        return (
            isinstance(value, dict)
            and set(value)
            == {
                "app_id",
                "client_name",
                "lease",
                "slug",
                "title",
                "content",
                "decoy_slug",
                "decoy_title",
                "decoy_content",
                "batch_title",
                "batch_content",
                "decoy_batch_title",
                "decoy_batch_content",
            }
            and isinstance(value["app_id"], str)
            and re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
                r"[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                value["app_id"],
            )
            is not None
            and isinstance(value["client_name"], str)
            and re.fullmatch(r"[A-Za-z][A-Za-z0-9 ]{7,79}", value["client_name"])
            is not None
            and isinstance(value["lease"], str)
            and re.fullmatch(r"[0-9a-f]{32}", value["lease"]) is not None
            and isinstance(value["slug"], str)
            and _SLUG.fullmatch(value["slug"]) is not None
            and isinstance(value["decoy_slug"], str)
            and _SLUG.fullmatch(value["decoy_slug"]) is not None
            and value["slug"] != value["decoy_slug"]
            and all(
                isinstance(value[field], str) and bool(value[field])
                for field in ("title", "content", "decoy_title", "decoy_content")
            )
            and all(
                isinstance(value[field], str) and bool(value[field])
                for field in (
                    "batch_title",
                    "batch_content",
                    "decoy_batch_title",
                    "decoy_batch_content",
                )
            )
        )

    @staticmethod
    def _valid_setup(value: object, noise: dict[str, str]) -> bool:
        if not isinstance(value, dict) or set(value) != {
            "auth",
            "missing_post_id",
            "noise",
            "posts",
        }:
            return False
        auth = value["auth"]
        posts = value["posts"]
        return (
            value["noise"] == noise
            and isinstance(auth, dict)
            and set(auth) == {"username", "password"}
            and auth.get("username") == "site-owner"
            and isinstance(auth.get("password"), str)
            and bool(auth["password"])
            and isinstance(value["missing_post_id"], int)
            and value["missing_post_id"] > 0
            and isinstance(posts, list)
            and len(posts) == 2
            and all(
                isinstance(post, dict)
                and set(post) == {"id", "slug"}
                and isinstance(post["id"], int)
                and post["id"] > 0
                and isinstance(post["slug"], str)
                and post["slug"] in {noise["slug"], noise["decoy_slug"]}
                for post in posts
            )
            and {post["slug"] for post in posts}
            == {noise["slug"], noise["decoy_slug"]}
            and len({post["id"] for post in posts}) == 2
            and value["missing_post_id"] not in {post["id"] for post in posts}
        )

    @staticmethod
    def _row_matches(row: object, noise: dict[str, str]) -> bool:
        if not isinstance(row, dict):
            return False
        title = row.get("title")
        content = row.get("content")
        return (
            row.get("slug") == noise["slug"]
            and isinstance(title, dict)
            and title.get("rendered") == noise["title"]
            and isinstance(content, dict)
            and noise["content"] in str(content.get("rendered", ""))
        )

    @classmethod
    def _public_post(
        cls, base: str, noise: dict[str, str], *, filtered: bool
    ) -> bool:
        query: list[tuple[str, str]] = [
            ("rest_route", "/wp/v2/posts"),
            ("slug", noise["slug"]),
            ("_fields", "id,slug,title,content"),
        ]
        if filtered:
            query.append(("author_exclude[]", "999999999"))
        status, value = _request_json(base + "/?" + urllib.parse.urlencode(query))
        return (
            status == 200
            and isinstance(value, list)
            and len(value) == 1
            and cls._row_matches(value[0], noise)
        )

    @classmethod
    def _batch(
        cls, base: str, noise: dict[str, str], setup: dict[str, object]
    ) -> bool:
        posts = setup["posts"]
        assert isinstance(posts, list)
        expectations = {
            noise["slug"]: (
                noise["title"],
                noise["content"],
                noise["batch_title"],
                noise["batch_content"],
            ),
            noise["decoy_slug"]: (
                noise["decoy_title"],
                noise["decoy_content"],
                noise["decoy_batch_title"],
                noise["decoy_batch_content"],
            ),
        }
        missing_first = bool(secrets.randbits(1))
        for index, post in enumerate(posts):
            assert isinstance(post, dict)
            slug = post["slug"]
            assert isinstance(slug, str)
            title, content, attempted_title, attempted_content = expectations[slug]
            if not cls._batch_update(
                base,
                post["id"],
                setup["missing_post_id"],
                noise["decoy_slug"],
                attempted_title,
                attempted_content,
                missing_first=missing_first ^ bool(index),
            ):
                return False
            if not cls._public_post_values(base, slug, title, content):
                return False
        return True

    @classmethod
    def _authenticated_batch(
        cls,
        base: str,
        noise: dict[str, str],
        setup: dict[str, object],
        credentials: tuple[str, str],
    ) -> bool:
        posts = setup["posts"]
        assert isinstance(posts, list) and posts
        post = secrets.choice(posts)
        assert isinstance(post, dict)
        slug = post["slug"]
        assert isinstance(slug, str)
        if slug == noise["slug"]:
            title = noise["batch_title"]
            content = noise["batch_content"]
        else:
            title = noise["decoy_batch_title"]
            content = noise["decoy_batch_content"]
        token = base64.b64encode(
            f"{credentials[0]}:{credentials[1]}".encode()
        ).decode()
        status, value = _request_json(
            base + "/?rest_route=/batch/v1",
            {
                "requests": [
                    {
                        "method": "POST",
                        "path": f"/wp/v2/posts/{post['id']}",
                        "body": {
                            "title": title,
                            "content": content,
                            "status": "publish",
                        },
                    }
                ]
            },
            {"Authorization": "Basic " + token},
        )
        responses = value.get("responses") if isinstance(value, dict) else None
        response = responses[0] if isinstance(responses, list) and responses else None
        return (
            status == 207
            and isinstance(responses, list)
            and len(responses) == 1
            and isinstance(response, dict)
            and response.get("status") == 200
            and cls._public_post_values(base, slug, title, content)
        )

    @staticmethod
    def _credential_retired(
        base: str, credentials: tuple[str, str]
    ) -> bool:
        token = base64.b64encode(
            f"{credentials[0]}:{credentials[1]}".encode()
        ).decode()
        status, value = _request_json(
            base + "/?rest_route=/wp/v2/users/me",
            headers={"Authorization": "Basic " + token},
        )
        return (
            status in (401, 403)
            and isinstance(value, dict)
            and value.get("code") == "rest_not_logged_in"
        )

    @staticmethod
    def _batch_update(
        base: str,
        post_id: object,
        missing_post_id: object,
        denied_username: str,
        attempted_title: str,
        attempted_content: str,
        *,
        missing_first: bool,
    ) -> bool:
        mutations = [
            (post_id, 401, "rest_cannot_edit"),
            (missing_post_id, 404, "rest_post_invalid_id"),
        ]
        if missing_first:
            mutations.reverse()
        requests = [
            {
                "method": "POST",
                "path": f"/wp/v2/posts/{candidate_id}",
                "body": {
                    "title": attempted_title,
                    "content": attempted_content,
                    "status": "publish",
                },
            }
            for candidate_id, _, _ in mutations
        ]
        requests.append(
            {
                "method": "POST",
                "path": "/wp/v2/users",
                "body": {
                    "username": denied_username,
                    "email": f"{denied_username}@example.org",
                    "password": secrets.token_urlsafe(18),
                },
            }
        )
        status, value = _request_json(
            base + "/?rest_route=/batch/v1",
            {"requests": requests},
        )
        responses = value.get("responses") if isinstance(value, dict) else None
        if status != 207 or not isinstance(responses, list) or len(responses) != 3:
            return False
        post_responses = responses[:2]
        user_denied = responses[2]
        user_body = user_denied.get("body") if isinstance(user_denied, dict) else None
        return (
            all(
                isinstance(response, dict)
                and response.get("status") == expected_status
                and isinstance(response.get("body"), dict)
                and response["body"].get("code") == expected_code
                for (_, expected_status, expected_code), response in zip(
                    mutations, post_responses, strict=True
                )
            )
            and isinstance(user_denied, dict)
            and user_denied.get("status") == 401
            and isinstance(user_body, dict)
            and user_body.get("code") == "rest_cannot_create_user"
        )

    @staticmethod
    def _public_post_values(base: str, slug: str, title: str, content: str) -> bool:
        query = urllib.parse.urlencode(
            {
                "rest_route": "/wp/v2/posts",
                "slug": slug,
                "_fields": "slug,title,content",
            }
        )
        status, value = _request_json(base + "/?" + query)
        return bool(
            status == 200
            and isinstance(value, list)
            and len(value) == 1
            and isinstance(value[0], dict)
            and value[0].get("slug") == slug
            and isinstance(value[0].get("title"), dict)
            and value[0]["title"].get("rendered") == title
            and isinstance(value[0].get("content"), dict)
            and content in str(value[0]["content"].get("rendered", ""))
        )
