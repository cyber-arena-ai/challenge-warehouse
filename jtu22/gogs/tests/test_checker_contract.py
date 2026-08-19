from __future__ import annotations

import subprocess

import pytest

# isort: split
from challenges.interface import VulboxTarget

# isort: split
from jtu22.gogs import _gogs, checker


def test_assert_rebased_tip_accepts_one_parent(monkeypatch):
    results = iter(
        (
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 0, "tip parent\n", ""),
        )
    )
    monkeypatch.setattr(_gogs.subprocess, "run", lambda *args, **kwargs: next(results))

    _gogs.assert_rebased_tip(
        "http://gogs:3000",
        "user",
        "pass",
        "repo",
        expected_parent="parent",
    )


def test_assert_rebased_tip_rejects_merge_commit(monkeypatch):
    results = iter(
        (
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 0, "tip parent-a parent-b\n", ""),
        )
    )
    monkeypatch.setattr(_gogs.subprocess, "run", lambda *args, **kwargs: next(results))

    with pytest.raises(RuntimeError, match="not a linear rebase result"):
        _gogs.assert_rebased_tip("http://gogs:3000", "user", "pass", "repo")


def test_assert_rebased_tip_rejects_rewritten_base(monkeypatch):
    results = iter(
        (
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 0, "tip wrong-parent\n", ""),
        )
    )
    monkeypatch.setattr(_gogs.subprocess, "run", lambda *args, **kwargs: next(results))

    with pytest.raises(RuntimeError, match="original base tip"):
        _gogs.assert_rebased_tip(
            "http://gogs:3000",
            "user",
            "pass",
            "repo",
            expected_parent="expected-parent",
        )


@pytest.mark.parametrize(
    ("feature_present", "base_present", "expected"),
    [(True, True, True), (False, True, False), (True, False, False)],
)
def test_checker_requires_both_sides_of_the_rebase(
    monkeypatch, feature_present, base_present, expected
):
    slugs = iter(
        ("alice7", "project9", "base3", "topic4", "basefile5", "feature6")
    )
    seen = {}

    class Client:
        def __init__(self, base):
            seen["base"] = base

        def sign_up(self, username, password):
            return None

        def login(self, username, password):
            return None

        def assert_ordinary(self):
            return None

        def create_repo(self, username, repo):
            return None

        def enable_rebase(self, username, repo):
            return None

        def create_pr(self, username, repo, base_branch, head_branch):
            seen["branches"] = (base_branch, head_branch)

        def merge_pr(self, username, repo):
            return 200

        def raw(self, username, repo, branch, filename):
            if filename == seen["feature_file"]:
                if feature_present:
                    return seen["feature_marker"] + "\n"
                return "wrong feature result\n"
            return (seen["base_marker"] + "\n") if base_present else "baseline\n"

    def push_fixture(*args, **kwargs):
        seen["feature_marker"] = args[4]
        seen["base_marker"] = kwargs["base_marker"]
        seen["base_file"] = kwargs["base_file"]
        seen["feature_file"] = kwargs["feature_file"]
        return _gogs.FixtureHistory("initial-tip", "feature-tip", "base-tip")

    def assert_rebased_tip(*args, **kwargs):
        seen["expected_parent"] = kwargs["expected_parent"]

    monkeypatch.setattr(checker, "resolve_host", lambda target: "gogs")
    monkeypatch.setattr(checker, "random_slug", lambda length=16: next(slugs))
    monkeypatch.setattr(checker, "random_password", lambda: "Pw-random")
    markers = iter(("feature-marker", "base-marker"))
    monkeypatch.setattr(checker, "random_marker", lambda: next(markers))
    monkeypatch.setattr(checker, "GogsClient", Client)
    monkeypatch.setattr(checker, "push_fixture", push_fixture)
    monkeypatch.setattr(checker, "assert_rebased_tip", assert_rebased_tip)

    result = checker.GogsChecker().run(
        VulboxTarget(host="gogs", ports={"service": 3000})
    )

    assert result.passed is expected
    assert seen["branches"] == ("base3", "topic4")
    if expected:
        assert seen["expected_parent"] == "base-tip"


def test_shared_random_values_have_no_checker_only_prefix():
    values = {_gogs.random_slug() for _ in range(20)}

    assert len(values) == 20
    assert all(len(value) == 16 and value.isalnum() for value in values)
    assert all(
        not value.startswith(("check", "flow", "hunt", "fresh")) for value in values
    )
    assert _gogs.random_password().startswith("Pw-")
    assert len(_gogs.random_marker()) == 32
