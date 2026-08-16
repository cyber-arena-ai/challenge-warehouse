from __future__ import annotations

import subprocess

import pytest

from jtu22.gogs import _gogs


def test_assert_rebased_tip_accepts_one_parent(monkeypatch):
    results = iter(
        (
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 0, "tip parent\n", ""),
        )
    )
    monkeypatch.setattr(_gogs.subprocess, "run", lambda *args, **kwargs: next(results))

    _gogs.assert_rebased_tip("http://gogs:3000", "user", "pass", "repo")


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
