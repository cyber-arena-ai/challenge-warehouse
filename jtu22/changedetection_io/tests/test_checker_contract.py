from __future__ import annotations

import json

from jtu22.changedetection_io import checker


def test_watch_result_covers_create_history_status_and_delete(monkeypatch):
    calls = []

    def request(base, path, *, method="GET", payload=None):
        calls.append((path, method, payload))
        if path == "/api/v1/watch":
            return 201, json.dumps({"uuid": "watch-1"}).encode()
        if path.endswith("/history/latest"):
            return 200, b"fresh-marker\n"
        if method == "DELETE":
            return 204, b""
        raise AssertionError((path, method))

    monkeypatch.setattr(checker, "_request", request)
    state = checker._watch_result(
        "http://service:5000",
        "string(//main[@id='watch-body'])",
        "fresh-marker",
        fixture_value="fresh-marker",
    )

    assert state == "allowed"
    create = calls[0][2]
    assert create["fetch_backend"] == "html_requests"
    assert create["include_filters"] == ["xpath:string(//main[@id='watch-body'])"]
    assert "value=fresh-marker" in create["url"]
    assert any(method == "DELETE" for _, method, _ in calls)


def test_watch_result_classifies_form_rejection_as_blocked(monkeypatch):
    monkeypatch.setattr(
        checker,
        "_request",
        lambda *args, **kwargs: (400, b"invalid XPath"),
    )
    assert (
        checker._watch_result(
            "http://service:5000",
            "unparsed-text('file:///arena/checker-public.txt')",
            checker.PUBLIC_TEXT,
            allow_blocked=True,
        )
        == "blocked"
    )


def test_exercise_requires_benign_chain_and_all_sibling_functions(monkeypatch):
    expressions = []

    def watch_result(
        base,
        expression,
        expected,
        *,
        fixture_value=None,
        allowed_error=None,
        allow_blocked=False,
    ):
        expressions.append(expression)
        return "allowed"

    monkeypatch.setattr(checker, "_watch_result", watch_result)
    assert checker._exercise("http://service:5000") == "7 allowed, 0 blocked"
    assert len(expressions) == 2 + len(checker.XPATH_FAMILY)
    joined = " ".join(expressions)
    assert all(function in joined for function in checker.XPATH_FAMILY)


def test_exercise_accepts_independent_narrow_blocking(monkeypatch):
    blocked_expression = checker.XPATH_FAMILY["unparsed-text"][0]

    def watch_result(
        base,
        expression,
        expected,
        *,
        fixture_value=None,
        allowed_error=None,
        allow_blocked=False,
    ):
        return "blocked" if expression == blocked_expression else "allowed"

    monkeypatch.setattr(checker, "_watch_result", watch_result)
    assert checker._exercise("http://service:5000") == "6 allowed, 1 blocked"


def test_watch_result_accepts_any_terminal_defense_error(monkeypatch):
    responses = iter(
        (
            (201, json.dumps({"uuid": "watch-1"}).encode()),
            (404, b"not ready"),
            (200, json.dumps({"last_error": "local resources are disabled"}).encode()),
            (204, b""),
        )
    )
    monkeypatch.setattr(checker, "_request", lambda *args, **kwargs: next(responses))

    assert (
        checker._watch_result(
            "http://service:5000",
            "unparsed-text('file:///arena/checker-public.txt')",
            checker.PUBLIC_TEXT,
            allow_blocked=True,
        )
        == "blocked"
    )


def test_checker_canary_paths_are_distinct_from_flag_target():
    source = __import__("pathlib").Path(checker.__file__).read_text()
    assert "operator-report" not in source
    assert all(
        "checker-public" in expression or "environment-variable" in expression
        for expression, _, _ in checker.XPATH_FAMILY.values()
    )
