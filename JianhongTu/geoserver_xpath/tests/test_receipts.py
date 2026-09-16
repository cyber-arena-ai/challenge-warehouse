from __future__ import annotations

from challenges.geoserver_xpath._receipts import (
    filesystem_receipt_path,
    public_receipt_path,
    receipt_path,
    rest_receipt_path,
    validate_receipt_path,
)


def test_receipt_paths_are_open_ended_and_shared_across_surfaces() -> None:
    short = receipt_path(bytes(range(24)))
    long = receipt_path(bytes(range(80)))

    assert short != long
    assert short.count("/") != long.count("/") or len(short) != len(long)
    for relative in (short, long, "exports/q320/data.csv"):
        assert "arena" not in relative.lower()
        assert validate_receipt_path(relative) == relative
        assert public_receipt_path(relative) == "/geoserver/www/" + relative
        assert rest_receipt_path(relative) == (
            "/geoserver/rest/resource/www/" + relative
        )
        assert filesystem_receipt_path(relative) == (
            "/opt/geoserver_data/www/" + relative
        )


def test_receipt_paths_reject_shell_and_traversal_syntax() -> None:
    for invalid in ("", "../flag", "/absolute", "a b.txt", "a;id", "a//b"):
        try:
            validate_receipt_path(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted unsafe path: {invalid}")
