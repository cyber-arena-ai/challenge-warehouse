"""Temporary participant-shaped source pages for native watch workflows."""

from __future__ import annotations

import contextlib
import html
import secrets
import socket
import string
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

_SECTION_TAGS = ("article", "section", "main", "aside", "div")
_FIELD_TAGS = ("p", "span", "div", "output")
_SECTION_ATTRIBUTES = ("data-section", "data-topic", "data-panel", "id", "class")
_FIELD_ATTRIBUTES = ("data-field", "data-value", "id", "class")
_TOPICS = ("notices", "status", "reports", "bulletins", "updates", "service")
_TITLES = (
    "Operations update",
    "Service notice",
    "Daily report",
    "Community bulletin",
)


def _route_address(target_host: str, target_port: int) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect((target_host, target_port))
        return str(probe.getsockname()[0])


def _slug(length: int) -> str:
    alphabet = string.ascii_letters + string.digits + "-_"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _fresh_page(marker: str) -> tuple[str, str, str]:
    section = secrets.choice(_TOPICS)
    section_tag = secrets.choice(_SECTION_TAGS)
    field_tag = secrets.choice(_FIELD_TAGS)
    section_attribute = secrets.choice(_SECTION_ATTRIBUTES)
    field_attribute = secrets.choice(_FIELD_ATTRIBUTES)
    section_value = f"{secrets.choice(_TOPICS)}-{_slug(9)}"
    field_value = f"{secrets.choice(('summary', 'message', 'body', 'entry'))}-{_slug(9)}"
    step = secrets.choice(("/", "//"))
    selected = (
        f"//{section_tag}[@{section_attribute}='{section_value}']"
        f"{step}{field_tag}[@{field_attribute}='{field_value}']"
    )
    selector = f"xpath:{secrets.choice(('string', 'normalize-space'))}({selected})"
    layout = (
        f'<{section_tag} {section_attribute}="{section_value}">'
        f'<{field_tag} {field_attribute}="{field_value}">{html.escape(marker)}</{field_tag}>'
        f"</{section_tag}>"
    )
    return section, selector, layout


@contextlib.contextmanager
def source_workflow(
    target_host: str, target_port: int
) -> Iterator[tuple[str, str, str]]:
    marker = (
        f"{secrets.choice(('North', 'Central', 'Regional', 'Evening'))} "
        f"{secrets.choice(('service', 'delivery', 'operations', 'platform'))} "
        f"update {secrets.randbelow(90000) + 10000}-{_slug(secrets.randbelow(5) + 7)}"
    )
    section, selector, layout = _fresh_page(marker)
    path = (
        f"/{section}/{secrets.choice(('daily', 'service', 'regional', 'public'))}-"
        f"{secrets.choice(('update', 'notice', 'report', 'status'))}-"
        f"{_slug(secrets.randbelow(7) + 6)}"
    )
    body = (
        f"<!doctype html><html><head><title>{secrets.choice(_TITLES)}</title></head>"
        f"<body>{layout}</body></html>"
    ).encode()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if self.path != path:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            del format, args

    source_host = _route_address(target_host, target_port)
    server = ThreadingHTTPServer((source_host, 0), Handler)
    server.daemon_threads = True
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        source_url = f"http://{source_host}:{server.server_port}{path}"
        yield source_url, selector, marker
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
