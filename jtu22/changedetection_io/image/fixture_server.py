#!/usr/bin/env python3
"""Loopback-only benign web page used by normal watch workflows."""

from __future__ import annotations

import html
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path != "/page":
            self.send_error(404)
            return
        value = urllib.parse.parse_qs(parsed.query).get("value", ["operations"])[0]
        body = (
            "<!doctype html><html><head><title>Operations status</title></head>"
            f"<body><main id=\"watch-body\">{html.escape(value)}</main></body></html>"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 8081), Handler).serve_forever()
