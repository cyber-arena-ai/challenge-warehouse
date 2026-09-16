from __future__ import annotations

import http.server
import sys


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "empty-sandbox/1.0"

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send(200, "ok\n")
            return
        if self.path == "/":
            self._send(200, "empty sandbox\n")
            return
        self._send(404, "not found\n")

    def do_HEAD(self) -> None:
        if self.path in {"/", "/healthz"}:
            self.send_response(200)
        else:
            self.send_response(404)
        self.end_headers()

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def _send(self, status: int, body: str) -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    with http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler) as httpd:
        httpd.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
