"""Minimal Chrome DevTools client for executing the served Nginx UI frontend."""

from __future__ import annotations

import http.client
import json
import socket
import subprocess
import time
from types import TracebackType
from typing import Any

from websockets.sync.client import ClientConnection, connect


class HeadlessPage:
    def __init__(self) -> None:
        self._command_id = 0
        self._process: subprocess.Popen[bytes] | None = None
        self._socket: ClientConnection | None = None

    def __enter__(self) -> HeadlessPage:
        debug_port = _loopback_port()
        self._process = subprocess.Popen(
            [
                "chromium-headless-shell",
                "--headless",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-background-networking",
                "--disable-blink-features=AutomationControlled",
                "--no-first-run",
                "--remote-debugging-address=127.0.0.1",
                f"--remote-debugging-port={debug_port}",
                "about:blank",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            target = _wait_for_page(debug_port)
            self._socket = connect(
                target["webSocketDebuggerUrl"],
                open_timeout=5,
                close_timeout=2,
            )
            self.command(
                "Network.setUserAgentOverride",
                {
                    "userAgent": (
                        "Mozilla/5.0 (X11; Linux x86_64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/151.0.0.0 Safari/537.36"
                    )
                },
            )
            return self
        except Exception:
            self.close()
            raise

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        connection = self._socket
        process = self._process
        self._socket = None
        self._process = None
        try:
            if connection is not None:
                connection.close()
        finally:
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

    def command(self, method: str, params: dict[str, Any] | None = None) -> dict:
        if self._socket is None:
            raise RuntimeError("Nginx UI headless browser is not connected")
        self._command_id += 1
        command_id = self._command_id
        self._socket.send(
            json.dumps(
                {"id": command_id, "method": method, "params": params or {}},
                separators=(",", ":"),
            )
        )
        while True:
            response = json.loads(self._socket.recv(timeout=30))
            if response.get("id") != command_id:
                continue
            if "error" in response:
                raise RuntimeError("Nginx UI browser command failed")
            result = response.get("result", {})
            if not isinstance(result, dict):
                raise RuntimeError("Nginx UI browser returned malformed data")
            return result

    def navigate(self, url: str) -> None:
        result = self.command("Page.navigate", {"url": url})
        if "errorText" in result:
            raise RuntimeError("Nginx UI browser navigation failed")

    def evaluate(self, expression: str) -> Any:
        result = self.command(
            "Runtime.evaluate",
            {"expression": expression, "returnByValue": True},
        )
        if "exceptionDetails" in result:
            raise RuntimeError("Nginx UI browser evaluation failed")
        remote = result.get("result", {})
        if not isinstance(remote, dict):
            raise RuntimeError("Nginx UI browser returned malformed data")
        return remote.get("value")


def _loopback_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _wait_for_page(port: int) -> dict:
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        try:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            try:
                connection.request("GET", "/json/list")
                response = connection.getresponse()
                raw = response.read()
            finally:
                connection.close()
            targets = json.loads(raw) if response.status == 200 else []
            for target in targets:
                if (
                    isinstance(target, dict)
                    and target.get("type") == "page"
                    and isinstance(target.get("webSocketDebuggerUrl"), str)
                ):
                    return target
        except (OSError, json.JSONDecodeError):
            pass
        time.sleep(0.05)
    raise RuntimeError("Nginx UI headless browser did not start")
