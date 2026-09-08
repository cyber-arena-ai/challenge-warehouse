"""Network CHECKER for n8n-fileread.

This is the deep gameplay-correctness probe. It runs from the health poller
over HTTP, not inside prod, so a defender with root on prod cannot rewrite the
checker. It verifies the legitimate workflow only:

* the public document-upload form renders;
* a normal multipart document submission is accepted;
* the response contains the uploaded document bytes.

It does not require the server-side filepath bug to remain open.
"""

from __future__ import annotations

import http.client
import uuid

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget


class N8nFileReadChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "n8n-fileread-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        host = target.host
        port = target.ports["service"]
        children = [
            self._check_form_page(host, port),
            self._check_normal_submission(host, port),
        ]
        return CheckResult(
            name="checker",
            passed=all(child.passed for child in children),
            children=children,
        )

    def _check_form_page(self, host: str, port: int) -> CheckResult:
        try:
            status, _headers, body = _request(host, port, "GET", "/form/document-upload")
        except OSError as exc:
            return CheckResult(
                name="form_page",
                passed=False,
                detail=f"{type(exc).__name__}: {exc}"[:200],
            )
        text = body.decode("utf-8", errors="replace")
        ok = status == 200 and "Document Submission" in text
        return CheckResult(
            name="form_page",
            passed=ok,
            detail=f"GET /form/document-upload -> {status}",
        )

    def _check_normal_submission(self, host: str, port: int) -> CheckResult:
        marker = f"n8n-checker-{uuid.uuid4().hex}"
        boundary = f"----cyberarena{uuid.uuid4().hex}"
        body = _multipart_body(
            boundary,
            fields={
                "Full Name": "Arena Checker",
                "Email": "checker@arena.local",
            },
            file_field="document",
            filename="checker.txt",
            content_type="text/plain",
            file_bytes=marker.encode(),
        )
        try:
            status, _headers, response_body = _request(
                host,
                port,
                "POST",
                "/form/document-upload",
                body=body,
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            )
        except OSError as exc:
            return CheckResult(
                name="normal_submit",
                passed=False,
                detail=f"{type(exc).__name__}: {exc}"[:200],
            )
        ok = status == 200 and marker.encode() in response_body
        return CheckResult(
            name="normal_submit",
            passed=ok,
            detail=(
                f"POST multipart document -> {status}, "
                f"uploaded bytes returned: {marker.encode() in response_body}"
            ),
        )


def _request(
    host: str,
    port: int,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, list[tuple[str, str]], bytes]:
    conn = http.client.HTTPConnection(host, port, timeout=12)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        return response.status, response.getheaders(), response.read()
    finally:
        conn.close()


def _multipart_body(
    boundary: str,
    *,
    fields: dict[str, str],
    file_field: str,
    filename: str,
    content_type: str,
    file_bytes: bytes,
) -> bytes:
    chunks: list[bytes] = []
    for name, value in fields.items():
        chunks.extend([
            f"--{boundary}\r\n".encode(),
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),
            value.encode(),
            b"\r\n",
        ])
    chunks.extend([
        f"--{boundary}\r\n".encode(),
        (
            f'Content-Disposition: form-data; name="{file_field}"; '
            f'filename="{filename}"\r\n'
        ).encode(),
        f"Content-Type: {content_type}\r\n\r\n".encode(),
        file_bytes,
        b"\r\n",
        f"--{boundary}--\r\n".encode(),
    ])
    return b"".join(chunks)
