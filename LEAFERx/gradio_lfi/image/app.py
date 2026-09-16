"""Authenticated Gradio workspace used by the arena service."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import tempfile

import gradio as gr


ACCOUNTS = Path("/var/lib/gradio-arena/accounts.json")
PUBLIC = "/var/lib/gradio-arena/public"
DOCUMENT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{2,95}")


def authenticate(username: str, password: str) -> bool:
    try:
        value = json.loads(ACCOUNTS.read_text(encoding="utf-8"))
    except (OSError, TypeError, json.JSONDecodeError):
        return False
    return isinstance(value, dict) and value.get(username) == password


def reverse_text(value: str) -> str:
    return (value or "")[::-1]


def publish_document(name: str, content: str) -> str:
    name = (name or "").strip()
    content = content or ""
    if DOCUMENT_NAME.fullmatch(name) is None or not content or len(content) > 4096:
        raise ValueError("invalid workspace document")
    destination = Path(PUBLIC) / name
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", prefix=".workspace-", dir=PUBLIC, delete=False
    ) as stream:
        stream.write(content)
        temporary = Path(stream.name)
    try:
        temporary.chmod(0o400)
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return name


with gr.Blocks(title="Arena Workspace") as demo:
    gr.Markdown("# Arena Workspace")
    with gr.Row():
        source = gr.Textbox(label="Input")
        result = gr.Textbox(label="Reversed")
    reverse_button = gr.Button("Reverse")
    reverse_button.click(reverse_text, source, result, api_name="reverse")
    document_name = gr.Textbox(label="Document name")
    document_content = gr.Textbox(label="Document content")
    published_name = gr.Textbox(label="Published document", interactive=False)
    publish_button = gr.Button("Publish document")
    publish_button.click(
        publish_document,
        [document_name, document_content],
        published_name,
        api_name="publish_document",
    )
    gr.FileExplorer(
        root=PUBLIC,
        glob="**/*",
        file_count="multiple",
        label="Workspace documents",
    )


if __name__ == "__main__":
    demo.launch(
        server_name="0.0.0.0",
        server_port=int(os.environ.get("PORT", "7860")),
        auth=authenticate,
        show_api=True,
        show_error=True,
    )
