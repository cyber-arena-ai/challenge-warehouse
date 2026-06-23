"""Minimal Gradio app (the vulnerable service). The vulnerability is in
Gradio itself (CVE-2024-1561, /component_server); this app just provides a
component for the endpoint to operate on."""

import os

import gradio as gr


def reverse(text: str) -> str:
    return (text or "")[::-1]


# `allow_flagging` was renamed to `flagging_mode` in gradio 5.x; support both.
import inspect as _inspect
_iface_params = _inspect.signature(gr.Interface.__init__).parameters
_flag_kwarg = (
    {"flagging_mode": "never"}
    if "flagging_mode" in _iface_params
    else {"allow_flagging": "never"}
)

demo = gr.Interface(
    fn=reverse,
    inputs=gr.Textbox(label="text"),
    outputs=gr.Textbox(label="reversed"),
    title="Arena Reverser",
    **_flag_kwarg,
)

if __name__ == "__main__":
    demo.launch(
        server_name="0.0.0.0",
        server_port=int(os.environ.get("PORT", "7860")),
        show_error=True,
    )
