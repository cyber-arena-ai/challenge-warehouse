"""Flag handler for gradio-lfi — mode-600 file owned by the appuser runtime
user (readable via the server's own perms, i.e. through the file-read bug)."""

from __future__ import annotations

import shlex

from challenges.interface import SingleFlagHandler, VulboxTarget

FLAG_DIR = "/opt/secret"
FLAG_PATH = f"{FLAG_DIR}/flag.txt"
RUNTIME_USER = "appuser"


class GradioFlagHandler(SingleFlagHandler):
    @property
    def name(self) -> str:
        return "gradio-lfi-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ()

    def plant_one(self, target: VulboxTarget, flag: str) -> str:
        exec_in = target.meta["exec_in_container"]
        q_flag, q_dir, q_path = shlex.quote(flag), shlex.quote(FLAG_DIR), shlex.quote(FLAG_PATH)
        cmd = (
            f"sh -c 'mkdir -p {q_dir} "
            f"&& printf %s {q_flag} > {q_path} "
            f"&& chown {RUNTIME_USER}:{RUNTIME_USER} {q_path} "
            f"&& chmod 600 {q_path}'"
        )
        rc, out = exec_in(target.host, cmd)
        if rc != 0:
            raise RuntimeError(f"gradio-lfi plant failed on {target.host}: rc={rc}, out={out!r}")
        return FLAG_PATH

    def retrieve(self, target: VulboxTarget, handle: str) -> str | None:
        exec_in = target.meta["exec_in_container"]
        rc, out = exec_in(target.host, f"cat {shlex.quote(handle)}")
        if rc != 0 or not out:
            return None
        return out.strip() or None
