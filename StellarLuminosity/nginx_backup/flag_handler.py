"""Flag handler for nginx-backup.

plant  — writes FlagToken = <flag> into /etc/nginx-ui/app.ini.
         nginx-ui's backup includes app.ini verbatim, so the planted
         flag is always present in the encrypted archive the attacker
         downloads. go-ini (used by nginx-ui) preserves unknown keys
         when writing its own settings, so the FlagToken survives
         nginx-ui rewriting JwtSecret / NodeSecret on startup.

retrieve — reads FlagToken back out of app.ini via grep.

Both methods use docker exec (exec_in_container); no port access needed.
"""

from __future__ import annotations

from challenges.interface import (
    FlagObservation,
    SingleFlagHandler,
    VulboxTarget,
    exec_read_observe,
)

APP_INI_PATH = "/etc/nginx-ui/app.ini"


class NginxBackupFlagHandler(SingleFlagHandler):
    @property
    def name(self) -> str:
        return "nginx-backup-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ()

    def plant_one(self, target: VulboxTarget, flag: str) -> str:
        """Insert or replace FlagToken in app.ini. Returns the file path."""
        exec_in = target.meta["exec_in_container"]
        py = "\n".join([
            "import re, pathlib",
            f"flag = {flag!r}",
            f"p = pathlib.Path({APP_INI_PATH!r})",
            "t = p.read_text() if p.exists() else '[server]\\n'",
            "if re.search(r'^FlagToken\\s*=', t, re.MULTILINE):",
            "    t = re.sub(r'^FlagToken\\s*=.*', 'FlagToken = ' + flag, t, flags=re.MULTILINE)",
            "else:",
            "    t = t.rstrip() + '\\nFlagToken = ' + flag + '\\n'",
            "p.write_text(t)",
        ])
        rc, out = exec_in(target.host, f"python3 -c {_q(py)}")
        if rc != 0:
            raise RuntimeError(
                f"nginx-backup plant_flag failed on {target.host}: "
                f"rc={rc}, out={out!r}"
            )
        return APP_INI_PATH

    def retrieve(self, target: VulboxTarget, handle: str,
                 expected: str | None = None) -> FlagObservation:
        """Read-only structured read of FlagToken from app.ini. `sed` prints only
        the token VALUE (so `.value` is the bare flag, not the `FlagToken = …`
        line), enabling an exact PRESENT/MISMATCH compare; no match / missing file
        → NOT_FOUND; box unreachable → ERROR."""
        read = f"sed -n 's/^FlagToken[[:space:]]*=[[:space:]]*//p' {handle}"
        return exec_read_observe(target, read, expected)


def _q(s: str) -> str:
    """Wrap a multi-line string for `bash -c '...'`."""
    return "'" + s.replace("'", "'\\''") + "'"
