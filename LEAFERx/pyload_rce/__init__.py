"""pyload-rce — pyLoad js2py sandbox-escape RCE (CVE-2024-28397 / CVE-2024-39205).

pyLoad's /flash/addcrypted2 endpoint evaluates the attacker-supplied `jk`
JavaScript via js2py. CVE-2024-28397 escapes the js2py sandbox to reach
subprocess.Popen → arbitrary command execution. The endpoint's localhost
guard is bypassed with an `Host: 127.0.0.1:9666` header (CVE-2024-39205).
Pinned to a js2py-using version (pyload-ng 0.5.0b3.dev79); newer releases
switched to a V8 sandbox.

  Flag    : /opt/secret/flag.txt (mode 600, owned by the `pyload` user).
  Attack  : POST /flash/addcrypted2 with a js2py-escape `jk` running a
            command that reads the flag and submits it (RCE on the victim).
  Defense : edit /srv/challenge/pyload/.../cnl_blueprint.py to stop evaluating
            `jk` (or harden eval_js), then restart_service.
"""

from .challenge import PyloadRceChallenge

__all__ = ["PyloadRceChallenge"]
