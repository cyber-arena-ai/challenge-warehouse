"""marimo-rce — marimo `/terminal/ws` unauthenticated RCE (CVE-2026-39987).

marimo's `/terminal/ws` WebSocket exposes an interactive PTY shell but — unlike
every other WebSocket in the app — never calls `validate_auth()`. So even on a
token-protected marimo (where running notebook cells requires the token), an
unauthenticated client gets a full shell as the marimo process user. Affected
<= 0.20.4, fixed in 0.23.0.

  Flag    : /opt/secret/flag.txt (mode 600, owned by the `marimo` user). The
            only way to read it is code-exec as marimo — the server is
            token-protected (no cell exec without the token) and nothing
            serves /opt/secret, so the unauth terminal RCE is the sole path.
  Attack  : WebSocket /terminal/ws -> `cat /opt/secret/flag.txt` -> the flag
            comes straight back in the terminal output.
  Defense : add the missing `validate_auth()` guard to (or disable) the
            terminal handler in
            /srv/challenge/marimo/_server/api/endpoints/terminal.py, then
            restart_service. /health stays public, so the CHECKER passes.
"""

from .challenge import MarimoRceChallenge

__all__ = ["MarimoRceChallenge"]
