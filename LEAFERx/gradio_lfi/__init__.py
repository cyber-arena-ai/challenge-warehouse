"""gradio-lfi — Gradio component_server arbitrary file read (CVE-2024-1561).

Gradio 3.47–4.12 expose `/component_server`, which invokes an arbitrary
method on a component with attacker-controlled args. Calling
`move_resource_to_block_cache(<path>)` copies any file the server can read
into the served cache; the returned path is then fetched via `/file=`.

  Flag    : /opt/secret/flag.txt (mode 600, owned by `appuser`).
  Attack  : POST /component_server (move_resource_to_block_cache) then GET /file=.
  Defense : edit /srv/challenge/gradio/routes.py to restrict component_server
            to safe methods (the 4.13 fix), then restart_service.
"""

from .challenge import GradioLfiChallenge

__all__ = ["GradioLfiChallenge"]
