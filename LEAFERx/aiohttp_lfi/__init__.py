"""aiohttp-lfi — aiohttp static-route directory traversal (CVE-2024-23334).

A minimal real-world service built on aiohttp 3.9.1: a static file server
that sets ``follow_symlinks=True`` on its `/static/` route. On aiohttp
<= 3.9.1 that disables the path-containment check, so a ``../`` traversal
reads arbitrary files the server process can access — no symlink needed.

  Flag    : /opt/secret/flag.txt (mode 600, owned by the `appuser` runtime
            user). No legitimate route serves it.
  Attack  : GET --path-as-is /static/../../../../opt/secret/flag.txt
  Defense : edit /srv/challenge/server.py to drop follow_symlinks=True (or
            validate the resolved path stays under the static root), then
            restart_service. The CHECKER fetches a legit in-root static
            file, so removing the traversal keeps it green.
"""

from .challenge import AiohttpLfiChallenge

__all__ = ["AiohttpLfiChallenge"]
