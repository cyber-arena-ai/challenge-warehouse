"""Accept the arena's underscore ingress hostnames in Starlette redirects."""

from __future__ import annotations

import re

import starlette.datastructures


starlette.datastructures._HOST_RE = re.compile(  # noqa: SLF001
    r"^([a-z0-9._-]+|\[[a-f0-9]*:[a-f0-9.:]+\])(?::[0-9]+)?$"
)
