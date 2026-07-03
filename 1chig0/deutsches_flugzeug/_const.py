"""Shared constants for deutsches-flugzeug — stdlib only, no 3rd-party imports.

Kept dependency-free so that importing `prompts.py` (which renders agent prompts)
does not drag in `httpx` or any other library that only the host-side flag/check
handlers need. Both `prompts.py` and `flag_handler.py` import from here.
"""

from __future__ import annotations

# The fixed, PUBLIC username whose flight stores the flag in its VIP boarding
# info. Named in the attack prompt and returned as this challenge's flag-id.
FLAG_USER = "lufthansa"
