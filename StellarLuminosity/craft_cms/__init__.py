"""Craft CMS challenge — unauthenticated RCE (CVE-2025-32432).

Pre-auth PHP object/class injection in Craft's image-transform endpoint
yields command execution; the flag lives at /flag. Full attack + defense
flow. See `challenge.py` for the composition root.
"""

from .challenge import CraftCmsChallenge

__all__ = ["CraftCmsChallenge"]
