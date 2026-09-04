"""wp2shell — WordPress 6.9.4 REST batch desync (CVE-2026-63030) chained into
an unauthenticated WP_Query SQL injection (CVE-2026-60137).
"""

from .challenge import Wp2ShellChallenge

__all__ = ["Wp2ShellChallenge"]
