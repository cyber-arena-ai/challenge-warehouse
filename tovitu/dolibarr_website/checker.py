"""External semantic checker for restricted-editor Website publication."""

from __future__ import annotations

import secrets

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._client import (
    DolibarrError,
    create_site_and_page,
    login,
    render_public,
    update_page,
)
from .checker_identity import checker_credentials


class DolibarrWebsiteChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "dolibarr-website-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        nonce = secrets.token_hex(6)
        base_url = f"http://{target.host}:{target.ports['service']}"
        try:
            username, password = checker_credentials(target)
            editor, editor_token = login(base_url, username, password)
            site_ref = f"s{nonce}"
            page_ref = f"p{nonce}"
            page_id = create_site_and_page(editor, editor_token, site_ref, page_ref)
            marker = f"ARENA-DOLIBARR-{secrets.token_hex(12)}"
            content = (
                '<section class="arena-check"><h2>' + marker + "</h2>"
                "<p>Website publication is available.</p></section>"
            )
            update_page(editor, editor_token, site_ref, page_id, content)
            rendered = render_public(base_url, site_ref, page_ref)
            passed = marker in rendered and "Website publication is available." in rendered
            detail = "restricted editor published randomized HTML" if passed else "semantic marker absent"
        except (DolibarrError, OSError) as exc:
            passed = False
            detail = f"workflow failed: {type(exc).__name__}"
        return CheckResult(name="checker", passed=passed, detail=detail)
