"""CHECKER for grav-editor-sandbox — a network probe run by the health poller,
never inside prod (the defender is root there and could rewrite a baked script).

It proves the minimum legitimate editor workflow still works, so a defender
cannot pass by amputating the feature the round is played on:

  login            — a content editor exchanges its credential for an API token.
  page_roundtrip   — that editor publishes a FRESH ordinary page whose body is
                     processed by Twig, and the public site renders the result.
  privileged_denied— the same editor's direct read of privileged plugin config
                     is refused.

The checker's own login is a fixed content-editor account created at cold start.
It is not a shortcut: it carries exactly the privileges every attacker's baseline
principal carries, so it grants nothing an attacker does not already hold.
"""

from __future__ import annotations

import secrets

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._client import GravApi, resolve_host

_PORT_NAME = "service"

CHECKER_USER = "sitecheck"
CHECKER_PASS = "Check1-editor-baseline"

# A safe, ordinary Twig expression: it must render arithmetically, which a canned
# response or a service with Twig processing amputated cannot do.
_TWIG_BODY = "SAFE={{ 6 * 7 }}"
_TWIG_RESULT = "SAFE=42"


class GravEditorSandboxChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "grav-editor-sandbox-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return (_PORT_NAME,)

    def run(self, target: VulboxTarget) -> CheckResult:
        base = f"http://{resolve_host(target.host)}:{target.ports[_PORT_NAME]}"
        api = GravApi(base)

        try:
            if not api.login(CHECKER_USER, CHECKER_PASS):
                return CheckResult(name="checker", passed=False,
                                   detail="content-editor login rejected")
        except Exception as exc:  # noqa: BLE001 — an unreachable box is a failure, not a crash
            return CheckResult(name="checker", passed=False, detail=f"login: {exc}")

        children = [CheckResult(name="login", passed=True, detail="editor token issued")]
        children.append(self._page_roundtrip(api))
        children.append(self._privileged_denied(api))
        return CheckResult(name="checker",
                           passed=all(child.passed for child in children),
                           children=children)

    def _page_roundtrip(self, api: GravApi) -> CheckResult:
        route = f"/site-check-{secrets.token_hex(6)}"
        try:
            status, _ = api.create_page(route, "Site check", _TWIG_BODY)
            if status != 201:
                return CheckResult(name="page_roundtrip", passed=False,
                                   detail=f"page create -> {status} (want 201)")
            render_status, body = api.get_text(route)
        except Exception as exc:  # noqa: BLE001
            return CheckResult(name="page_roundtrip", passed=False, detail=f"{exc}")
        finally:
            # Best effort: keep the probe from accumulating pages round after
            # round. A failed cleanup is not a gameplay failure.
            try:
                api.delete_page(route)
            except Exception:  # noqa: BLE001
                pass
        rendered = render_status == 200 and _TWIG_RESULT in body
        return CheckResult(
            name="page_roundtrip", passed=rendered,
            detail=(f"create 201, render {render_status}, "
                    f"{_TWIG_RESULT!r} {'present' if rendered else 'absent'}"),
        )

    def _privileged_denied(self, api: GravApi) -> CheckResult:
        try:
            status, _ = api.read_plugin_config("api")
        except Exception as exc:  # noqa: BLE001
            return CheckResult(name="privileged_denied", passed=False, detail=f"{exc}")
        return CheckResult(name="privileged_denied", passed=(status == 403),
                           detail=f"editor config read -> {status} (want 403)")
