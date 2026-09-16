"""Network-only check of the anonymous native watch workflow."""

from __future__ import annotations

from dataclasses import dataclass

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._source import source_workflow
from ._ui import (
    WatchWorkflowError,
    create_watch,
    delete_watch,
    opener,
    preview,
    request,
    watch_matches,
    watches_with_source,
)


@dataclass(frozen=True)
class _OwnedWatch:
    uuid: str
    source_url: str
    marker: str


def _retire_owned(client: object, base: str, owned: _OwnedWatch) -> bool:
    try:
        return watch_matches(
            client, base, owned.uuid, owned.source_url
        ) and delete_watch(client, base, owned.uuid)
    except Exception:
        return False


class ChangedetectionIoChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "changedetection-io-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        base = f"http://{target.host}:{target.ports['service']}"
        client = opener()
        children: list[CheckResult] = []
        watch_uuid: str | None = None
        owned: _OwnedWatch | None = None
        source_url: str | None = None
        marker: str | None = None

        try:
            status, _, _root = request(client, base, "/")
            if status != 200:
                return CheckResult("checker", False, f"public root HTTP {status}")

            with source_workflow(target.host, target.ports["service"]) as workflow:
                source_url, selector, marker = workflow
                watch_uuid, saved, _ = create_watch(
                    client,
                    base,
                    source_url,
                    selector,
                )
                owned = _OwnedWatch(watch_uuid, source_url, marker)
                children.append(
                    CheckResult("public_watch_create", saved, "anonymous UI form")
                )
                observed = preview(client, base, watch_uuid)
                children.append(
                    CheckResult(
                        "randomized_xpath_preview",
                        observed == marker,
                        "fresh value matched"
                        if observed == marker
                        else "unexpected preview",
                    )
                )
        except Exception as error:  # gameplay failures are health results
            if isinstance(error, WatchWorkflowError) and watch_uuid is None:
                watch_uuid = error.watch_uuid
                if (
                    watch_uuid is not None
                    and owned is None
                    and source_url is not None
                    and marker is not None
                ):
                    owned = _OwnedWatch(watch_uuid, source_url, marker)
            children.append(
                CheckResult(
                    "public_workflow",
                    False,
                    f"{type(error).__name__}: {error}"[:220],
                )
            )
        finally:
            if owned is None and source_url is not None and marker is not None:
                try:
                    status, _, root = request(client, base, "/")
                    candidates = (
                        watches_with_source(root, source_url) if status == 200 else []
                    )
                except Exception:
                    candidates = []
                if len(candidates) == 1:
                    owned = _OwnedWatch(candidates[0], source_url, marker)
                elif len(candidates) > 1:
                    children.append(
                        CheckResult(
                            "failed_watch_cleanup",
                            False,
                            "ambiguous owned-watch recovery",
                        )
                    )
            if owned is not None:
                cleanup_ok = _retire_owned(client, base, owned)
                children.append(
                    CheckResult(
                        "watch_cleanup",
                        cleanup_ok,
                        "verified exact watch retired"
                        if cleanup_ok
                        else "exact watch cleanup failed",
                    )
                )
        return CheckResult(
            "checker", bool(children) and all(child.passed for child in children), children=children
        )
