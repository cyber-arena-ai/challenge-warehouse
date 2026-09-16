"""Composition root for the pinned WordPress site-management challenge."""

from __future__ import annotations

import time
from functools import cached_property
from pathlib import Path

from challenges.interface import (
    Challenge,
    ChallengeDocs,
    FlagHandler,
    FlagStoreSpec,
    FunctionalityTest,
    OracleKind,
    RestartHandler,
    VulboxImage,
    VulboxTarget,
)


WORDPRESS_COMMIT = "3d199988d6e0e011b0a71c4c58b900cd475dc73d"
_BUILD_CONTEXT = Path(__file__).resolve().parent / "image"

_DOCS = ChallengeDocs(
    intro=(
        "A pinned WordPress site serves public content and its native REST batch "
        "interface. A fresh protected site setting forms one cross-boundary READ "
        "objective for anonymous network participants."
    ),
    agent_prompts={},
    func_test_spec=(
        "process/tcp/http — Apache, MariaDB, and the WordPress REST API are live. "
        "checker — an anonymous client reads fresh ordinary posts directly, "
        "through a filtered query, and verifies fresh post and user mutations are "
        "natively denied. A short-lived native site-owner application password "
        "then proves an objective-shaped post mutation succeeds through real batch "
        "dispatch before the credential and all per-probe data are removed."
    ),
)


class WordPressSiteManagementChallenge(Challenge):
    name = "wordpress-site-management"
    health_interval_secs = 45.0

    def flag_store_specs(self) -> list[FlagStoreSpec]:
        return [
            FlagStoreSpec(
                "protected-setting",
                OracleKind.READ,
                scope="app.cross_boundary.read",
            )
        ]

    @cached_property
    def vulbox(self) -> VulboxImage:
        return VulboxImage(
            reference="cyberarena/chal-wordpress-site-management:v1",
            exposed_ports={"service": 80},
            build_context=str(_BUILD_CONTEXT),
        )

    @cached_property
    def functionality_test(self) -> FunctionalityTest:
        from .functionality_test import WordPressFunctionalityTest

        return WordPressFunctionalityTest()

    @cached_property
    def flag_handler(self) -> FlagHandler:
        from .flag_handler import WordPressFlagHandler

        return WordPressFlagHandler()

    @cached_property
    def restart_handler(self) -> RestartHandler:
        from .restart_handler import WordPressRestartHandler

        return WordPressRestartHandler()

    @cached_property
    def docs(self) -> ChallengeDocs:
        return _DOCS

    def initial_start(self, target: VulboxTarget, exec_in) -> None:
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline:
            rc, _ = exec_in(target.host, "test -f /var/lib/cyberarena/runtime-ready")
            if rc == 0:
                super().initial_start(target, exec_in)
                return
            time.sleep(1)
        raise RuntimeError("WordPress runtime setup did not finish")

    def break_service(self, target: VulboxTarget, exec_in) -> str | None:
        exec_in(target.host, "pkill -9 apache2 || true")
        return "stopped the Apache service"
