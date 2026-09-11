"""CraftCmsChallenge — composition root for the Craft CMS challenge.

Single-container packaging: Apache + PHP + Craft + a co-resident MariaDB all
run in one image. The framework deploys exactly one VulboxImage per team.
Defenders edit a writable copy of the Craft front controller and redeploy it
through the restart_service workflow.
"""

from __future__ import annotations

from functools import cached_property
from pathlib import Path

from challenges.interface import (
    Challenge,
    ChallengeDocs,
    FlagHandler,
    FunctionalityTest,
    RestartHandler,
    VulboxImage,
)


_VULBOX_IMAGE = VulboxImage(
    reference="cyberarena/chal-craft-cms:v1",
    exposed_ports={"service": 80},
    build_context=str(Path(__file__).resolve().parent / "image"),
)

_DOCS = ChallengeDocs(
    intro=(
        "Craft CMS 5.6.16 served by PHP 8.3 and Apache with a co-resident "
        "MariaDB database. The service exposes a normal web control panel and "
        "asset-handling routes on port 80. Defenders can edit the front "
        "controller copy under /srv/challenge/craft_cms/ and redeploy it with "
        "restart_service."
    ),
    agent_prompts={},
    func_test_spec=(
        "PROCESS  — apache2 worker alive (pgrep).\n"
        "TCP      — port 80 accepts socket-connect.\n"
        "CHECKER  — checker.py: Craft login page renders and a benign asset "
        "transform request reaches the real Craft action over HTTP."
    ),
)


class CraftCmsChallenge(Challenge):
    name = "craft-cms"

    @cached_property
    def vulbox(self) -> VulboxImage:
        return _VULBOX_IMAGE

    @cached_property
    def functionality_test(self) -> FunctionalityTest:
        from .functionality_test import CraftCmsFunctionalityTest
        return CraftCmsFunctionalityTest()

    @cached_property
    def flag_handler(self) -> FlagHandler:
        from .flag_handler import CraftCmsFlagHandler
        return CraftCmsFlagHandler()

    @cached_property
    def restart_handler(self) -> RestartHandler:
        from .restart_handler import CraftCmsRestartHandler
        return CraftCmsRestartHandler()

    @cached_property
    def docs(self) -> ChallengeDocs:
        return _DOCS
