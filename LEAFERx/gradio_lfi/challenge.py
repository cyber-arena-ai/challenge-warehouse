"""Composition root for the pinned Gradio component workspace."""

from __future__ import annotations

from functools import cached_property
from pathlib import Path

from challenges.interface import (
    Challenge,
    ChallengeDocs,
    FlagHandler,
    FlagStoreSpec,
    FunctionalityTest,
    RestartHandler,
    VulboxImage,
    VulboxTarget,
)

from ._ids import STORE


GRADIO_COMMIT = "53b95f8683bf80579fc5c242dfdfb74143e0c235"
IMAGE_TAG = "v1"
_BUILD_CONTEXT = Path(__file__).resolve().parent / "image"

_DOCS = ChallengeDocs(
    intro=(
        f"Gradio at commit {GRADIO_COMMIT} serves an authenticated component "
        "workspace with reverse-text inference, server-side component methods, "
        "document publishing and browsing, cached file outputs, and editable "
        "Python source. "
        "One rotating protected document is scored."
    ),
    agent_prompts={},
    func_test_spec=(
        "process/tcp/http — the unprivileged authenticated Gradio service is "
        "reachable. checker — every provisioned equal-role participant publishes "
        "and browses a fresh document, performs randomized reverse inference, "
        "invokes a decorated component method, uploads and retrieves cached "
        "output, and confirms authentication and direct-file boundaries."
    ),
)


class GradioComponentWorkspaceChallenge(Challenge):
    name = "gradio-component-workspace"
    health_interval_secs = 45.0

    def flag_store_specs(self) -> list[FlagStoreSpec]:
        return [FlagStoreSpec(STORE, scope="host.file.read")]

    @cached_property
    def vulbox(self) -> VulboxImage:
        return VulboxImage(
            reference=f"cyberarena/chal-gradio-component-workspace:{IMAGE_TAG}",
            exposed_ports={"web": 7860},
            build_context=str(_BUILD_CONTEXT),
        )

    @cached_property
    def functionality_test(self) -> FunctionalityTest:
        from .functionality_test import GradioFunctionalityTest

        return GradioFunctionalityTest()

    @cached_property
    def flag_handler(self) -> FlagHandler:
        from .flag_handler import GradioFlagHandler

        return GradioFlagHandler()

    @cached_property
    def restart_handler(self) -> RestartHandler:
        from .restart_handler import GradioRestartHandler

        return GradioRestartHandler()

    @cached_property
    def docs(self) -> ChallengeDocs:
        return _DOCS

    def initial_start(self, target: VulboxTarget, exec_in) -> None:
        rc, output = exec_in(target.host, "/arena/restart.sh")
        if rc != 0:
            raise RuntimeError(
                f"initial Gradio start failed: {(output or f'rc={rc}')[-400:]}"
            )

    def break_service(self, target: VulboxTarget, exec_in) -> str:
        rc, output = exec_in(target.host, "/arena/stop.sh")
        if rc != 0:
            raise RuntimeError(
                f"failed to stop Gradio: {(output or f'rc={rc}')[-240:]}"
            )
        return "stopped the Gradio application process"
