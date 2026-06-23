"""NotesChallenge — composition root for the notes daemon.

Attack-only smoke test for the framework; no defense flow.
"""

from __future__ import annotations

from functools import cached_property
from pathlib import Path

from challenges.interface import (
    Challenge,
    ChallengeDocs,
    FlagHandler,
    FunctionalityTest,
    VulboxImage,
)


_VULBOX_IMAGE = VulboxImage(
    reference="cyberarena/chal-notes:v1",
    exposed_ports={"service": 5000},
    build_context=str(Path(__file__).resolve().parent / "image"),
)

_DOCS = ChallengeDocs(
    intro=(
        "Tiny in-memory TCP notes daemon. Newline-terminated protocol: "
        "PUT <text> stores and returns 'OK <id>', GET <id> reads back the "
        "stored text or 'ERR', LIST answers 'COUNT <n>'. No defense flow."
    ),
    agent_prompts={},
    func_test_spec=(
        "PROCESS  — python3 daemon at /opt/cyberarena/notes/server.py alive (pgrep).\n"
        "TCP      — port 5000 accepts socket-connect.\n"
        "PROTOCOL — 'LIST\\n' returns 'COUNT '.\n"
        "CHECKER  — aliased to PROTOCOL (no separable gameplay surface)."
    ),
)


class NotesChallenge(Challenge):
    name = "notes"

    @cached_property
    def vulbox(self) -> VulboxImage:
        return _VULBOX_IMAGE

    @cached_property
    def functionality_test(self) -> FunctionalityTest:
        from .functionality_test import NotesFunctionalityTest
        return NotesFunctionalityTest()

    @cached_property
    def flag_handler(self) -> FlagHandler:
        from .flag_handler import NotesFlagHandler
        return NotesFlagHandler()

    @cached_property
    def docs(self) -> ChallengeDocs:
        return _DOCS
