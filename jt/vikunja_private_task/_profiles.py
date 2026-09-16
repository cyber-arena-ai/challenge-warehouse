"""Application-visible record profiles shared by placement and checking."""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
from typing import NamedTuple


BASELINE_PROJECT_TITLE = "Project summary 4821"
BASELINE_PROJECT_DESCRIPTION = "Planning notes for the project summary."

_READ_TAG_RE = re.compile(r"[0-9a-f]{32}")
_PROJECT_IDENTIFIER_RE = re.compile(r"[A-Z2-7]{10}")
_ACTIONS = (
    "Arrange", "Check", "Confirm", "Draft", "Finalize", "Gather", "Prepare",
    "Review",
)
_QUALIFIERS = (
    "client", "design", "launch", "monthly", "project", "release", "service",
    "weekly",
)
_SUBJECTS = (
    "agenda", "brief", "checklist", "handoff", "notes", "plan", "report",
    "summary",
)


class ReadProfile(NamedTuple):
    shared_project_title: str
    shared_project_description: str
    shared_project_identifier: str
    private_project_title: str
    private_project_description: str
    private_project_identifier: str
    shared_task_title: str
    shared_task_description: str
    peer_task_title: str
    peer_task_description: str
    private_task_title: str


def _material(tag: str, label: str) -> bytes:
    return hashlib.sha256(bytes.fromhex(tag) + b"\0" + label.encode()).digest()


def _task_title(tag: str, label: str) -> str:
    material = _material(tag, label)
    return (
        f"{_ACTIONS[material[0] % len(_ACTIONS)]} "
        f"{_QUALIFIERS[material[1] % len(_QUALIFIERS)]} "
        f"{_SUBJECTS[material[2] % len(_SUBJECTS)]} "
        f"{int.from_bytes(material[3:6], 'big') % 1000000:06d}"
    )


def _project_fields(tag: str, label: str) -> tuple[str, str, str]:
    material = _material(tag, label)
    qualifier = _QUALIFIERS[material[0] % len(_QUALIFIERS)]
    subject = _SUBJECTS[material[1] % len(_SUBJECTS)]
    number = int.from_bytes(material[2:4], "big") % 10000
    title = f"{qualifier.title()} {subject} {number:04d}"
    description = f"Planning notes for the {qualifier} {subject}."
    identifier = _project_identifier(material[4:11])
    return title, description, identifier


def read_profile(tag: str) -> ReadProfile:
    if _READ_TAG_RE.fullmatch(tag) is None:
        raise ValueError("read profile tag must be 32 lowercase hex characters")
    shared_project = _project_fields(tag, "shared-project")
    private_project = _project_fields(tag, "private-project")
    return ReadProfile(
        shared_project_title=shared_project[0],
        shared_project_description=shared_project[1],
        shared_project_identifier=shared_project[2],
        private_project_title=private_project[0],
        private_project_description=private_project[1],
        private_project_identifier=private_project[2],
        shared_task_title=_task_title(tag, "shared-task"),
        shared_task_description="Coordinate the next review with the project team.",
        peer_task_title=_task_title(tag, "peer-task"),
        peer_task_description="Keep the related work item available to project members.",
        private_task_title=_task_title(tag, "private-task"),
    )


def _project_identifier(material: bytes) -> str:
    if len(material) < 7:
        raise ValueError("project identifier needs seven bytes of material")
    return base64.b32encode(material[:7]).decode()[:10]


def fresh_project_identifier() -> str:
    return _project_identifier(secrets.token_bytes(7))


def is_baseline_project_identifier(value: object) -> bool:
    return isinstance(value, str) and _PROJECT_IDENTIFIER_RE.fullmatch(value) is not None
