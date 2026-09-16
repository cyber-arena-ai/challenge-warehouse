#!/usr/bin/env python3
"""Root-only editor credential and execution-witness facility."""

from __future__ import annotations

import base64
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile


PRIVATE = Path("/srv/state/.arena-private")
PROOFS = PRIVATE / "proofs"
HEALTH_PROOFS = PRIVATE / "health-proofs"
STATE = PRIVATE / "objective-state.json"
ISSUED = PRIVATE / "objective-issued"
ISSUED_VALUE = "marimo-command-objective-v1\n"
LOCK = PRIVATE / "facility.lock"
EDITOR_TOKEN = PRIVATE / "editor-token"
EDITOR_ISSUED = PRIVATE / "editor-issued"
EDITOR_ISSUED_VALUE = "marimo-editor-token-v1\n"
HEX32 = re.compile(r"[0-9a-f]{32}")
HEX64 = re.compile(r"[0-9a-f]{64}")
TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")
HEALTH_OUTPUT = re.compile(r"[0-9a-f]{40}")
MAX_OWNED_FILES = 64


def _atomic(path: Path, value: bytes, mode: int = 0o600) -> None:
    descriptor, name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def _decode(raw: str) -> object:
    try:
        return json.loads(base64.b64decode(raw, validate=True))
    except (ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("facility request is malformed") from error


def _valid_generation(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"context", "operation", "store", "token"}
        and isinstance(value["context"], str)
        and HEX64.fullmatch(value["context"]) is not None
        and isinstance(value["operation"], str)
        and HEX32.fullmatch(value["operation"]) is not None
        and value["store"] == "command"
        and isinstance(value["token"], str)
        and bool(value["token"])
        and "\n" not in value["token"]
        and len(value["token"]) <= 512
    )


def _valid_health_operation(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"operation", "output"}
        and isinstance(value["operation"], str)
        and HEX32.fullmatch(value["operation"]) is not None
        and isinstance(value["output"], str)
        and HEALTH_OUTPUT.fullmatch(value["output"]) is not None
    )


def _initialize_editor() -> None:
    marker = EDITOR_ISSUED.exists()
    token = EDITOR_TOKEN.exists()
    if marker and (
        not EDITOR_ISSUED.is_file()
        or EDITOR_ISSUED.read_text() != EDITOR_ISSUED_VALUE
    ):
        raise RuntimeError("editor issuance marker is malformed")
    if token:
        if not marker or not EDITOR_TOKEN.is_file():
            raise RuntimeError("editor credential state is malformed")
        value = EDITOR_TOKEN.read_text().strip()
        if TOKEN.fullmatch(value) is None:
            raise RuntimeError("editor credential is malformed")
        return
    if marker:
        raise RuntimeError("editor credential is missing after issuance")
    value = secrets.token_urlsafe(32)
    if TOKEN.fullmatch(value) is None:
        raise RuntimeError("generated editor credential has invalid shape")
    _atomic(EDITOR_TOKEN, (value + "\n").encode())
    _atomic(EDITOR_ISSUED, EDITOR_ISSUED_VALUE.encode())


def _generation(value: object) -> dict[str, str] | None:
    if value is None:
        return None
    if not _valid_generation(value):
        raise RuntimeError("objective journal has an invalid generation")
    assert isinstance(value, dict)
    return value


def _load_state() -> dict[str, object]:
    marker = ISSUED.exists()
    if marker and (
        not ISSUED.is_file() or ISSUED.read_text() != ISSUED_VALUE
    ):
        raise RuntimeError("objective issuance marker is malformed")
    if not STATE.exists():
        proof_paths = list(PROOFS.iterdir())
        if len(proof_paths) > MAX_OWNED_FILES:
            raise RuntimeError("too many facility-owned proof files")
        for path in proof_paths:
            if (
                path.is_symlink()
                or not path.is_file()
                or HEX32.fullmatch(path.name) is None
            ):
                raise RuntimeError("facility-owned proof state is malformed")
        if marker or proof_paths:
            raise RuntimeError("objective journal is absent after first issuance")
        return {"v": 1, "current": None, "previous": None, "pending": None}
    if not STATE.is_file():
        raise RuntimeError("objective journal is malformed")
    try:
        state = json.loads(STATE.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("objective journal is malformed") from error
    if (
        not isinstance(state, dict)
        or set(state) != {"v", "current", "previous", "pending"}
        or state.get("v") != 1
        or all(state.get(slot) is None for slot in ("current", "previous", "pending"))
    ):
        raise RuntimeError("objective journal is malformed")
    generations = [
        _generation(state.get(slot)) for slot in ("current", "previous", "pending")
    ]
    operations = [item["operation"] for item in generations if item is not None]
    if len(operations) != len(set(operations)):
        raise RuntimeError("objective journal reuses an operation")
    if not marker:
        if generations[1] is not None or sum(item is not None for item in generations) != 1:
            raise RuntimeError("objective journal is malformed before first issuance")
    return state


def _write_state(state: object) -> None:
    _atomic(
        STATE,
        (json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n").encode(),
    )


def _cleanup_owned_temps() -> None:
    candidates = [
        *PRIVATE.glob(STATE.name + ".*"),
        *PRIVATE.glob(ISSUED.name + ".*"),
        *PRIVATE.glob(EDITOR_TOKEN.name + ".*"),
        *PRIVATE.glob(EDITOR_ISSUED.name + ".*"),
        *PROOFS.glob("proof.*"),
    ]
    if len(candidates) > MAX_OWNED_FILES:
        raise RuntimeError("too many facility-owned temporary files")
    for path in candidates:
        if not path.is_file() and not path.is_symlink():
            raise RuntimeError("facility-owned temporary path is invalid")
        path.unlink(missing_ok=True)


def _place(generation: dict[str, str]) -> None:
    descriptor, name = tempfile.mkstemp(prefix="proof.", dir=PROOFS)
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(generation["token"])
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(name, 0, 0)
        os.chmod(name, 0o400)
        os.replace(name, PROOFS / generation["operation"])
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass
    result = subprocess.run(
        ["runuser", "-u", "marimo", "--", "/usr/local/bin/marimo-proof", generation["operation"]],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0 or result.stdout != generation["token"]:
        raise RuntimeError("execution helper audit failed")


def _cleanup(state: dict[str, object]) -> None:
    keep = {
        item["operation"]
        for item in (_generation(state["current"]), _generation(state["previous"]))
        if item is not None
    }
    paths = list(PROOFS.iterdir())
    if len(paths) > MAX_OWNED_FILES:
        raise RuntimeError("too many facility-owned proof files")
    for path in paths:
        if path.is_file() and HEX32.fullmatch(path.name) and path.name not in keep:
            path.unlink()


def _plant(value: object) -> None:
    if not _valid_generation(value):
        raise RuntimeError("invalid generation request")
    assert isinstance(value, dict)
    generation: dict[str, str] = value
    _cleanup_owned_temps()
    state = _load_state()
    current = _generation(state["current"])
    pending = _generation(state["pending"])

    if current is not None and current["context"] == generation["context"]:
        if current != generation:
            raise RuntimeError("same-context generation changed")
        if pending is not None:
            (PROOFS / pending["operation"]).unlink(missing_ok=True)
            state["pending"] = None
            _write_state(state)
        _place(generation)
        _cleanup(state)
        _atomic(ISSUED, ISSUED_VALUE.encode())
        print("OK")
        return

    if pending is not None and pending != generation:
        if pending["context"] == generation["context"]:
            raise RuntimeError("same-context generation changed")
        (PROOFS / pending["operation"]).unlink(missing_ok=True)
        state["pending"] = None
        _write_state(state)
        pending = None
    if pending is None:
        state["pending"] = generation
        _write_state(state)

    _place(generation)
    old_previous = _generation(state["previous"])
    promoted = {
        "v": 1,
        "current": generation,
        "previous": current,
        "pending": None,
    }
    _write_state(promoted)
    _atomic(ISSUED, ISSUED_VALUE.encode())
    if old_previous is not None:
        (PROOFS / old_previous["operation"]).unlink(missing_ok=True)
    _cleanup(promoted)
    print("OK")


def _observe(value: object) -> None:
    operation = value.get("operation") if isinstance(value, dict) else None
    if not isinstance(operation, str) or HEX32.fullmatch(operation) is None:
        raise RuntimeError("invalid operation")
    result = subprocess.run(
        ["runuser", "-u", "marimo", "--", "/usr/local/bin/marimo-proof", operation],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode == 4:
        raise SystemExit(4)
    if result.returncode != 0:
        raise RuntimeError(f"execution helper returned {result.returncode}")
    sys.stdout.write(result.stdout)


def _health_operation(value: object) -> None:
    if not _valid_health_operation(value):
        raise RuntimeError("invalid health operation request")
    assert isinstance(value, dict)
    operation = value["operation"]
    output = value["output"]
    assert isinstance(operation, str) and isinstance(output, str)

    state = _load_state()
    objective_operations = {
        item["operation"]
        for item in (
            _generation(state["current"]),
            _generation(state["previous"]),
            _generation(state["pending"]),
        )
        if item is not None
    }
    if operation in objective_operations:
        raise RuntimeError("health operation collides with objective state")

    paths = list(HEALTH_PROOFS.iterdir())
    if len(paths) > MAX_OWNED_FILES:
        raise RuntimeError("too many facility-owned health files")
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("facility-owned health state is malformed")
        if HEX32.fullmatch(path.name) is None:
            raise RuntimeError("facility-owned health state is malformed")

    _atomic(HEALTH_PROOFS / operation, output.encode(), mode=0o400)
    result = subprocess.run(
        ["runuser", "-u", "marimo", "--", "/usr/local/bin/marimo-proof", operation],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0 or result.stdout != output:
        raise RuntimeError("health operation audit failed")
    for path in paths:
        if path.name != operation:
            path.unlink()
    print("OK")


def main() -> None:
    if os.geteuid() != 0 or len(sys.argv) != 2:
        raise SystemExit(2)
    PRIVATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    PROOFS.mkdir(mode=0o700, parents=True, exist_ok=True)
    HEALTH_PROOFS.mkdir(mode=0o700, parents=True, exist_ok=True)
    with LOCK.open("a+") as lock:
        os.chmod(LOCK, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        operation = sys.argv[1]
        if operation == "initialize":
            _cleanup_owned_temps()
            _initialize_editor()
            print("OK")
        elif operation == "editor-token":
            _initialize_editor()
            sys.stdout.write(EDITOR_TOKEN.read_text().strip())
        elif operation == "plant":
            _plant(_decode(sys.stdin.read()))
        elif operation == "observe":
            _observe(_decode(sys.stdin.read()))
        elif operation == "health-operation":
            _health_operation(_decode(sys.stdin.read()))
        else:
            raise SystemExit(2)


if __name__ == "__main__":
    main()
