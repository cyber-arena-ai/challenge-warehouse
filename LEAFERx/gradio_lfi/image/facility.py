#!/usr/bin/env python3
"""Root-only lifecycle bridge for Gradio accounts, health data, and proofs."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
import tempfile
import time
import urllib.parse


STATE = Path("/var/lib/gradio-arena")
ACCOUNTS = STATE / "accounts.json"
ACCOUNT_BOOK = STATE / "account-bookkeeping.json"
PROOFS = STATE / "proofs"
PUBLIC = STATE / "public"
OBJECTIVE = STATE / "objective-journal.json"
ISSUED = STATE / "objective-issued"
HEALTH = STATE / "health-journal.json"
LOCK = STATE / "facility.lock"
CACHE = Path("/tmp/gradio")
ISSUED_VALUE = "gradio-proof-file-v1"
STORE = "proof_file"
USERNAME_RE = re.compile(r"[a-z]+\.[a-z]+\.[0-9a-f]{10}")
PASSWORD_RE = re.compile(r"[A-Za-z0-9_-]{32}")
HEX64_RE = re.compile(r"[0-9a-f]{64}")
TARGET_RE = re.compile(r"report-[0-9a-f]{24}\.txt")
DOCUMENT_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{2,95}")
OWNER_RE = re.compile(r"[A-Za-z0-9_-]{32}")
MAX_TEMPS = 64
LEASE_SECONDS = 180


def _app_identity() -> tuple[int, int]:
    row = pwd.getpwnam("appuser")
    return row.pw_uid, row.pw_gid


def _layout() -> None:
    uid, gid = _app_identity()
    STATE.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(STATE, 0, gid)
    os.chmod(STATE, 0o750)
    PROOFS.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(PROOFS, 0, gid)
    os.chmod(PROOFS, 0o750)
    PUBLIC.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(PUBLIC, uid, gid)
    os.chmod(PUBLIC, 0o700)
    CACHE.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(CACHE, uid, gid)


def _decode(raw: str) -> object:
    if not raw or len(raw) > 131_072:
        raise RuntimeError("invalid facility payload")
    try:
        return json.loads(base64.b64decode(raw, validate=True))
    except (ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("invalid facility payload") from error


def _atomic_json(
    path: Path, value: object, *, mode: int = 0o600, uid: int = 0, gid: int = 0
) -> None:
    _atomic_text(
        path,
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        mode=mode,
        uid=uid,
        gid=gid,
    )


def _atomic_text(path: Path, value: str, *, mode: int, uid: int, gid: int) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".arena-tmp-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temporary, uid, gid)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _account(value: object) -> tuple[str, str]:
    if not isinstance(value, dict) or set(value) != {"password", "username"}:
        raise RuntimeError("invalid account")
    username = value.get("username")
    password = value.get("password")
    if (
        not isinstance(username, str)
        or USERNAME_RE.fullmatch(username) is None
        or not isinstance(password, str)
        or PASSWORD_RE.fullmatch(password) is None
    ):
        raise RuntimeError("invalid account")
    return username, password


def _accounts() -> dict[str, dict[str, str]]:
    if not ACCOUNT_BOOK.exists():
        if ACCOUNTS.exists():
            raise RuntimeError("account bookkeeping is missing after publication")
        return {"baseline": {}, "cohort": "", "publisher": {}, "v": 3}
    try:
        value = json.loads(ACCOUNT_BOOK.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("account bookkeeping is malformed") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"baseline", "cohort", "publisher", "v"}
        or value.get("v") != 3
    ):
        raise RuntimeError("account bookkeeping is malformed")
    result: dict[str, dict[str, str]] = {}
    for group in ("baseline", "publisher"):
        rows = value[group]
        if not isinstance(rows, dict):
            raise RuntimeError("account bookkeeping is malformed")
        result[group] = dict(
            _account({"username": username, "password": password})
            for username, password in rows.items()
        )
    result["cohort"] = value["cohort"]
    result["v"] = 3
    return result


def _write_accounts(value: dict[str, dict[str, str]]) -> None:
    _, gid = _app_identity()
    _atomic_json(ACCOUNT_BOOK, value, mode=0o600, uid=0, gid=0)
    public = {**value["baseline"], **value["publisher"]}
    _atomic_json(ACCOUNTS, public, mode=0o640, uid=0, gid=gid)


def provision(value: object) -> None:
    rows = value.get("accounts") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or set(value) != {"accounts", "cohort"}
        or not isinstance(rows, list)
    ):
        raise RuntimeError("invalid principal request")
    parsed = dict(_account(row) for row in rows)
    if len(parsed) != len(rows):
        raise RuntimeError("principal identities are not distinct")
    accounts = _accounts()
    accounts["baseline"] = parsed
    accounts["cohort"] = value["cohort"]
    _write_accounts(accounts)
    print("OK")


def _valid_generation(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "context", "store", "target_id", "target_path", "token"
    }:
        return False
    target_id = value.get("target_id")
    token = value.get("token")
    return (
        value.get("store") == STORE
        and isinstance(value.get("context"), str)
        and HEX64_RE.fullmatch(value["context"]) is not None
        and isinstance(target_id, str)
        and TARGET_RE.fullmatch(target_id) is not None
        and value.get("target_path") == str(PUBLIC / target_id)
        and isinstance(token, str)
        and bool(token)
        and "\n" not in token
        and len(token) <= 512
    )


def _empty_objective() -> dict[str, object]:
    return {"v": 1, "current": None, "previous": None, "pending": None}


def _objective() -> dict[str, object]:
    marker = ISSUED.read_text() if ISSUED.is_file() else None
    if marker not in (None, ISSUED_VALUE + "\n"):
        raise RuntimeError("objective issuance marker is malformed")
    if not OBJECTIVE.exists():
        if marker is not None:
            raise RuntimeError("objective journal is missing after issuance")
        return _empty_objective()
    try:
        value = json.loads(OBJECTIVE.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("objective journal is malformed") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"v", "current", "previous", "pending"}
        or value.get("v") != 1
        or any(
            value.get(key) is not None and not _valid_generation(value.get(key))
            for key in ("current", "previous", "pending")
        )
        or all(value.get(key) is None for key in ("current", "previous", "pending"))
    ):
        raise RuntimeError("objective journal is malformed")
    targets = [
        row["target_id"]
        for key in ("current", "previous", "pending")
        if isinstance((row := value.get(key)), dict)
    ]
    if len(targets) != len(set(targets)):
        raise RuntimeError("objective journal reuses a target")
    return value


def _write_objective(value: object) -> None:
    _atomic_json(OBJECTIVE, value)


def _mark_issued() -> None:
    _atomic_text(ISSUED, ISSUED_VALUE + "\n", mode=0o600, uid=0, gid=0)


def _proof_path(generation: dict[str, str]) -> Path:
    path = PUBLIC / generation["target_id"]
    if str(path) != generation["target_path"]:
        raise RuntimeError("invalid proof target")
    return path


def _issued_cohort(sealed: str) -> list[tuple[str, str]]:
    """The issued identities carried by the sealed cohort, or none before one.

    The seal is the only account material health trusts: the checker verifies
    its signature with the facility key and logs in as exactly these identities.
    Placement reads the same bytes, so the two cannot be made to disagree — the
    signature cannot be forged in prod, so rewriting the plain bookkeeping copy
    changes neither who health is nor who publishes the proof.
    """
    if not sealed:
        return []
    encoded = sealed.partition(".")[0]
    try:
        payload = json.loads(
            base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        )
        return sorted(
            _account({"username": username, "password": password})
            for username, password in payload["accounts"]
        )
    except (ValueError, TypeError, LookupError) as error:
        raise RuntimeError("issued cohort seal is malformed") from error


def _placement_account(context: str) -> tuple[str, str]:
    """The identity this round's proof is published through.

    Placement publishes as a member of the issued participant cohort that health
    logs in as. A publisher of its own is distinguishable from every account
    health exercises, so a defence can deny just that one, keep the whole
    participant workflow green, and still stop the next proof being placed.
    Sharing the cohort closes that gap: denying whoever places the proof also
    denies a participant health authenticates as, and health fails with it. The
    member rotates with the round context so placement does not lean on one
    account, and is derived rather than random so a round is reproducible.

    Before any participant is provisioned the application has no account at all,
    so placement registers one to publish through. Only the canonical build
    tier, which never provisions, reaches that branch; a match always issues the
    cohort before the first placement, and health refuses an unissued cohort.
    """
    accounts = _accounts()
    cohort = _issued_cohort(accounts["cohort"])
    if cohort:
        material = hashlib.sha256(("gradio-placement/" + context).encode()).digest()
        return cohort[int.from_bytes(material[:4], "big") % len(cohort)]
    if not accounts["publisher"]:
        material = hashlib.sha256(("gradio-publisher/" + context).encode()).digest()
        username = f"olive.parker.{material[:5].hex()}"
        password = base64.urlsafe_b64encode(material[5:29]).decode().rstrip("=")
        accounts["publisher"] = {username: password}
        _write_accounts(accounts)
    return next(iter(accounts["publisher"].items()))


def _request(
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, list[tuple[str, str]], bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", 7860, timeout=20)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.getheaders(), response.read()
    finally:
        connection.close()


def _login(username: str, password: str) -> str:
    body = urllib.parse.urlencode(
        {"username": username, "password": password}
    ).encode()
    status, headers, _ = _request(
        "POST",
        "/login",
        body=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    cookies = [
        value.split(";", 1)[0]
        for key, value in headers
        if key.lower() == "set-cookie"
    ]
    if status != 200 or not cookies:
        raise RuntimeError(f"placement login returned HTTP {status}")
    return "; ".join(cookies)


def _publish_document(username: str, password: str, name: str, content: str) -> None:
    cookie = _login(username, password)
    payload = json.dumps(
        {
            "data": [name, content],
            "fn_index": 1,
            "session_hash": hashlib.sha256(os.urandom(32)).hexdigest()[:16],
        },
        separators=(",", ":"),
    ).encode()
    status, _, raw = _request(
        "POST",
        "/run/predict",
        body=payload,
        headers={"Content-Type": "application/json", "Cookie": cookie},
    )
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("placement workflow returned malformed JSON") from error
    data = document.get("data") if isinstance(document, dict) else None
    if status != 200 or not isinstance(data, list) or data[:1] != [name]:
        raise RuntimeError(f"placement workflow returned HTTP {status}")


def _place(generation: dict[str, str]) -> None:
    path = _proof_path(generation)
    username, password = _placement_account(generation["context"])
    _publish_document(
        username, password, generation["target_id"], generation["token"]
    )
    result = subprocess.run(
        ["runuser", "-u", "appuser", "--", "cat", str(path)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0 or result.stdout != generation["token"]:
        raise RuntimeError("application cannot read the proof target")


def _unlink_generation(value: object) -> None:
    if isinstance(value, dict) and _valid_generation(value):
        _proof_path(value).unlink(missing_ok=True)


def plant(value: object) -> None:
    if not _valid_generation(value):
        raise RuntimeError("invalid generation request")
    generation = value
    assert isinstance(generation, dict)
    state = _objective()
    current = state["current"]
    pending = state["pending"]
    if isinstance(current, dict) and current["context"] == generation["context"]:
        if current != generation:
            raise RuntimeError("same round context changed its proof generation")
        if isinstance(pending, dict):
            _unlink_generation(pending)
            state["pending"] = None
            _write_objective(state)
        _place(generation)
        _mark_issued()
        print("OK")
        return

    previous = state["previous"]
    if isinstance(previous, dict):
        _unlink_generation(previous)
        state["previous"] = None
        _write_objective(state)

    pending = state["pending"]
    if isinstance(pending, dict) and pending != generation:
        _unlink_generation(pending)
        state["pending"] = None
        _write_objective(state)
        pending = None
    if pending is None:
        if any(
            isinstance(row, dict) and row["target_id"] == generation["target_id"]
            for row in (state["current"], state["previous"])
        ):
            raise RuntimeError("objective target identity collided")
        state["pending"] = generation
        _write_objective(state)

    _place(generation)
    _mark_issued()
    promoted = {"v": 1, "current": generation, "previous": current, "pending": None}
    _write_objective(promoted)
    print("OK")


def observe(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {
        "context", "store", "target_id", "target_path"
    }:
        raise RuntimeError("invalid observation request")
    state = _objective()
    generation = next(
        (
            row
            for key in ("current", "previous")
            if isinstance((row := state.get(key)), dict)
            and all(row.get(field) == value.get(field) for field in value)
        ),
        None,
    )
    if generation is None:
        raise SystemExit(4)
    path = _proof_path(generation)
    if not path.is_file():
        raise SystemExit(4)
    result = subprocess.run(
        ["runuser", "-u", "appuser", "--", "cat", str(path)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError("application proof read failed")
    sys.stdout.write(result.stdout)


def _health_value(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {
        "document",
        "objective_noise",
        "opened_at",
        "owner",
        "upload",
    }:
        raise RuntimeError("invalid health context")
    owner = value.get("owner")
    opened_at = value.get("opened_at")
    document = value.get("document")
    objective_noise = value.get("objective_noise")
    upload = value.get("upload")
    if (
        not isinstance(owner, str)
        or OWNER_RE.fullmatch(owner) is None
        or not isinstance(opened_at, int)
        or isinstance(opened_at, bool)
        or opened_at <= 0
        or not isinstance(document, dict)
        or set(document) != {"content", "name"}
        or not isinstance(objective_noise, dict)
        or set(objective_noise) != {"content", "name"}
        or not isinstance(upload, dict)
        or set(upload) != {"content", "name", "path"}
    ):
        raise RuntimeError("invalid health context")
    for item in (document, objective_noise, upload):
        if (
            not isinstance(item.get("name"), str)
            or DOCUMENT_NAME_RE.fullmatch(item["name"]) is None
            or not isinstance(item.get("content"), str)
            or not item["content"]
            or len(item["content"]) > 4096
        ):
            raise RuntimeError("invalid health file")
    if (
        TARGET_RE.fullmatch(document["name"]) is not None
        or TARGET_RE.fullmatch(upload["name"]) is not None
        or TARGET_RE.fullmatch(objective_noise["name"]) is None
        or len({document["name"], objective_noise["name"], upload["name"]}) != 3
    ):
        raise RuntimeError("invalid health file shape")
    digest = hashlib.sha1(upload["content"].encode()).hexdigest()
    if upload.get("path") != str(CACHE / digest / upload["name"]):
        raise RuntimeError("invalid health upload target")
    return {
        "document": dict(document),
        "objective_noise": dict(objective_noise),
        "opened_at": opened_at,
        "owner": owner,
        "upload": dict(upload),
    }


def _load_health() -> dict[str, object] | None:
    if not HEALTH.exists():
        return None
    try:
        return _health_value(json.loads(HEALTH.read_text()))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("health journal is malformed") from error


def _public_path(name: str) -> Path:
    path = PUBLIC / name
    if path.parent != PUBLIC:
        raise RuntimeError("invalid health document path")
    return path


def _cleanup_health(value: dict[str, object]) -> None:
    for key in ("document", "objective_noise"):
        document = value[key]
        _public_path(document["name"]).unlink(missing_ok=True)
        cached_path = (
            CACHE
            / hashlib.sha1(document["content"].encode()).hexdigest()
            / document["name"]
        )
        cached_path.unlink(missing_ok=True)
        try:
            cached_path.parent.rmdir()
        except OSError:
            pass
    upload = value["upload"]
    upload_path = Path(upload["path"])
    expected = (
        CACHE / hashlib.sha1(upload["content"].encode()).hexdigest() / upload["name"]
    )
    if upload_path != expected:
        raise RuntimeError("invalid health upload cleanup")
    upload_path.unlink(missing_ok=True)
    try:
        upload_path.parent.rmdir()
    except OSError:
        pass


def health_open(value: object) -> None:
    context = _health_value(value)
    previous = _load_health()
    if previous is not None:
        age = int(time.time()) - previous["opened_at"]
        if previous["owner"] != context["owner"] and age < LEASE_SECONDS:
            raise RuntimeError("another health workflow still owns the lease")
        _cleanup_health(previous)
        HEALTH.unlink(missing_ok=True)
    accounts = _accounts()
    if not accounts["baseline"]:
        raise RuntimeError("baseline principals are not provisioned")
    _atomic_json(HEALTH, context)
    print(
        json.dumps(
            {"cohort": accounts["cohort"]}, sort_keys=True, separators=(",", ":")
        )
    )


def health_close(value: object) -> None:
    owner = value.get("owner") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or set(value) != {"owner"}
        or not isinstance(owner, str)
        or OWNER_RE.fullmatch(owner) is None
    ):
        raise RuntimeError("invalid health cleanup request")
    context = _load_health()
    if context is None or context["owner"] != owner:
        raise RuntimeError("health workflow does not own the lease")
    _cleanup_health(context)
    HEALTH.unlink()
    print("OK")


def _cleanup_temps() -> None:
    candidates = [*STATE.glob(".arena-tmp-*"), *PROOFS.glob(".arena-tmp-*")]
    if len(candidates) > MAX_TEMPS:
        raise RuntimeError("too many owned temporary files")
    for path in candidates:
        if not path.is_file() and not path.is_symlink():
            raise RuntimeError("owned temporary path is invalid")
        path.unlink()


def main() -> None:
    if os.geteuid() != 0 or len(sys.argv) != 3:
        raise SystemExit(2)
    _layout()
    with LOCK.open("a+") as lock:
        os.chmod(LOCK, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        _cleanup_temps()
        value = _decode(sys.argv[2])
        operation = sys.argv[1]
        if operation == "principals":
            provision(value)
        elif operation == "plant":
            plant(value)
        elif operation == "observe":
            observe(value)
        elif operation == "health-open":
            health_open(value)
        elif operation == "health-close":
            health_close(value)
        else:
            raise SystemExit(2)


if __name__ == "__main__":
    main()
