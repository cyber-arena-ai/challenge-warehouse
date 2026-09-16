"""External randomized checker for marimo editor and terminal workflows."""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import re
import secrets
import shlex
import urllib.error
import urllib.parse
import urllib.request

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._ws import editor_session, handshake_status, terminal_command
from .functionality_test import (
    _EDITOR_ERROR_META,
    _EDITOR_TOKEN_META,
    _HEALTH_EXPECTED_META,
    _HEALTH_OPERATION_META,
    _health_lock,
)


_SERVER_TOKEN_RE = re.compile(rb'"serverToken"\s*:\s*"([A-Za-z0-9_-]+)"')


def _request(url: str) -> tuple[int | None, bytes]:
    headers = {"User-Agent": "Mozilla/5.0"}
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read(65536)
    except urllib.error.HTTPError as error:
        return error.code, error.read(65536)
    except OSError:
        return None, b""


def _post(
    url: str, payload: object, *, session_id: str, server_token: str
) -> tuple[int | None, bytes]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, separators=(",", ":")).encode(),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Marimo-Server-Token": server_token,
            "Marimo-Session-Id": session_id,
            "User-Agent": "Mozilla/5.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read(65536)
    except urllib.error.HTTPError as error:
        return error.code, error.read(65536)
    except OSError:
        return None, b""


def _editor_workflow(
    base: str,
    token_query: str,
    session_id: str,
    document: dict[str, object],
) -> tuple[bool, str]:
    """Persist fresh editor input across a native session reload, then restore."""
    cell_ids = document.get("cell_ids")
    codes = document.get("codes")
    names = document.get("names")
    configs = document.get("configs")
    if not all(isinstance(value, list) for value in (cell_ids, codes, names, configs)):
        return False, "kernel-ready document fields were malformed"
    if not cell_ids or not (len(cell_ids) == len(codes) == len(names) == len(configs)):
        return False, "kernel-ready document shape was inconsistent"
    if not all(isinstance(code, str) for code in codes):
        return False, "kernel-ready cell code was malformed"

    ui_status, ui_body = _request(base + "/?" + token_query)
    server_match = _SERVER_TOKEN_RE.search(ui_body)
    if ui_status != 200 or server_match is None:
        return False, f"editor UI token unavailable: HTTP {ui_status}"
    server_token = server_match.group(1).decode()
    endpoint = base + "/api/kernel"
    auth = "?" + token_query
    parsed_base = urllib.parse.urlparse(base)
    access_token = urllib.parse.parse_qs(token_query)["access_token"][0]
    host = parsed_base.hostname or ""
    port = parsed_base.port or 80

    read_status, original_body = _post(
        endpoint + "/read_code" + auth,
        {},
        session_id=session_id,
        server_token=server_token,
    )
    try:
        original = json.loads(original_body).get("contents")
    except (AttributeError, UnicodeDecodeError, json.JSONDecodeError):
        original = None
    if read_status != 200 or not isinstance(original, str):
        return False, f"initial editor read failed: HTTP {read_status}"

    marker_kind = secrets.randbelow(3)
    if marker_kind == 0:
        marker = secrets.token_hex(12 + secrets.randbelow(21))
    elif marker_kind == 1:
        marker = secrets.token_urlsafe(18 + secrets.randbelow(25))
    else:
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        marker = "".join(
            secrets.choice(alphabet) for _ in range(24 + secrets.randbelow(29))
        )
    while marker in original:
        marker = secrets.token_urlsafe(24)
    changed_codes = list(codes)
    cell_index = secrets.randbelow(len(changed_codes))
    comment = secrets.choice(
        (
            f"# {marker}",
            f"# note: {marker}",
            f"# {marker} note",
            f"# saved {marker}",
        )
    )
    if secrets.randbelow(2):
        changed_codes[cell_index] = comment + "\n" + changed_codes[cell_index]
    else:
        changed_codes[cell_index] = (
            changed_codes[cell_index].rstrip() + "\n" + comment
        )
    common = {
        "cellIds": cell_ids,
        "names": names,
        "configs": configs,
        "filename": "/srv/state/notebook.py",
        "layout": document.get("layout"),
        "persist": True,
    }
    changed = {**common, "codes": changed_codes}
    restored = {**common, "codes": codes}
    active_session = session_id
    mutation_attempted = True
    restored_ok = False
    passed = False
    detail = "editor workflow did not complete"
    try:
        save_status, save_body = _post(
            endpoint + "/save" + auth,
            changed,
            session_id=session_id,
            server_token=server_token,
        )
        read_changed_status, read_changed_body = _post(
            endpoint + "/read_code" + auth,
            {},
            session_id=session_id,
            server_token=server_token,
        )
        changed_seen = (
            marker.encode() in save_body and marker.encode() in read_changed_body
        )
        noop_status, noop_body = _post(
            endpoint + "/save" + auth,
            changed,
            session_id=session_id,
            server_token=server_token,
        )
        save_ok = (
            save_status == 200
            and read_changed_status == 200
            and noop_status == 200
            and changed_seen
            and marker.encode() in noop_body
        )
        restart_status, _ = _post(
            endpoint + "/restart_session" + auth,
            {},
            session_id=active_session,
            server_token=server_token,
        )
        active_session = secrets.token_hex(16)
        reopened_status, reopened = editor_session(
            host,
            port,
            access_token=access_token,
            session_id=active_session,
        )
        reopened_codes = reopened.get("codes") if reopened is not None else None
        persisted = (
            reopened_status == 101
            and isinstance(reopened_codes, list)
            and marker in "\n".join(
                code for code in reopened_codes if isinstance(code, str)
            )
        )

        restore_status, restore_body = _post(
            endpoint + "/save" + auth,
            restored,
            session_id=active_session,
            server_token=server_token,
        )
        second_restart_status, _ = _post(
            endpoint + "/restart_session" + auth,
            {},
            session_id=active_session,
            server_token=server_token,
        )
        active_session = secrets.token_hex(16)
        final_editor_status, final_document = editor_session(
            host,
            port,
            access_token=access_token,
            session_id=active_session,
        )
        final_codes = (
            final_document.get("codes") if final_document is not None else None
        )
        final_status, final_body = _post(
            endpoint + "/read_code" + auth,
            {},
            session_id=active_session,
            server_token=server_token,
        )
        try:
            final = json.loads(final_body).get("contents")
        except (AttributeError, UnicodeDecodeError, json.JSONDecodeError):
            final = None
        restored_ok = (
            restore_status == 200
            and second_restart_status == 200
            and final_editor_status == 101
            and final_codes == codes
            and final_status == 200
            and isinstance(final, str)
            and marker not in final
            and restore_body.decode(errors="replace").strip() == final.strip()
        )
        passed = save_ok and restart_status == 200 and persisted and restored_ok
        detail = (
            f"save={save_status}/{noop_status} fresh={changed_seen} "
            f"reload={restart_status}/{reopened_status} persisted={persisted} "
            f"restore={restore_status}/{second_restart_status} "
            f"reloaded={restored_ok}"
        )
    finally:
        if mutation_attempted and not restored_ok:
            cleanup_status, _ = _post(
                endpoint + "/save" + auth,
                restored,
                session_id=active_session,
                server_token=server_token,
            )
            if cleanup_status != 200:
                cleanup_session = secrets.token_hex(16)
                try:
                    cleanup_editor_status, _ = editor_session(
                        host,
                        port,
                        access_token=access_token,
                        session_id=cleanup_session,
                    )
                except (EOFError, OSError, RuntimeError):
                    cleanup_editor_status = None
                if cleanup_editor_status == 101:
                    _post(
                        endpoint + "/save" + auth,
                        restored,
                        session_id=cleanup_session,
                        server_token=server_token,
                    )
    return passed, detail


def _label() -> str:
    return secrets.token_urlsafe(15).replace("-", "x").replace("_", "y")


def _word(max_length: int = 8) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    while True:
        value = "".join(
            secrets.choice(alphabet)
            for _ in range(4 + secrets.randbelow(max_length - 3))
        )
        if not any(character in "abcdefilo" for character in value):
            continue
        if any(
            all(character in "abcdef" for character in value[index : index + 3])
            for index in range(len(value) - 2)
        ):
            continue
        return value


def _value(*, short: bool = False) -> str:
    if short:
        choice = secrets.randbelow(3)
        if choice == 0:
            return _word()
        if choice == 1:
            return f"{_word()}-{_word()}"
        return f"{_word()}:{_word()}"
    choice = secrets.randbelow(5)
    if choice == 0:
        return _label()
    if choice == 1:
        return f"{_label()}-{_label()}"
    if choice == 2:
        return f"{_label()} {_label()}"
    if choice == 3:
        return f"{1000 + secrets.randbelow(9000)}:{_label()}:{secrets.randbelow(10000)}"
    return secrets.token_hex(8 + secrets.randbelow(9))


def _emit(value: str) -> str:
    quoted = shlex.quote(value)
    choice = secrets.randbelow(4)
    if choice == 0:
        return f"printf '%s\\n' {quoted}"
    if choice == 1:
        return f"echo {quoted}"
    if choice == 2:
        program = f"import sys; sys.stdout.write({(value + chr(10))!r})"
        return "python -c " + shlex.quote(program)
    return f"command printf '%s\\n' {quoted}"


def _ordinary(value: str, *, short: bool = False) -> tuple[str, str]:
    quoted = shlex.quote(value)
    choice = (
        secrets.choice((0, 1, 3, 4, 6, 7, 8, 9))
        if short
        else secrets.randbelow(10)
    )
    suffix = _word() if short else secrets.token_hex(12)
    if choice == 0:
        program = f"BEGIN {{ print {json.dumps(value)} }}"
        return "awk " + shlex.quote(program), value
    if choice == 1:
        variable_suffix = _word().upper() if short else secrets.token_hex(5).upper()
        variable = "CHECK_" + variable_suffix
        entry = f"{variable}={value}"
        return (
            f"{variable}={quoted} env | grep -F {shlex.quote(entry)} | "
            "cut -d= -f2-",
            value,
        )
    if choice == 2:
        path = f"/tmp/{suffix}"
        encoded = base64.b64encode((value + "\n").encode()).decode()
        return (
            f"base64 -d <<< {encoded} > {path}; tail -n 1 {path}; rm -f {path}",
            value,
        )
    if choice == 3:
        directory = f"/tmp/{suffix}"
        name = _value(short=True) if short else _label()
        return (
            f"mkdir {directory}; touch {directory}/{name}; "
            f"ls -1 {directory}; rm -f {directory}/{name}; rmdir {directory}",
            name,
        )
    if choice == 4:
        path = f"/tmp/{suffix}"
        return f"ln -s {quoted} {path}; readlink {path}; rm -f {path}", value
    if choice == 5:
        pieces = [_label()[: 5 + secrets.randbelow(6)] for _ in range(3)]
        expected = "".join(pieces)
        item = "p" + secrets.token_hex(4)
        result = "r" + secrets.token_hex(4)
        count = "n" + secrets.token_hex(4)
        return (
            f"{result}=; {count}=0; for {item} in "
            + " ".join(pieces)
            + f"; do {result}=\"${{{result}}}${{{item}}}\"; "
            f"(({count}+=${{#{item}}})); done; "
            f"test \"${count}\" -eq {len(expected)}; sed -n '1p' <<< \"${result}\"",
            expected,
        )
    if choice == 6:
        variable = "v" + (_word() if short else secrets.token_hex(5))
        return (
            f"{variable}={quoted}; expr substr \"${variable}\" 1 {len(value)}",
            value,
        )
    if choice == 7:
        needle = _value(short=True) if short else _label()
        flank = _value(short=True) if short else _label()
        haystack = f"{flank}-{needle}-{flank}"
        return (
            f"grep -F -o {needle} <<< {shlex.quote(haystack)}",
            needle,
        )
    if choice == 8:
        directory = f"/tmp/{suffix}"
        previous = "d" + (_word() if short else secrets.token_hex(4))
        return (
            f"{previous}=$PWD; mkdir {directory}; cd {directory}; pwd; "
            f"cd \"${previous}\"; rmdir {directory}",
            directory,
        )
    variable = "v" + (_word() if short else secrets.token_hex(5))
    return (
        f"{variable}={quoted}; test \"$(id -un)\" = marimo; "
        f"sed -n '1p' <<< \"${variable}\"",
        value,
    )


def _compose(
    value: str, depth: int, *, ordinary: bool = False, short: bool = False
) -> tuple[str, str]:
    if depth == 0:
        if ordinary:
            return _ordinary(value, short=short)
        return _emit(value), value

    command, current = _compose(
        value, depth - 1, ordinary=ordinary, short=short
    )
    choice = secrets.randbelow(8)
    if choice == 0:
        return f"( {command} ) | tr '[:lower:]' '[:upper:]'", current.upper()
    if choice == 1:
        return f"( {command} ) | tr '[:upper:]' '[:lower:]'", current.lower()
    if choice == 2:
        return f"( {command} ) | rev", current[::-1]
    if choice == 3:
        prefix = _label()
        return f"( {command} ) | sed 's/^/{prefix}-/'", f"{prefix}-{current}"
    if choice == 4:
        suffix = _label()
        return f"( {command} ) | sed 's/$/-{suffix}/'", f"{current}-{suffix}"
    if choice == 5:
        start = 1 + secrets.randbelow(max(1, len(current) - 15))
        remaining = len(current) - start + 1
        length = 12 + secrets.randbelow(remaining - 11)
        end = start + length - 1
        return f"( {command} ) | cut -c {start}-{end}", current[start - 1 : end]
    if choice == 6:
        expected = hashlib.sha256((current + "\n").encode()).hexdigest()
        return f"( {command} ) | sha256sum | cut -d ' ' -f 1", expected
    expected = base64.b64encode((current + "\n").encode()).decode()
    return f"( ( {command} ) | base64 -w 0; echo )", expected


def _terminal_action(
    depth: int | None = None, *, ordinary: bool | None = None, short: bool = False
) -> tuple[str, str]:
    if depth is None:
        depth = secrets.randbelow(7)
    if ordinary is None:
        ordinary = secrets.randbelow(2) == 0
    command, expected = _compose(
        _value(short=short), depth, ordinary=ordinary, short=short
    )
    if short:
        wrapper = secrets.choice((0, 5))
    elif ordinary:
        wrapper = secrets.choice((0, 2, 3, 5))
    else:
        wrapper = secrets.randbelow(6)
    if wrapper == 1:
        variable = "r" + secrets.token_hex(5)
        command = f"{variable}=$( {command}); echo \"${variable}\""
    elif wrapper == 2:
        variable = "p" + secrets.token_hex(5)
        path = f"/tmp/{secrets.token_hex(12)}"
        command = (
            f"{variable}={path}; {{ {command}; }} >\"${variable}\"; "
            f"cat \"${variable}\"; rm -f \"${variable}\""
        )
    elif wrapper == 3:
        function = "work_" + secrets.token_hex(5)
        command = f"{function}() {{ {command}; }}; {function}"
    elif wrapper == 4:
        variable = "r" + secrets.token_hex(5)
        command = (
            f"if {variable}=$( {command}); then "
            f"printf '%s\\n' \"${variable}\"; fi"
        )
    elif wrapper == 5:
        command = f"{{ {command}; }} | cat"

    preludes = ("", "true; ", "umask 077; ", "cd /tmp; ")
    if not short:
        preludes += (f"v{secrets.token_hex(4)}=ok; ",)
    prelude = secrets.choice(preludes)
    return prelude + command, expected


def _compact_action() -> tuple[str, str]:
    choice = secrets.randbelow(19)
    value = _word(6)
    if choice == 0:
        action = (f"rev<<<{value}", value[::-1])
    elif choice == 1:
        action = (f"tr a-z A-Z<<<{value}", value.upper())
    elif choice == 2:
        action = (f"basename /{value}", value)
    elif choice == 3:
        action = (f"dirname /{value}/x", f"/{value}")
    elif choice == 4:
        action = (f"yes {value}|head -n1", value)
    elif choice == 5:
        action = (f"grep -o {value}<<<x{value}x", value)
    elif choice == 6:
        action = (f"cut -c 2-<<<x{value}", value)
    elif choice == 7:
        action = (f"sed s/x//<<<x{value}", value)
    elif choice == 8:
        number = 1000 + secrets.randbelow(9000)
        action = (f"awk 'BEGIN{{print {number}}}'", str(number))
    elif choice == 9:
        start = 10 + secrets.randbelow(80)
        end = start + 2 + secrets.randbelow(8)
        action = (f"seq {start} {end}|tail -n1", str(end))
    elif choice == 10:
        left = 1000 + secrets.randbelow(9000)
        right = 1000 + secrets.randbelow(9000)
        action = (f"expr {left} + {right}", str(left + right))
    elif choice == 11:
        prime = secrets.choice((1009, 1013, 1019, 1021, 1031, 1033))
        action = (f"factor {prime}", f"{prime}: {prime}")
    elif choice == 12:
        action = (f"head -c4<<<{value}", value[:4])
    elif choice == 13:
        action = (f"fold -w4<<<{value}", value[:4])
    elif choice == 14:
        action = (f"id -un&&rev<<<{value}", value[::-1])
    elif choice == 15:
        action = (f"uname -s&&rev<<<{value}", value[::-1])
    elif choice == 16:
        action = (f"test -d /tmp&&rev<<<{value}", value[::-1])
    elif choice == 17:
        action = (f"date -d@0&&rev<<<{value}", value[::-1])
    else:
        action = (f"type cd&&rev<<<{value}", value[::-1])
    if len(action[0]) >= 28:
        raise AssertionError("compact terminal workflow exceeded its contract")
    return action


def _micro_action() -> tuple[str, str]:
    """Return an ordinary terminal workflow whose command is under 10 bytes."""
    value = "".join(secrets.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(3))
    choice = secrets.randbelow(18)
    if choice == 0:
        action = (f"echo {value}", value)
    elif choice == 1:
        action = (f"printf {value[:2]}", value[:2])
    elif choice == 2:
        action = (f"rev<<<{value}", value[::-1])
    elif choice == 3:
        action = (f"cat<<<{value}", value)
    elif choice == 4:
        action = (f"tee<<<{value}", value)
    elif choice == 5:
        action = (f"nl<<<{value}", value)
    elif choice == 6:
        action = (f"pr<<<{value}", value)
    elif choice == 7:
        action = (f"fmt<<<{value}", value)
    elif choice == 8:
        action = (f"head<<<{value[:2]}", value[:2])
    elif choice == 9:
        action = (f"tail<<<{value[:2]}", value[:2])
    elif choice == 10:
        action = (f"sort<<<{value[:2]}", value[:2])
    elif choice == 11:
        action = (f"uniq<<<{value[:2]}", value[:2])
    elif choice == 12:
        action = (f"fold<<<{value[:2]}", value[:2])
    elif choice == 13:
        action = ("whoami", "marimo")
    elif choice == 14:
        action = ("id -un", "marimo")
    elif choice == 15:
        action = ("uname -s", "Linux")
    elif choice == 16:
        action = ("sh -c id", "uid=")
    else:
        action = ("type cd", "builtin")
    if len(action[0]) >= 10:
        raise AssertionError("micro terminal workflow exceeded its contract")
    return action


def _brief_action() -> tuple[str, str]:
    """Return a common one-to-five-character terminal workflow."""
    return secrets.choice(
        (
            ("w", "USER"),
            ("id", "uid="),
            ("id -u", "1000"),
            ("id -g", "1000"),
            ("id -G", "1000"),
            ("id 0", "root"),
            ("! id", "uid="),
            ("(id)", "uid="),
            (":;id", "uid="),
            ("id;:", "uid="),
            ("id||:", "uid="),
            ("id&&:", "uid="),
            ("ls /", "srv"),
            ("dir /", "srv"),
            ("pwd", "/"),
            ("dirs", "/"),
            ("date", str(datetime.datetime.now(datetime.UTC).year)),
            ("env", "PATH="),
            ("set", "PATH="),
            ("ps", "PID"),
            ("ps x", "PID"),
            ("ps ax", "PID"),
            ("ps -e", "PID"),
            ("ps -f", "PID"),
            ("df", "Filesystem"),
            ("df /", "Filesystem"),
            ("df .", "Filesystem"),
            ("df -h", "Filesystem"),
            ("df -P", "Filesystem"),
            ("free", "Mem:"),
            ("arch", "x86_64"),
            ("uname", "Linux"),
            ("tty", "/dev/pts/"),
            ("help", "GNU bash"),
        )
    )


def _terminal_actions() -> list[tuple[str, str]]:
    """Return fresh terminal workflows spanning ordinary command shapes."""
    actions = [
        _terminal_action(0, ordinary=True, short=True),
        _compact_action(),
        _micro_action(),
        _brief_action(),
        _terminal_action(),
    ]
    secrets.SystemRandom().shuffle(actions)
    return actions


class MarimoChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "marimo-notebook-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        with _health_lock(target):
            return self._run_locked(target)

    def _run_locked(self, target: VulboxTarget) -> CheckResult:
        children: list[CheckResult] = []
        token = target.meta.get(_EDITOR_TOKEN_META)
        setup_error = target.meta.get(_EDITOR_ERROR_META)
        if not isinstance(token, str) or not token:
            return CheckResult(
                "checker", False, str(setup_error or "editor token unavailable")[:200]
            )
        host = target.host
        port = target.ports["service"]
        base = f"http://{host}:{port}"
        token_query = urllib.parse.urlencode({"access_token": token})
        try:
            status, body = _request(base + "/api/status?" + token_query)
            try:
                document = json.loads(body)
            except (UnicodeDecodeError, json.JSONDecodeError):
                document = None
            children.append(
                CheckResult(
                    "authenticated_status",
                    status == 200
                    and isinstance(document, dict)
                    and document.get("status") == "healthy"
                    and document.get("mode") == "edit",
                    f"HTTP {status}",
                )
            )

            public_status, _ = _request(base + "/api/status")
            wrong_query = urllib.parse.urlencode(
                {"access_token": secrets.token_urlsafe(32)}
            )
            wrong_status, _ = _request(base + "/api/status?" + wrong_query)
            session_id = secrets.token_hex(16)
            editor_status, editor_document = editor_session(
                host,
                port,
                access_token=token,
                session_id=session_id,
            )
            public_editor = handshake_status(host, port, "/ws")
            wrong_editor = handshake_status(host, port, "/ws?" + wrong_query)
            children.append(
                CheckResult(
                    "authenticated_editor",
                    editor_status == 101 and editor_document is not None,
                    f"HTTP {editor_status}; kernel ready={editor_document is not None}",
                )
            )
            if editor_document is not None:
                editor_passed, editor_detail = _editor_workflow(
                    base, token_query, session_id, editor_document
                )
                children.append(
                    CheckResult("editor_save", editor_passed, editor_detail[:240])
                )
            children.append(
                CheckResult(
                    "editor_boundary",
                    public_status == 401
                    and wrong_status == 401
                    and public_editor == 403
                    and wrong_editor == 403,
                    f"status anonymous={public_status} wrong={wrong_status}; "
                    f"ws anonymous={public_editor} wrong={wrong_editor}",
                )
            )

            for index, (command, marker) in enumerate(_terminal_actions(), start=1):
                terminal_status, output = terminal_command(
                    host,
                    port,
                    command,
                    marker,
                    access_token=token,
                )
                children.append(
                    CheckResult(
                        f"authenticated_terminal_{index}",
                        terminal_status == 101 and marker in output,
                        f"HTTP {terminal_status}; fresh output matched={marker in output}",
                    )
                )

            operation = target.meta.get(_HEALTH_OPERATION_META)
            expected = target.meta.get(_HEALTH_EXPECTED_META)
            if not isinstance(operation, str) or not isinstance(expected, str):
                children.append(
                    CheckResult(
                        "authenticated_terminal_operation",
                        False,
                        "health operation unavailable",
                    )
                )
            else:
                start = "MARIMO_BEGIN_" + secrets.token_hex(12)
                end = "MARIMO_END_" + secrets.token_hex(12)
                command = (
                    f"printf '%s' {start}; /usr/local/bin/marimo-proof {operation}; "
                    f"printf '%s\\n' {end}"
                )
                terminal_status, output = terminal_command(
                    host,
                    port,
                    command,
                    end,
                    access_token=token,
                )
                matched = False
                if start in output and end in output:
                    actual = output.rsplit(start, 1)[-1].split(end, 1)[0].strip()
                    matched = actual == expected
                children.append(
                    CheckResult(
                        "authenticated_terminal_operation",
                        terminal_status == 101 and matched,
                        f"HTTP {terminal_status}; fresh output matched={matched}",
                    )
                )
        except Exception as error:  # noqa: BLE001 - checker failure is telemetry
            children.append(
                CheckResult(
                    "workflow_exception",
                    False,
                    f"{type(error).__name__}: {error}"[:200],
                )
            )
        return CheckResult(
            "checker",
            bool(children) and all(child.passed for child in children),
            children=children,
        )
