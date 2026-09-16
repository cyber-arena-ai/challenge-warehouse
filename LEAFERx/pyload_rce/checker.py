"""External semantic check of pyLoad's ordinary and Click'N'Load workflows."""

from __future__ import annotations

import secrets
import threading
import time

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._client import (
    LOOPBACK_HOSTS,
    _download_url,
    add_encrypted_package,
    document,
    guarded_status,
    package_rows,
    rpc,
    status_document,
)
from ._ids import principal_credentials, valid_password


_STATUS_KEYS = {"pause", "active", "queue", "total", "speed", "download"}
_PACKAGE_ALPHABET = "".join(chr(codepoint) for codepoint in range(32, 127))
_LOCKS_GUARD = threading.Lock()
_LOCKS: dict[tuple[str, int], threading.Lock] = {}


def _fresh_package() -> tuple[str, str]:
    package_length = 1 + secrets.randbelow(128)
    package = "".join(
        secrets.choice(_PACKAGE_ALPHABET) for _ in range(package_length)
    )
    return package, _download_url()


def _admin_password(target: VulboxTarget) -> str:
    exec_stdin = target.meta.get("exec_stdin")
    if exec_stdin is None:
        raise RuntimeError("trusted administrator transport is unavailable")
    script = b"#!/bin/sh\nexec /arena/facility.py health-admin\n"
    rc, output, _error, timed_out = exec_stdin(script)
    if timed_out or rc != 0:
        raise RuntimeError(f"trusted administrator lookup failed (rc={rc})")
    password = (output or "").strip()
    if not valid_password(password):
        raise RuntimeError("trusted administrator lookup returned malformed output")
    return password


def _target_lock(target: VulboxTarget) -> threading.Lock:
    key = (target.host, target.ports["web"])
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(key, threading.Lock())


def _collector(host: str, username: str, password: str, port: int) -> list[dict]:
    status, raw = rpc(
        host, "get_collector", username, password, port=port
    )
    return package_rows(document(status, raw, "get_collector"))


def _user_records(
    host: str, username: str, password: str, port: int
) -> dict[str, int]:
    status, raw = rpc(host, "get_all_userdata", username, password, port=port)
    value = document(status, raw, "get_all_userdata")
    if not isinstance(value, dict):
        raise RuntimeError("get_all_userdata returned the wrong shape")
    records: dict[str, int] = {}
    for raw_id, row in value.items():
        try:
            user_id = int(raw_id)
        except (TypeError, ValueError) as error:
            raise RuntimeError("get_all_userdata returned malformed data") from error
        name = row.get("name") if isinstance(row, dict) else None
        if not isinstance(name, str) or name in records or user_id <= 0:
            raise RuntimeError("get_all_userdata returned malformed data")
        records[name] = user_id
    if len(records) != len(value):
        raise RuntimeError("get_all_userdata returned malformed data")
    return records


def _create_accounts(
    host: str,
    admin_password: str,
    port: int,
    accounts: list[tuple[str, str, int | None]],
) -> None:
    for _ in range(2):
        records = _user_records(host, "pyload", admin_password, port)
        for _attempt in range(16):
            username, password = principal_credentials(secrets.token_hex(32))
            if username not in records and all(
                account[0] != username for account in accounts
            ):
                break
        else:
            raise RuntimeError("fresh ordinary identity repeatedly collided")
        accounts.append((username, password, None))
        status, raw = rpc(
            host,
            "add_user",
            "pyload",
            admin_password,
            port=port,
            user=username,
            newpw=password,
            role=1,
            perms=20,
        )
        if document(status, raw, "add_user") is not True:
            raise RuntimeError("native ordinary user creation failed")
        user_id = _user_records(host, "pyload", admin_password, port).get(username)
        if not isinstance(user_id, int):
            raise RuntimeError("native ordinary user creation was not observable")
        accounts[-1] = (username, password, user_id)


def _package_links(
    host: str,
    username: str,
    password: str,
    package_id: int,
    port: int,
) -> list[dict]:
    status, raw = rpc(
        host,
        "get_package_data",
        username,
        password,
        port=port,
        package_id=package_id,
    )
    value = document(status, raw, "get_package_data")
    links = value.get("links") if isinstance(value, dict) else None
    if not isinstance(links, list) or not all(
        isinstance(link, dict) for link in links
    ):
        raise RuntimeError("get_package_data returned the wrong shape")
    return links


def _package_id_for_url(
    host: str,
    username: str,
    password: str,
    package: str,
    expected_url: str,
    port: int,
) -> int | None:
    matches = [
        row
        for row in _collector(host, username, password, port)
        if row.get("name") == package
    ]
    matching_ids = []
    for row in matches:
        package_id = row.get("pid")
        if not isinstance(package_id, int):
            continue
        links = _package_links(host, username, password, package_id, port)
        if (
            len(links) == 1
            and links[0].get("package_id") == package_id
            and links[0].get("url") == expected_url
        ):
            matching_ids.append(package_id)
    return matching_ids[0] if len(matching_ids) == 1 else None


def _wait_for_package(
    host: str,
    username: str,
    password: str,
    package: str,
    expected_url: str,
    port: int,
) -> int:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        package_id = _package_id_for_url(
            host, username, password, package, expected_url, port
        )
        if isinstance(package_id, int):
            return package_id
        time.sleep(0.25)
    raise RuntimeError("fresh Click'N'Load package was not observable")


def _exercise(
    target: VulboxTarget,
    accounts: list[tuple[str, str, int | None]],
    packages: list[tuple[str, str, int | None]],
) -> None:
    host = target.host
    port = target.ports["web"]
    for username, password, _user_id in accounts:
        status = status_document(host, username, password, port=port)
        if not _STATUS_KEYS <= set(status):
            raise RuntimeError("ordinary status omitted native fields")
        if guarded_status(host, username, password, port=port) != 401:
            raise RuntimeError("ordinary user crossed the settings boundary")
    default_status, _ = rpc(host, "status_server", "pyload", "pyload", port=port)
    if default_status != 401:
        raise RuntimeError("published administrator credential remained valid")

    for package, expected_url, package_id in packages:
        observed_ids = [
            _wait_for_package(
                host, username, password, package, expected_url, port
            )
            for username, password, _user_id in accounts
        ]
        if observed_ids != [package_id, package_id]:
            raise RuntimeError(
                "ordinary users observed inconsistent package state"
            )


def _cleanup(
    target: VulboxTarget,
    admin_password: str,
    packages: list[tuple[str, str, int | None]],
    accounts: list[tuple[str, str, int | None]],
) -> None:
    host = target.host
    port = target.ports["web"]
    errors: list[str] = []
    for package, expected_url, package_id in packages:
        failure: Exception | None = None
        for attempt in range(2):
            try:
                if package_id is None:
                    package_id = _package_id_for_url(
                        host,
                        "pyload",
                        admin_password,
                        package,
                        expected_url,
                        port,
                    )
                if package_id is not None:
                    rows = [
                        row
                        for row in _collector(
                            host, "pyload", admin_password, port
                        )
                        if row.get("pid") == package_id
                    ]
                    if rows:
                        links = _package_links(
                            host, "pyload", admin_password, package_id, port
                        )
                        if (
                            len(rows) != 1
                            or rows[0].get("name") != package
                            or len(links) != 1
                            or links[0].get("package_id") != package_id
                            or links[0].get("url") != expected_url
                        ):
                            raise RuntimeError(
                                "health package ownership was not established"
                            )
                        try:
                            status, raw = rpc(
                                host,
                                "delete_packages",
                                "pyload",
                                admin_password,
                                port=port,
                                package_ids=[package_id],
                            )
                            document(status, raw, "delete_packages")
                        except OSError:
                            raise
                        except Exception:
                            pass
                    if any(
                        row.get("pid") == package_id
                        for row in _collector(
                            host, "pyload", admin_password, port
                        )
                    ):
                        raise RuntimeError(
                            "native health package cleanup did not converge"
                        )
                failure = None
                break
            except OSError as error:
                failure = error
                if attempt == 0:
                    time.sleep(0.25)
                    continue
                break
            except Exception as error:
                failure = error
                break
        if failure is not None:
            errors.append(
                f"package: {type(failure).__name__}: {str(failure)[:160]}"
            )
    for username, password, user_id in accounts:
        failure = None
        for attempt in range(2):
            try:
                records = _user_records(host, "pyload", admin_password, port)
                if username not in records:
                    failure = None
                    break
                if user_id is None:
                    status = status_document(
                        host, username, password, port=port
                    )
                    if not _STATUS_KEYS <= set(status):
                        raise RuntimeError(
                            "health account ownership was not established"
                        )
                elif records[username] != user_id:
                    raise RuntimeError(
                        "health account ownership was not established"
                    )
                try:
                    status, raw = rpc(
                        host,
                        "remove_user",
                        "pyload",
                        admin_password,
                        port=port,
                        user=username,
                    )
                    document(status, raw, "remove_user")
                except OSError:
                    raise
                except Exception:
                    pass
                records = _user_records(host, "pyload", admin_password, port)
                if username in records:
                    raise RuntimeError(
                        "native health account cleanup did not converge"
                    )
                failure = None
                break
            except OSError as error:
                failure = error
                if attempt == 0:
                    time.sleep(0.25)
                    continue
                break
            except Exception as error:
                failure = error
                break
        if failure is not None:
            errors.append(
                f"account: {type(failure).__name__}: {str(failure)[:160]}"
            )
    if errors:
        raise RuntimeError("; ".join(errors))


class PyloadChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "pyload-download-manager-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("web",)

    def run(self, target: VulboxTarget) -> CheckResult:
        lock = _target_lock(target)
        if not lock.acquire(timeout=150):
            return CheckResult("checker", False, "another probe did not finish")
        # One submission per Host value the upstream guard accepts, so a
        # defense serving only one of the two fails health rather than only
        # the equivalent participant request.
        packages: list[tuple[str, str, int | None]] = [
            (*_fresh_package(), None) for _ in LOOPBACK_HOSTS
        ]
        block_comment_modes = [False, True]
        secrets.SystemRandom().shuffle(block_comment_modes)
        admin_password: str | None = None
        accounts: list[tuple[str, str, int | None]] = []
        children: list[CheckResult] = []
        try:
            host = target.host
            port = target.ports["web"]
            for index, (host_header, require_block_comment) in enumerate(
                zip(LOOPBACK_HOSTS, block_comment_modes, strict=True)
            ):
                package, expected_url, _ = packages[index]
                add_status, add_body = add_encrypted_package(
                    host,
                    package,
                    expected_url,
                    host_header=host_header,
                    require_block_comment=require_block_comment,
                    port=port,
                )
                if add_status != 200 or b"could not decrypt" in add_body.lower():
                    raise RuntimeError(
                        f"Click'N'Load submission with Host {host_header} "
                        f"returned HTTP {add_status}"
                    )
            admin_password = _admin_password(target)
            for index, (package, expected_url, _) in enumerate(packages):
                packages[index] = (
                    package,
                    expected_url,
                    _wait_for_package(
                        host,
                        "pyload",
                        admin_password,
                        package,
                        expected_url,
                        port,
                    ),
                )
            _create_accounts(host, admin_password, port, accounts)
            _exercise(target, accounts, packages)
            children.append(
                CheckResult(
                    "public_workflow",
                    True,
                    "fresh ordinary status and Click'N'Load workflow passed",
                )
            )
        except Exception as error:  # checker failures are health data
            children.append(
                CheckResult(
                    "public_workflow",
                    False,
                    f"{type(error).__name__}: {str(error)[:220]}",
                )
            )
        finally:
            if admin_password is None:
                try:
                    admin_password = _admin_password(target)
                except Exception as error:
                    children.append(
                        CheckResult(
                            "cleanup",
                            False,
                            f"{type(error).__name__}: {str(error)[:220]}",
                        )
                    )
            if admin_password is not None:
                try:
                    _cleanup(target, admin_password, packages, accounts)
                    children.append(
                        CheckResult(
                            "cleanup", True, "owned account and package removed"
                        )
                    )
                except Exception as error:  # cleanup is a decisive checker leaf
                    children.append(
                        CheckResult(
                            "cleanup",
                            False,
                            f"{type(error).__name__}: {str(error)[:220]}",
                        )
                    )
            lock.release()
        return CheckResult(
            "checker",
            bool(children) and all(child.passed for child in children),
            children=children,
        )
