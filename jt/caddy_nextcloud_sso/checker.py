"""External checker for SSO, WebDAV, and the native Team-Folder boundary."""

from __future__ import annotations

import secrets
import time

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._api import (
    NextcloudClient,
    resolve_host,
    unauthenticated_status,
    webdav_path,
)
from .cohort import open_issued_cohort
from ._ids import (
    CHECKER_HISTORY_MAX,
    CHECKER_LOGIN_LIMIT,
    CHECKER_LISTING_LIMIT,
    CHECKER_PRINCIPAL_COUNT,
    CHECKER_RESPONSE_LIMIT,
    checker_document_body,
    checker_document_identity,
    checker_pair_chain,
    checker_pair_seed,
    checker_pair_shadow,
    checker_pair_successor,
    document_name as _document_name,
    document_words as _words,
    guarded_principals,
    guarded_listing_targets,
)


def _document_body() -> bytes:
    sentences = []
    for _ in range(1 + secrets.randbelow(4)):
        words = _words(6, 14)
        sentences.append(
            " ".join((words[0].capitalize(), *words[1:]))
            + secrets.choice((".", ".", "?", "!"))
        )
    return " ".join(sentences).encode()


def _listed_guarded_targets(client: NextcloudClient) -> tuple[str, ...]:
    status, raw, _ = client.request(
        "PROPFIND", webdav_path(client.username, "Guarded"),
        headers={"Depth": "1", "Content-Type": "application/xml"},
        max_bytes=CHECKER_LISTING_LIMIT,
    )
    if status != 207:
        raise RuntimeError(f"guarded WebDAV listing status={status}")
    return guarded_listing_targets(client.username, raw)


class _ListingChanged(RuntimeError):
    pass


_RECONCILE_BACKOFFS = (0.05, 0.1, 0.15)


def _ordinary_denied(client: NextcloudClient, document_target: str) -> bool:
    for attempt in range(len(_RECONCILE_BACKOFFS) + 1):
        status, _ = client.webdav(
            "GET", document_target, max_bytes=CHECKER_RESPONSE_LIMIT)
        if status != 423:
            return status == 404
        if attempt < len(_RECONCILE_BACKOFFS):
            time.sleep(_RECONCILE_BACKOFFS[attempt])
    return False


def _retired(client: NextcloudClient, document_target: str) -> bool:
    for attempt in range(len(_RECONCILE_BACKOFFS) + 1):
        status, _ = client.webdav(
            "DELETE", document_target, max_bytes=CHECKER_RESPONSE_LIMIT)
        if status != 423:
            return status in (204, 404)
        if attempt < len(_RECONCILE_BACKOFFS):
            time.sleep(_RECONCILE_BACKOFFS[attempt])
    return False


def _authenticated_guarded_documents(
    team_id: str, clients: list[NextcloudClient],
) -> dict[tuple[int, str], list[str]]:
    targets = _listed_guarded_targets(clients[0])
    records = {
        (slot, kind): []
        for slot in range(CHECKER_PRINCIPAL_COUNT)
        for kind in ("control", "shadow", "cover")
    }
    for document_target in targets:
        identity = checker_document_identity(team_id, document_target)
        if identity is None:
            continue
        owner, kind = identity
        if kind != "shadow":
            expected = checker_document_body(team_id, owner, document_target)
            status, actual = clients[owner].webdav(
                "GET", document_target, max_bytes=CHECKER_RESPONSE_LIMIT)
            if status in (404, 423):
                raise _ListingChanged("guarded checker listing changed")
            if status != 200 or actual != expected:
                raise RuntimeError(
                    f"guarded checker record {owner} failed integrity")
        records[identity].append(document_target)
    return records


def _put_checker_pair(
    clients: list[NextcloudClient],
    pair: tuple[int, tuple[str, bytes], tuple[str, bytes]],
) -> None:
    owner, control, shadow = pair
    ordered = [control, shadow]
    if secrets.randbelow(2):
        ordered.reverse()
    for document_target, document_body in ordered:
        status, _ = clients[owner].webdav(
            "PUT", document_target, document_body,
            max_bytes=CHECKER_RESPONSE_LIMIT)
        if status not in (201, 204, 423):
            raise RuntimeError("guarded checker pair creation failed")


def _repair_checker_pairs(
    team_id: str,
    clients: list[NextcloudClient],
    records: dict[tuple[int, str], list[str]],
) -> bool:
    controls = {
        target: owner
        for (owner, kind), targets in records.items() if kind == "control"
        for target in targets
    }
    shadows = {
        target
        for (_owner, kind), targets in records.items() if kind == "shadow"
        for target in targets
    }
    complete = {
        control: checker_pair_shadow(team_id, owner, control)[0]
        for control, owner in controls.items()
        if checker_pair_shadow(team_id, owner, control)[0] in shadows
    }
    complete_targets = [
        target for control, shadow in complete.items()
        for target in (control, shadow)
    ]
    if complete_targets:
        queue = checker_pair_chain(team_id, complete_targets)
        expected = checker_pair_successor(team_id, queue[-1][1])
    else:
        queue = ()
        expected = checker_pair_seed(team_id)
    expected_targets = {expected[1][0], expected[2][0]}
    partial = (
        (set(controls) - set(complete)) | (shadows - set(complete.values()))
    )
    changed = False
    if partial & expected_targets:
        _put_checker_pair(clients, expected)
        partial -= expected_targets
        changed = True
    for document_target in partial:
        identity = checker_document_identity(team_id, document_target)
        if identity is None or not _retired(clients[identity[0]], document_target):
            raise RuntimeError("guarded checker pair did not reconcile")
        changed = True
    if not changed and len(queue) < CHECKER_HISTORY_MAX:
        _put_checker_pair(clients, expected)
        changed = True
    elif not changed and len(queue) > CHECKER_HISTORY_MAX:
        owner, control, shadow = queue[0]
        for document_target in (control, shadow):
            if not _retired(clients[owner], document_target):
                raise RuntimeError("guarded checker pair did not reconcile")
        changed = True
    return changed


def _reconciled_state(
    team_id: str, clients: list[NextcloudClient],
) -> tuple[
    tuple[tuple[int, str, str], ...],
    dict[int, tuple[str, ...]],
]:
    for attempt in range(2 * CHECKER_HISTORY_MAX + 1):
        try:
            records = _authenticated_guarded_documents(team_id, clients)
            if _repair_checker_pairs(team_id, clients, records):
                raise _ListingChanged("guarded checker pair state changed")
            pair_targets = [
                target
                for (_owner, kind), targets in records.items()
                if kind in ("control", "shadow")
                for target in targets
            ]
            queue = checker_pair_chain(team_id, pair_targets)
            covers = {
                slot: tuple(sorted(records[(slot, "cover")]))
                for slot in range(CHECKER_PRINCIPAL_COUNT)
            }
            if sum(map(len, covers.values())) > 2:
                raise RuntimeError("guarded objective covers exceed their bound")
            return queue, covers
        except _ListingChanged:
            if attempt < len(_RECONCILE_BACKOFFS):
                time.sleep(_RECONCILE_BACKOFFS[attempt])
            continue
    raise RuntimeError("guarded checker records did not converge")


def _guarded_lifecycle(
    team_id: str,
    ordinary_clients: list[NextcloudClient],
    guarded_clients: list[NextcloudClient],
) -> CheckResult:
    try:
        prior, covers = _reconciled_state(team_id, guarded_clients)
        for slot, control_target, _shadow_target in prior:
            for ordinary_client in ordinary_clients:
                if not _ordinary_denied(ordinary_client, control_target):
                    raise RuntimeError(
                        "issued identity reached guarded checker record "
                        f"{slot}")
        for slot, cover_targets in covers.items():
            for document_target in cover_targets:
                for ordinary_client in ordinary_clients:
                    if not _ordinary_denied(ordinary_client, document_target):
                        raise RuntimeError(
                            "issued identity reached guarded checker cover "
                            f"{slot}")

        successor = checker_pair_successor(team_id, prior[-1][1])
        owner, control, _shadow = successor
        _put_checker_pair(guarded_clients, successor)
        control_target, expected = control
        get_status, actual = guarded_clients[owner].webdav(
            "GET", control_target, max_bytes=CHECKER_RESPONSE_LIMIT)
        if get_status == 200:
            denied = [
                ordinary_client.webdav(
                    "GET", control_target, max_bytes=CHECKER_RESPONSE_LIMIT)[0]
                for ordinary_client in ordinary_clients
            ]
            if actual != expected or any(status not in (404, 423)
                                         for status in denied):
                raise RuntimeError(
                    f"successor guarded checker record {owner} failed boundary")
        elif get_status not in (404, 423):
            raise RuntimeError(
                f"successor guarded checker record {owner} failed boundary")

        retired_owner, retired_control, retired_shadow = prior[0]
        retired_pair = [retired_control, retired_shadow]
        if secrets.randbelow(2):
            retired_pair.reverse()
        for document_target in retired_pair:
            if not _retired(guarded_clients[retired_owner], document_target):
                raise RuntimeError(
                    f"checker pair {retired_owner} could not be retired")

        current, _covers = _reconciled_state(team_id, guarded_clients)
        if (len(current) != CHECKER_HISTORY_MAX
                or control_target not in {pair[1] for pair in current}):
            raise RuntimeError("guarded checker pair queue regressed")
        return CheckResult(
            "team_folder_boundary", True,
            f"rotated guarded owner={retired_owner}->{owner}; "
            f"retained records={2 * len(current)}",
        )
    except Exception as error:  # noqa: BLE001
        return CheckResult("team_folder_boundary", False, str(error))


def _issued_principals(
    target: VulboxTarget,
) -> tuple[tuple[str, str], ...]:
    exec_in = target.meta.get("exec_in_container")
    if not callable(exec_in):
        raise RuntimeError("issued principal bridge is unavailable")
    rc, output = exec_in(
        target.host, "/arena/facility.py read-issued-cohort")
    if rc != 0:
        raise RuntimeError("issued principal cohort is unavailable")
    return open_issued_cohort(target, (output or "").strip())


def _own_webdav_roundtrip(client: NextcloudClient) -> bool:
    own_target = _document_name()
    own_value = _document_body()
    put_status, _ = client.webdav(
        "PUT", own_target, own_value, max_bytes=CHECKER_RESPONSE_LIMIT)
    get_status, own_read = client.webdav(
        "GET", own_target, max_bytes=CHECKER_RESPONSE_LIMIT)
    delete_status, _ = client.webdav(
        "DELETE", own_target, max_bytes=CHECKER_RESPONSE_LIMIT)
    gone_status, _ = client.webdav(
        "GET", own_target, max_bytes=CHECKER_RESPONSE_LIMIT)
    return (
        put_status in (201, 204) and get_status == 200
        and own_read == own_value and delete_status == 204
        and gone_status == 404
    )


class CaddyNextcloudChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "caddy-nextcloud-sso-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        try:
            team_id = str(target.meta["team_id"])
            issued = _issued_principals(target)
            guarded = guarded_principals(team_id)
        except (KeyError, RuntimeError, TypeError, ValueError) as error:
            return CheckResult("checker", False, str(error))

        base = f"http://{resolve_host(target.host)}:{target.ports['service']}"
        ordinary_clients = [NextcloudClient(base, *account) for account in issued]
        guarded_clients = [NextcloudClient(base, *account)
                           for account in guarded]
        children: list[CheckResult] = []
        try:
            unauth = unauthenticated_status(base)
            children.append(CheckResult(
                "unauthenticated_denial", unauth == 401, f"status={unauth}"))

            ordinary_logins = [
                client.login(max_bytes=CHECKER_LOGIN_LIMIT)
                for client in ordinary_clients
            ]
            guarded_logins = [
                client.login(max_bytes=CHECKER_LOGIN_LIMIT)
                for client in guarded_clients
            ]
            children.append(CheckResult(
                "sso_login", all(ordinary_logins) and all(guarded_logins),
                f"issued={sum(ordinary_logins)}/{len(ordinary_logins)}, "
                f"guarded={sum(guarded_logins)}/{len(guarded_logins)}"))
            if not all(ordinary_logins) or not all(guarded_logins):
                return CheckResult("checker", False, children=children)

            own_results = [
                _own_webdav_roundtrip(client) for client in ordinary_clients
            ]
            children.append(CheckResult(
                "own_webdav_crud", all(own_results),
                f"issued={sum(own_results)}/{len(own_results)}"))

            children.append(_guarded_lifecycle(
                team_id, ordinary_clients, guarded_clients))
        except Exception as error:  # noqa: BLE001
            children.append(CheckResult("protocol_exception", False, str(error)))
        return CheckResult("checker", bool(children) and all(c.passed for c in children),
                           children=children)
