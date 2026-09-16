"""External checker for GeoServer's WFS, WMS, WFS-T, and layer ACLs."""

from __future__ import annotations

import secrets
import shlex
import threading
import time

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._client import GeoServerClient, feature_record, resolve_host
from ._ids import checker_principals, open_issued_cohort
from ._receipts import public_receipt_path, receipt_path, rest_receipt_path
from .journal import (
    CHECKER_LIFETIMES as _CHECKER_LIFETIMES,
    PHASE_ACTIVE as _PHASE_ACTIVE,
    PHASE_DELETE as _PHASE_DELETE,
    PHASE_INTENT as _PHASE_INTENT,
    PHASE_RECHECKED as _PHASE_RECHECKED,
    JournalEntry as _JournalEntry,
    NativeRecord as _Road,
    begin_cycle_context as _begin_cycle_context,
    begin_retirement as _begin_retirement,
    commit_journal as _commit_journal,
    decoy_record as _decoy_record,
    facility_key as _facility_key,
    finish_cycle_context as _finish_cycle_context,
    finish_retirement as _finish_retirement,
    load_journal as _load_journal,
    locate_marker as _locate_marker,
    record_matches as _record_matches,
    retirement as _retirement,
)
from .image.road_protocol import (
    GEOMETRY_X as _GEOMETRY_X,
    GEOMETRY_Y as _GEOMETRY_Y,
    WMS_BBOX as _WMS_BBOX,
    WMS_HEIGHT as _WMS_HEIGHT,
    WMS_WIDTH as _WMS_WIDTH,
    geometry_matches as _shared_geometry_matches,
    native_layer_denial as _native_layer_denial,
    png_pixels as _png_pixels,
    property_matches as _property_matches,
    render_matches as _render_matches,
    road_filter as _road_filter,
    road_label as _road_label,
    valid_png as _valid_png,
)

_RUN_LOCKS: dict[tuple[str, str, int], threading.Lock] = {}
_RUN_LOCKS_GUARD = threading.Lock()


def _run_lock(team_id: str, host: str, port: int) -> threading.Lock:
    key = (team_id, host, port)
    with _RUN_LOCKS_GUARD:
        return _RUN_LOCKS.setdefault(key, threading.Lock())


def _issued_principals(target: VulboxTarget) -> tuple[tuple[str, str], ...]:
    exec_in = target.meta.get("exec_in_container")
    if not callable(exec_in):
        raise RuntimeError("issued principal bridge is unavailable")
    rc, output = exec_in(
        target.host,
        f"{shlex.quote('/arena/facility.py')} read-issued-cohort",
    )
    if rc != 0:
        raise RuntimeError("issued principal cohort is unavailable")
    return open_issued_cohort((output or "").strip())


def _validate_issued_principal(
    base: str, credentials: tuple[str, str], slot: int,
) -> CheckResult:
    client = GeoServerClient(base, *credentials)
    children: list[CheckResult] = []

    status, body = client.capabilities()
    children.append(CheckResult(
        "capabilities", status == 200 and b"WFS_Capabilities" in body,
        f"status={status}",
    ))

    status, document = client.feature("topp:states", count=64)
    candidate = _scalar_candidate(document)
    row = feature_record(document)
    state_name = _state_name(document)
    public_ok = (
        status == 200
        and row is not None
        and candidate is not None
        and state_name is not None
    )
    children.append(CheckResult(
        "public_feature", public_ok, f"status={status}"
    ))

    if candidate is None:
        property_ok = False
        property_status = 0
    else:
        state_id, property_name, expected = candidate
        property_status, property_body = client.property_value(
            "topp:states", property_name, state_id
        )
        property_ok = (
            property_status == 200
            and _property_matches(
                property_body, "topp:states", property_name, expected
            )
        )
    children.append(CheckResult(
        "public_property_value", property_ok, f"status={property_status}"
    ))

    width = 120 + secrets.randbelow(40)
    height = 80 + secrets.randbelow(30)
    if state_name is None:
        selected_status = absent_status = 0
        selected_image = absent_image = b""
    else:
        selected_status, selected_image = client.map_png(
            width,
            height,
            layer="topp:states",
            cql_filter=f"STATE_NAME='{state_name}'",
            transparent=True,
        )
        absent_status, absent_image = client.map_png(
            width,
            height,
            layer="topp:states",
            cql_filter=f"STATE_NAME='missing_{secrets.token_hex(12)}'",
            transparent=True,
        )
    selected_pixels = _png_pixels(selected_image, width, height)
    absent_pixels = _png_pixels(absent_image, width, height)
    wms_ok = (
        selected_status == 200
        and absent_status == 200
        and selected_pixels is not None
        and absent_pixels is not None
        and selected_pixels != absent_pixels
    )
    children.append(CheckResult(
        "public_wms_map",
        wms_ok,
        f"selected={selected_status},absent={absent_status},"
        f"size={width}x{height}",
    ))

    return CheckResult(
        f"issued_principal_{slot}",
        all(child.passed for child in children),
        children=children,
    )




def _road_rows(
    client: GeoServerClient, category: int, label: str = "", *, count: int = 3,
) -> list[dict] | None:
    status, document = client.feature(
        "sf:roads", cql_filter=_road_filter(category, label), count=count
    )
    if status != 200 or not isinstance(document, dict):
        return None
    rows = document.get("features")
    if not isinstance(rows, list):
        return None
    for row in rows:
        properties = row.get("properties") if isinstance(row, dict) else None
        found_category = properties.get("cat") if isinstance(properties, dict) else None
        if (
            not isinstance(row, dict)
            or not isinstance(properties, dict)
            or not isinstance(properties.get("label"), str)
            or isinstance(found_category, bool)
            or not isinstance(found_category, (int, float))
            or found_category != category
        ):
            return None
    return rows


def _geometry_matches(document: object, expected: _Road) -> bool:
    return _shared_geometry_matches(document, expected.geometry)


def _ensure_road(client: GeoServerClient, road: _Road) -> tuple[bool, str]:
    rows = _road_rows(client, road.category)
    if rows is None:
        return False, "lookup invalid"
    status = 200
    if not rows:
        status, body = client.insert_road(
            road.label, road.category, road.geometry
        )
        rows = _road_rows(client, road.category)
        if not rows and (status != 200 or b"SUCCESS" not in body):
            return False, f"insert={status},absent=True"
    valid = len(rows) == 1 and _record_matches(rows[0], road)
    return valid, f"insert={status},unique={valid}"


def _scalar_candidate(document: object) -> tuple[str, str, str | int | float] | None:
    if not isinstance(document, dict):
        return None
    candidates: list[tuple[str, str, str | int | float]] = []
    for row in document.get("features") or []:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            continue
        properties = row.get("properties")
        if not isinstance(properties, dict):
            continue
        for name, value in properties.items():
            if (
                isinstance(name, str)
                and name
                and isinstance(value, (str, int, float))
                and not isinstance(value, bool)
                and str(value)
            ):
                candidates.append((row["id"], name, value))
    return secrets.choice(candidates) if candidates else None


def _delete_and_confirm(
    client: GeoServerClient, road: _Road,
) -> tuple[bool, str]:
    rows = _road_rows(client, road.category, road.label)
    if rows == []:
        return True, "already_absent=True"
    if rows is None or len(rows) != 1 or not _record_matches(rows[0], road):
        return False, "locator_unique=False"
    status, _ = client.delete_road(road.label, road.category)
    remaining = _road_rows(client, road.category, road.label)
    absent = remaining == []
    return (
        absent,
        f"delete={status},locator_query_valid={remaining is not None},"
        f"absent={absent}",
    )


def _state_name(document: object) -> str | None:
    if not isinstance(document, dict):
        return None
    available = {
        row["properties"].get("STATE_NAME")
        for row in document.get("features") or []
        if isinstance(row, dict) and isinstance(row.get("properties"), dict)
    }
    candidates = [
        name for name in ("Texas", "California", "Alaska", "Montana")
        if name in available
    ]
    return secrets.choice(candidates) if candidates else None


def _replace_entry(
    entries: tuple[_JournalEntry, ...], old: _JournalEntry,
    new: _JournalEntry | None,
) -> tuple[_JournalEntry, ...]:
    if entries.count(old) != 1:
        raise RuntimeError("checker journal entry is not unique")
    updated = [entry for entry in entries if entry != old]
    if new is not None:
        updated.append(new)
    return tuple(updated)


def _validate_road(
    guarded: GeoServerClient,
    issued: tuple[GeoServerClient, ...],
    road: _Road,
) -> list[CheckResult]:
    property_name = secrets.choice(("label", "cat"))
    expected = road.label if property_name == "label" else road.category
    value_status, value_body = guarded.road_property_value(
        property_name, road.category, road.label
    )
    property_ok = (
        value_status == 200
        and _property_matches(value_body, "sf:roads", property_name, expected)
    )

    selected_filter = _road_filter(road.category, road.label)
    absent_filter = _road_filter(road.category, _road_label())
    status, selected_image = guarded.map_png(
        _WMS_WIDTH, _WMS_HEIGHT, layer="sf:roads", srs="EPSG:26713",
        bbox=_WMS_BBOX, cql_filter=selected_filter, transparent=True,
    )
    absent_status, absent_image = guarded.map_png(
        _WMS_WIDTH, _WMS_HEIGHT, layer="sf:roads", srs="EPSG:26713",
        bbox=_WMS_BBOX, cql_filter=absent_filter, transparent=True,
    )
    png_ok = (
        status == 200
        and absent_status == 200
        and _render_matches(
            selected_image, absent_image, _WMS_WIDTH, _WMS_HEIGHT,
            road.geometry,
        )
    )

    results = [
        CheckResult(
            "guarded_property_value", property_ok, f"status={value_status}"
        ),
        CheckResult(
            "wms_map", png_ok,
            f"selected={status},absent={absent_status},"
            f"size={_WMS_WIDTH}x{_WMS_HEIGHT}",
        ),
    ]
    for slot, ordinary in enumerate(issued):
        denied_status, denied_doc = ordinary.feature(
            "sf:roads", cql_filter=selected_filter, count=3,
        )
        results.append(CheckResult(
            f"issued_principal_{slot}_layer_boundary",
            _native_layer_denial(denied_status, denied_doc),
            f"authorized=True,ordinary={denied_status}",
        ))
    return results


def _validate_public_receipt(
    guarded: GeoServerClient, ordinary: GeoServerClient, slot: int,
) -> CheckResult:
    relative = receipt_path()
    resource_path = rest_receipt_path(relative)
    public_path = public_receipt_path(relative)
    body = (_road_label() + "\n").encode()
    put_status, _ = guarded.put_resource(resource_path, body)
    get_status, observed = ordinary.public_resource(public_path)
    delete_status, _ = guarded.delete_resource(resource_path)
    absent_status, _ = ordinary.public_resource(public_path)
    passed = (
        put_status in (200, 201)
        and get_status == 200
        and observed == body
        and delete_status in (200, 204)
        and absent_status == 404
    )
    return CheckResult(
        f"issued_principal_{slot}_public_receipt", passed,
        f"put={put_status},get={get_status},exact={observed == body},"
        f"delete={delete_status},absent={absent_status}",
    )


class GeoServerChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "geoserver-xpath-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        try:
            team_id = str(target.meta["team_id"])
            host = resolve_host(target.host)
            port = target.ports["service"]
        except (KeyError, TypeError, ValueError, RuntimeError):
            return CheckResult("checker", False, "checker accounts unavailable")
        with _run_lock(team_id, host, port):
            return self._run_serialized(target)

    def _run_serialized(self, target: VulboxTarget) -> CheckResult:
        try:
            team_id = str(target.meta["team_id"])
            lifecycle_key = _facility_key()
            guarded_principal = checker_principals(team_id, "guarded")[0]
            issued_principals = _issued_principals(target)
            guarded = dict(zip(
                ("username", "password"), guarded_principal,
            ))
        except (KeyError, TypeError, ValueError, RuntimeError):
            return CheckResult("checker", False, "checker accounts unavailable")

        host = resolve_host(target.host)
        base = f"http://{host}:{target.ports['service']}"
        issued_apis = tuple(
            GeoServerClient(base, *credentials)
            for credentials in issued_principals
        )
        guarded_api = GeoServerClient(base, **guarded)
        now = int(time.time())
        children: list[CheckResult] = []
        try:
            for slot, credentials in enumerate(issued_principals):
                participant = _validate_issued_principal(base, credentials, slot)
                children.append(participant)
                if not participant.passed:
                    return CheckResult("checker", False, children=children)

            marker = _locate_marker(
                guarded_api, lifecycle_key, team_id
            )
            if marker is None:
                return CheckResult(
                    "checker", False,
                    children=[CheckResult(
                        "guarded_wfs_t", False,
                        "native road journal marker did not converge",
                    )],
                )
            state = _load_journal(
                guarded_api, marker, lifecycle_key, team_id, now
            )
            identities = {(entry.nonce, entry.born_at) for entry in state.entries}
            if len(identities) != len(state.entries):
                raise RuntimeError("checker journal contains conflicting phases")
            if state.stale:
                state = _commit_journal(
                    guarded_api, state, state.entries, marker,
                    lifecycle_key, team_id, now,
                )

            for entry in tuple(state.entries):
                if entry.phase == _PHASE_DELETE:
                    road = _decoy_record(entry, marker, lifecycle_key, team_id)
                    deleted, detail = _delete_and_confirm(guarded_api, road)
                    children.append(CheckResult("guarded_delete", deleted, detail))
                    if not deleted:
                        return CheckResult("checker", False, children=children)
                    state = _finish_retirement(
                        guarded_api, state, entry, marker,
                        lifecycle_key, team_id, now,
                    )
                elif entry.phase not in (
                    _PHASE_INTENT, _PHASE_ACTIVE, _PHASE_RECHECKED
                ):
                    raise RuntimeError("checker journal phase is invalid")

            cycle = _begin_cycle_context(
                guarded_api, lifecycle_key, team_id, now,
                marker=marker, state=state,
            )
            intent = cycle.intent
            state = cycle.state

            for entry in tuple(state.entries):
                if entry.phase != _PHASE_ACTIVE:
                    continue
                road = _decoy_record(entry, marker, lifecycle_key, team_id)
                rows = _road_rows(guarded_api, road.category)
                present = (
                    rows is not None
                    and len(rows) == 1
                    and _shared_geometry_matches(
                        rows[0].get("geometry"), road.geometry
                    )
                )
                children.append(CheckResult(
                    "guarded_retained", present, f"unique={present}",
                ))
                if not present:
                    return CheckResult("checker", False, children=children)
                validation = _validate_road(
                    guarded_api, issued_apis, road
                )
                children.extend(validation)
                if not all(result.passed for result in validation):
                    return CheckResult("checker", False, children=children)

            road = _decoy_record(intent, marker, lifecycle_key, team_id)
            available = _road_rows(guarded_api, road.category, count=3)
            if available is None or (
                available and not (
                    len(available) == 1
                    and _record_matches(available[0], road)
                )
            ):
                state = _commit_journal(
                    guarded_api, state,
                    _replace_entry(state.entries, intent, None), marker,
                    lifecycle_key, team_id, now,
                )
                children.append(CheckResult(
                    "guarded_wfs_t", False, "locator lookup invalid"
                ))
                return CheckResult("checker", False, children=children)
            present, detail = _ensure_road(guarded_api, road)
            children.append(CheckResult("guarded_wfs_t", present, detail))
            if not present:
                return CheckResult("checker", False, children=children)
            validation = _validate_road(guarded_api, issued_apis, road)
            children.extend(validation)
            if not all(result.passed for result in validation):
                return CheckResult("checker", False, children=children)

            cycle = _finish_cycle_context(
                guarded_api, lifecycle_key, cycle, now
            )
            state = cycle.state

            for entry in tuple(state.entries):
                if (
                    entry.phase == _PHASE_RECHECKED
                    and _retirement(entry, lifecycle_key, team_id) <= now
                ):
                    state, deleting = _begin_retirement(
                        guarded_api, state, entry, marker,
                        lifecycle_key, team_id, now,
                    )
                    road = _decoy_record(entry, marker, lifecycle_key, team_id)
                    deleted, detail = _delete_and_confirm(guarded_api, road)
                    children.append(CheckResult("guarded_delete", deleted, detail))
                    if not deleted:
                        return CheckResult("checker", False, children=children)
                    state = _finish_retirement(
                        guarded_api, state, deleting, marker,
                        lifecycle_key, team_id, now,
                    )

            children.extend(
                _validate_public_receipt(guarded_api, ordinary, slot)
                for slot, ordinary in enumerate(issued_apis)
            )

        except Exception as error:  # noqa: BLE001
            children.append(CheckResult("workflow_exception", False, str(error)))
        return CheckResult(
            "checker",
            bool(children) and all(child.passed for child in children),
            children=children,
        )
