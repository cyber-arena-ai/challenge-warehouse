from __future__ import annotations

import re
import struct
import threading
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from math import floor
from xml.sax.saxutils import escape

import pytest

from challenges.interface import CheckResult, VulboxTarget
from challenges.geoserver_xpath import checker, journal
from challenges.geoserver_xpath._client import GeoServerClient
from challenges.geoserver_xpath._ids import seal_issued_cohort


def _rgba_png(
    width: int,
    height: int,
    geometry: tuple[tuple[int, int], tuple[int, int]] | None = None,
) -> bytes:
    def chunk(kind: bytes, body: bytes) -> bytes:
        return (
            len(body).to_bytes(4, "big") + kind + body
            + (zlib.crc32(kind + body) & 0xFFFFFFFF).to_bytes(4, "big")
        )

    pixels = [bytearray(width * 4) for _ in range(height)]
    if geometry is not None:
        projected = [(
            (x - checker._GEOMETRY_X[0]) * (width - 1)
            / (checker._GEOMETRY_X[1] - checker._GEOMETRY_X[0]),
            (checker._GEOMETRY_Y[1] - y) * (height - 1)
            / (checker._GEOMETRY_Y[1] - checker._GEOMETRY_Y[0]),
        ) for x, y in geometry]
        steps = max(
            1,
            int(max(
                abs(projected[1][0] - projected[0][0]),
                abs(projected[1][1] - projected[0][1]),
            )),
        )
        for step in range(steps + 1):
            amount = step / steps
            x = floor(projected[0][0] + amount * (
                projected[1][0] - projected[0][0]
            ) + 0.5)
            y = floor(projected[0][1] + amount * (
                projected[1][1] - projected[0][1]
            ) + 0.5)
            offset = x * 4
            pixels[y][offset:offset + 4] = b"\xff\0\0\xff"
    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    raw = b"".join(b"\0" + bytes(row) for row in pixels)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


def test_checker_uses_sealed_issued_cohort_with_external_http(
    monkeypatch,
) -> None:
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-secret")
    now = [1_800_000_000]
    monkeypatch.setattr(checker.time, "time", lambda: now[0])

    ordinary_principal = ("arena_" + "o" * 16, "Gs!" + "o" * 32)
    guarded_principal = ("arena_" + "g" * 16, "Gs!" + "g" * 32)
    issued_principals = (
        ("arena_" + "1" * 16, "Gs!" + "1" * 32),
        ("arena_" + "2" * 16, "Gs!" + "2" * 32),
    )
    sealed_cohort = seal_issued_cohort(issued_principals)
    disabled: set[str] = set()
    boundary_bypassed: set[str] = set()
    receipt_denied: set[str] = set()
    cohort_reads: list[str] = []

    roads: dict[str, dict[str, object]] = {}
    histories: dict[str, list[str]] = {}
    resources: dict[str, bytes] = {}
    next_id = 0

    def property_document(namespace: str, name: str, value: object) -> bytes:
        return (
            '<wfs:ValueCollection xmlns:wfs="http://www.opengis.net/wfs/2.0" '
            f'xmlns:f="{namespace}" numberMatched="1" numberReturned="1">'
            f"<wfs:member><f:{name}>{escape(str(value))}</f:{name}></wfs:member>"
            "</wfs:ValueCollection>"
        ).encode()

    class Client:
        def __init__(self, _base: str, username: str, password: str):
            self.username = username
            self.guarded = username == "arena_" + "g" * 16

        def capabilities(self):
            if self.username in disabled:
                return 401, b""
            return 200, b"WFS_Capabilities"

        def feature(self, type_name: str, *, resource_id="", cql_filter="", count=1):
            if type_name == "topp:states":
                if self.username in disabled:
                    return 401, {"features": []}
                states = {
                    "states.1": {"STATE_NAME": "Illinois"},
                    "states.2": {"STATE_NAME": "Texas"},
                }
                if resource_id:
                    return 200, {"features": [{
                        "id": resource_id, "properties": states[resource_id],
                    }]}
                return 200, {"features": [
                    {"id": feature_id, "properties": properties}
                    for feature_id, properties in states.items()
                ]}
            if cql_filter:
                match = re.fullmatch(
                    r"cat=(\d+)(?: AND label='([^']+)')?", cql_filter
                )
                assert match is not None
                wanted = int(match.group(1))
                wanted_label = match.group(2)
                matching = [
                    row for row in roads.values()
                    if row["cat"] == wanted
                    and (wanted_label is None or row["label"] == wanted_label)
                ]
                if not self.guarded:
                    for row in matching:
                        histories[row["label"]].append("ordinary")
                    if self.username in boundary_bypassed:
                        return 200, {
                            "numberMatched": len(matching),
                            "features": matching,
                        }
                    return 403, {"features": []}
                for row in matching:
                    histories[row["label"]].append("lookup")
                result = [
                    {
                        "id": feature_id,
                        "properties": {
                            "label": row["label"], "cat": row["cat"],
                        },
                        "geometry": {
                            "type": "MultiLineString",
                            "coordinates": [[list(point) for point in row["geometry"]]],
                        },
                    }
                    for feature_id, row in roads.items()
                    if row["cat"] == wanted
                    and (wanted_label is None or row["label"] == wanted_label)
                ]
                return 200, {
                    "numberMatched": len(result), "features": result,
                }
            return 403, {"features": []}

        def property_value(self, type_name: str, name: str, feature_id: str):
            if self.username in disabled:
                return 401, b""
            if type_name == "topp:states":
                value = (
                    "Texas" if feature_id == "states.2" else "Illinois"
                )
                namespace = "http://www.openplans.org/topp"
            return 200, property_document(namespace, name, value)

        def road_property_value(self, name: str, category: int, label: str):
            row = next(
                row for row in roads.values()
                if row["cat"] == category and row["label"] == label
            )
            histories[label].append("property")
            return 200, property_document(
                "http://www.openplans.org/spearfish", name, row[name]
            )

        def map_png(self, width: int, height: int, **kwargs):
            if kwargs.get("layer") == "topp:states":
                if self.username in disabled:
                    return 401, b""
                selected = "missing_" not in kwargs["cql_filter"]
                geometry = (
                    ((594000, 4917000), (596000, 4919000))
                    if selected else None
                )
                return 200, _rgba_png(width, height, geometry)
            match = re.fullmatch(
                r"cat=(\d+) AND label='([^']+)'", kwargs["cql_filter"]
            )
            assert match is not None
            geometry = next((
                row["geometry"] for row in roads.values()
                if row["cat"] == int(match.group(1))
                and row["label"] == match.group(2)
            ), None)
            category = int(match.group(1))
            if geometry is None:
                for row in roads.values():
                    if row["cat"] == category:
                        histories[row["label"]].append("wms_absent")
            else:
                histories[match.group(2)].append("wms_selected")
            return 200, _rgba_png(width, height, geometry)

        def insert_road(self, value: str, category: int, geometry):
            nonlocal next_id
            next_id += 1
            roads[f"roads.{next_id}"] = {
                "label": value, "cat": category, "geometry": geometry,
            }
            histories[value] = ["insert"]
            return 200, b"SUCCESS"

        def delete_road(self, label: str, category: int):
            for feature_id, row in list(roads.items()):
                if row["label"] == label and row["cat"] == category:
                    histories[label].append("delete")
                    roads.pop(feature_id)
            return 200, b"SUCCESS"

        def put_resource(self, path: str, body: bytes):
            assert self.guarded
            resources[path] = body
            return 201, b""

        def public_resource(self, path: str):
            if self.username in receipt_denied:
                return 404, b""
            resource_path = path.replace(
                "/geoserver/www/", "/geoserver/rest/resource/www/", 1
            )
            if resource_path in resources:
                return 200, resources[resource_path]
            return 404, b""

        def delete_resource(self, path: str):
            assert self.guarded
            resources.pop(path, None)
            return 200, b""

    monkeypatch.setattr(
        checker, "checker_principals",
        lambda _team_id, authority: (
            (guarded_principal,) if authority == "guarded" else (ordinary_principal,)
        ),
    )
    monkeypatch.setattr(checker, "GeoServerClient", Client)
    journal.initialize_journal(
        Client("", "arena_" + "g" * 16, "unused"),
        b"facility-secret", "victim",
    )
    target = VulboxTarget(
        host="prod",
        ports={"service": 8080},
        meta={
            "team_id": "victim",
            "exec_in_container": lambda _host, command: (
                cohort_reads.append(command) or (0, sealed_cohort)
            ),
        },
    )

    probe = checker.GeoServerChecker()
    assert probe.run(target).passed
    decoys = [label for label in histories if label.startswith("FLAG{")]
    assert len(decoys) == 1
    first_label = decoys[0]
    assert histories[first_label] == [
        "insert", "lookup", "property", "wms_selected", "wms_absent",
        "ordinary", "ordinary",
    ]
    first_history = list(histories[first_label])
    first_categories = {
        int(row["cat"]) for row in roads.values()
        if str(row["label"]).startswith("FLAG{")
    }
    roads.update({
        f"roads.{int(feature_id.partition('.')[2]) + 10_000}": roads.pop(feature_id)
        for feature_id in list(roads)
    })
    state = journal.load_journal(
        Client("", "arena_" + "g" * 16, "unused"),
        journal.locate_marker(
            Client("", "arena_" + "g" * 16, "unused"),
            b"facility-secret", "victim",
        ),
        b"facility-secret", "victim", now[0],
    )
    first_entry = next(
        entry for entry in state.entries if entry.phase == journal.PHASE_ACTIVE
    )
    # Even if the first retry arrives after expiry, ACTIVE is semantically
    # rechecked and durably published as RECHECKED before its DELETE.
    now[0] = journal.retirement(
        first_entry, b"facility-secret", "victim"
    )
    probe = checker.GeoServerChecker()
    assert probe.run(target).passed
    assert histories[first_label] == [
        *first_history,
        "lookup", "property", "wms_selected", "wms_absent",
        "ordinary", "ordinary",
        "lookup", "delete",
    ]
    assert first_label not in {row["label"] for row in roads.values()}
    now[0] += 60
    assert probe.run(target).passed
    assert histories[first_label][-1] == "delete"
    for _ in range(7):
        now[0] += 60
        assert probe.run(target).passed
        assert sum(
            str(row["label"]).startswith("FLAG{") for row in roads.values()
        ) <= journal.CHECKER_POOL_SIZE
    now[0] += max(checker._CHECKER_LIFETIMES) + 60
    assert probe.run(target).passed
    assert first_label not in {row["label"] for row in roads.values()}
    assert cohort_reads and set(cohort_reads) == {
        "/arena/facility.py read-issued-cohort"
    }

    disabled.add(issued_principals[1][0])
    selective_result = probe.run(target)
    assert not selective_result.passed
    assert any(
        child.name == "issued_principal_1" and not child.passed
        for child in selective_result.children
    )

    disabled.clear()
    boundary_bypassed.add(issued_principals[1][0])
    boundary_result = probe.run(target)
    assert not boundary_result.passed
    assert all(
        next(
            child for child in boundary_result.children if child.name == name
        ).passed
        for name in ("issued_principal_0", "issued_principal_1")
    )
    assert any(
        child.name == "issued_principal_1_layer_boundary" and not child.passed
        for child in boundary_result.children
    )

    boundary_bypassed.clear()
    receipt_denied.add(issued_principals[1][0])
    receipt_result = probe.run(target)
    assert not receipt_result.passed
    assert all(
        next(
            child for child in receipt_result.children if child.name == name
        ).passed
        for name in ("issued_principal_0", "issued_principal_1")
    )
    assert any(
        child.name == "issued_principal_1_public_receipt" and not child.passed
        for child in receipt_result.children
    )


def test_issued_principal_bridge_rejects_forged_cohort(monkeypatch) -> None:
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-secret")
    sealed = seal_issued_cohort([
        ("arena_" + "1" * 16, "Gs!" + "1" * 32),
    ])
    forged = sealed[:-1] + ("0" if sealed[-1] != "0" else "1")
    target = VulboxTarget(
        host="prod",
        ports={"service": 8080},
        meta={"exec_in_container": lambda *_args: (0, forged)},
    )

    with pytest.raises(RuntimeError, match="untrusted"):
        checker._issued_principals(target)


def test_overlapping_checker_runs_are_serialized_per_target(monkeypatch) -> None:
    entered = threading.Event()
    release = threading.Event()
    state_lock = threading.Lock()
    active = 0
    maximum = 0

    def run_serialized(_self, _target):
        nonlocal active, maximum
        with state_lock:
            active += 1
            maximum = max(maximum, active)
            first = maximum == 1 and not entered.is_set()
        if first:
            entered.set()
            assert release.wait(2)
        with state_lock:
            active -= 1
        return CheckResult("checker", True)

    monkeypatch.setattr(checker, "resolve_host", lambda host: host)
    monkeypatch.setattr(
        checker.GeoServerChecker, "_run_serialized", run_serialized
    )
    target = VulboxTarget(
        host="prod", ports={"service": 8080}, meta={"team_id": "victim"}
    )
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(checker.GeoServerChecker().run, target)
        assert entered.wait(1)
        second = pool.submit(checker.GeoServerChecker().run, target)
        time.sleep(0.05)
        assert maximum == 1
        release.set()
        assert first.result(timeout=2).passed
        assert second.result(timeout=2).passed
    assert maximum == 1


def test_public_receipt_filter_turns_health_leaf_red(monkeypatch) -> None:
    monkeypatch.setattr(
        checker, "receipt_path", lambda: "exports/q320/roads.csv"
    )

    class Guarded:
        def put_resource(self, path, body):
            return 201, b""

        def delete_resource(self, path):
            return 200, b""

    class SelectivelyFilteredOrdinary:
        def public_resource(self, path):
            # The simulated defense leaves unrelated GeoServer routes alone but
            # rejects the same public-receipt surface the PoV uses.
            return (404, b"") if path.startswith("/geoserver/www/") else (200, b"")

    result = checker._validate_public_receipt(
        Guarded(), SelectivelyFilteredOrdinary(), 3
    )

    assert not result.passed
    assert result.name == "issued_principal_3_public_receipt"
    assert "get=404" in result.detail


def test_public_receipt_body_filter_turns_health_leaf_red(monkeypatch) -> None:
    monkeypatch.setattr(
        checker, "receipt_path", lambda: "reports/field/roads.json"
    )
    published = b""

    class Guarded:
        def put_resource(self, path, body):
            nonlocal published
            published = body
            return 201, b""

        def delete_resource(self, path):
            return 200, b""

    class SelectivelyFilteredOrdinary:
        calls = 0

        def public_resource(self, path):
            self.calls += 1
            if self.calls == 1:
                assert re.fullmatch(rb"FLAG\{[A-Z0-9]{32}\}\n", published)
                return 200, b"filtered\n"
            return 404, b""

    result = checker._validate_public_receipt(
        Guarded(), SelectivelyFilteredOrdinary(), 4
    )

    assert not result.passed
    assert result.name == "issued_principal_4_public_receipt"
    assert "get=200" in result.detail
    assert "exact=False" in result.detail


def test_checker_lifetimes_cover_pinned_two_generation_residence() -> None:
    # Pinned Orche supports 60/120/180/300-second async rotation cadences.
    objective_residence = {2 * seconds for seconds in (60, 120, 180, 300)}
    assert objective_residence <= set(checker._CHECKER_LIFETIMES)
    assert checker._CHECKER_LIFETIMES == tuple(range(120, 601, 60))


def test_checker_road_labels_have_normal_application_shapes() -> None:
    labels = [checker._road_label() for _ in range(20)]
    assert all(re.fullmatch(r"FLAG\{[A-Z0-9]{32}\}", label) for label in labels)
    assert all("checker" not in label.lower() and "arena" not in label.lower()
               for label in labels)


def test_checker_control_matches_objective_placement_request_history(
    monkeypatch,
) -> None:
    trace: list[str] = []

    class Guarded:
        row: dict[str, object] | None = None

        def feature(self, _type_name, **_kwargs):
            trace.append("lookup" if self.row is not None else "availability")
            rows = [self.row] if self.row else []
            return 200, {"numberMatched": len(rows), "features": rows}

        def insert_road(self, label, category, geometry):
            trace.append("insert")
            self.row = {
                "properties": {"cat": category, "label": label},
                "geometry": {
                    "type": "MultiLineString",
                    "coordinates": [[list(point) for point in geometry]],
                },
            }
            return 200, b"SUCCESS"

        def road_property_value(self, *_args):
            trace.append("property")
            return 200, b"property"

        def map_png(self, *_args, **_kwargs):
            selected = "wms_selected" not in trace
            trace.append("wms_selected" if selected else "wms_absent")
            return 200, b"selected" if selected else b"absent"

    class Ordinary:
        def feature(self, *_args, **_kwargs):
            trace.append("ordinary")
            return 403, {"features": []}

    monkeypatch.setattr(checker, "_property_matches", lambda *_args: True)
    monkeypatch.setattr(checker, "_render_matches", lambda *_args: True)
    guarded = Guarded()
    entry = journal.JournalEntry(
        "ABCDEFG", 1_800_000_000, journal.PHASE_INTENT
    )
    marker = journal.marker_candidates(b"facility-secret", "victim")[0]
    road = journal.decoy_record(
        entry, marker, b"facility-secret", "victim"
    )
    assert checker._road_rows(guarded, road.category) == []
    assert checker._ensure_road(guarded, road)[0]
    assert all(
        result.passed
        for result in checker._validate_road(guarded, (Ordinary(),), road)
    )
    assert trace == [
        "availability", "availability", "insert", "lookup", "property",
        "wms_selected", "wms_absent", "ordinary",
    ]


def test_layer_boundary_accepts_only_the_native_denial_shape() -> None:
    native = (
        '<ows:ExceptionReport xmlns:ows="http://www.opengis.net/ows/1.1">'
        '<ows:Exception exceptionCode="InvalidParameterValue" locator="typeName">'
        '<ows:ExceptionText>Feature type sf:roads unknown</ows:ExceptionText>'
        '</ows:Exception></ows:ExceptionReport>'
    ).encode()
    assert checker._native_layer_denial(401, b"")
    assert checker._native_layer_denial(403, b"")
    assert checker._native_layer_denial(400, native)
    assert not checker._native_layer_denial(500, native)
    assert not checker._native_layer_denial(400, b"not xml")
    assert not checker._native_layer_denial(
        400, native.replace(b"typeName", b"CQL_FILTER")
    )


def test_wms_requires_a_complete_image_with_requested_dimensions() -> None:
    width, height = 8, 4
    assert not checker._valid_png(b"\x89PNG\r\n\x1a\n", width, height)

    def chunk(kind: bytes, body: bytes) -> bytes:
        return (
            len(body).to_bytes(4, "big") + kind + body
            + (zlib.crc32(kind + body) & 0xFFFFFFFF).to_bytes(4, "big")
        )

    header = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
    pixels = b"".join(b"\0" + bytes([row]) * width for row in range(height))
    image = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(pixels))
        + chunk(b"IEND", b"")
    )
    assert checker._valid_png(image, width, height)
    assert not checker._valid_png(image, width + 1, height)


def test_wms_semantics_reject_dimension_only_canned_image() -> None:
    width, height = 8, 4

    def chunk(kind: bytes, body: bytes) -> bytes:
        return (
            len(body).to_bytes(4, "big") + kind + body
            + (zlib.crc32(kind + body) & 0xFFFFFFFF).to_bytes(4, "big")
        )

    header = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
    pixels = b"".join(b"\0" + b"\x11" * width for _ in range(height))
    canned = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(pixels))
        + chunk(b"IEND", b"")
    )
    geometry = ((594000, 4917000), (596000, 4919000))
    assert not checker._render_matches(canned, canned, width, height, geometry)
    assert not checker._render_matches(
        _rgba_png(width, height), _rgba_png(width, height),
        width, height, geometry,
    )


def test_wms_semantics_require_the_wfs_geometry() -> None:
    width, height = 170, 110
    geometry = ((594000, 4917000), (596000, 4919000))
    other = ((602000, 4924000), (604000, 4926000))
    selected = _rgba_png(width, height, geometry)
    absent = _rgba_png(width, height)

    assert checker._render_matches(selected, absent, width, height, geometry)
    assert not checker._render_matches(selected, absent, width, height, other)


def test_checker_accepts_lost_insert_and_delete_responses_by_stable_locator() -> None:
    geometry = ((594000, 4917000), (596000, 4919000))
    road = checker._Road("FLAG{" + "A" * 32 + "}", 17, geometry)

    class Client:
        def __init__(self):
            self.rows: dict[str, dict[str, object]] = {}

        def feature(self, _type_name, *, cql_filter="", **_kwargs):
            match = re.fullmatch(
                r"cat=(\d+)(?: AND label='([^']+)')?", cql_filter
            )
            assert match is not None
            category = int(match.group(1))
            label = match.group(2)
            rows = [
                {
                    "id": feature_id,
                    "properties": {
                        "label": row["label"], "cat": row["cat"],
                    },
                    "geometry": {
                        "type": "MultiLineString",
                        "coordinates": [[list(point) for point in row["geometry"]]],
                    },
                }
                for feature_id, row in self.rows.items()
                if row["cat"] == category
                and (label is None or row["label"] == label)
            ]
            return 200, {"numberMatched": len(rows), "features": rows}

        def insert_road(self, label, category, inserted_geometry):
            self.rows["roads.9"] = {
                "label": label, "cat": category,
                "geometry": inserted_geometry,
            }
            return 500, b"lost"

        def delete_road(self, label, category):
            for feature_id, row in list(self.rows.items()):
                if row["label"] == label and row["cat"] == category:
                    self.rows.pop(feature_id)
            return 500, b"lost"

    client = Client()
    present, _ = checker._ensure_road(client, road)
    assert present
    assert checker._delete_and_confirm(client, road)[0]
