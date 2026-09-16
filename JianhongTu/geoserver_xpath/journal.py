"""Native, proof-independent lifecycle journal for checker-owned roads."""

from __future__ import annotations

import hashlib
import hmac
import itertools
import os
import re
import secrets
import string
import time
from dataclasses import dataclass, replace

from ._client import GeoServerClient
from .image.road_protocol import GEOMETRY_SPAN, GEOMETRY_X, GEOMETRY_Y

CHECKER_LIFETIMES = tuple(range(120, 601, 60))
CHECKER_POOL_SIZE = 12
JOURNAL_SCAN_LIMIT = 64

PHASE_INTENT = "intent"
PHASE_ACTIVE = "active"
PHASE_RECHECKED = "rechecked"
PHASE_DELETE = "delete"
_PHASES = (PHASE_INTENT, PHASE_ACTIVE, PHASE_RECHECKED, PHASE_DELETE)
_FACILITY_TOKEN_ENV = "CYBERARENA_FACILITY_TOKEN"
_ALPHABET = string.ascii_uppercase + string.digits
_RADIX = len(_ALPHABET)
_ENTRY_NONCE_WIDTH = 7
_TIME_WIDTH = 8
_ENTRY_TAG_WIDTH = 16
_TIME_SPACE = _RADIX ** _TIME_WIDTH
_HEAD_PAYLOAD_WIDTH = 14
_HEAD_TAG_WIDTH = 14
_HEAD_GENERATION_LIMIT = 1 << 24
_HEAD_DIGEST_LIMIT = 1 << 44
_ENTRY_RE = re.compile(r"META\{E([A-Z0-9]{31})\}")
_HEAD_RE = re.compile(r"META\{H([A-Z0-9]{31})\}")


@dataclass(frozen=True)
class NativeRecord:
    label: str
    category: int
    geometry: tuple[tuple[int, int], tuple[int, int]]


@dataclass(frozen=True)
class JournalEntry:
    nonce: str
    born_at: int
    phase: str


@dataclass(frozen=True)
class JournalHead:
    generation: int
    labels: tuple[str, ...]


@dataclass(frozen=True)
class JournalState:
    generation: int
    entries: tuple[JournalEntry, ...]
    current: tuple[NativeRecord, ...]
    stale: tuple[NativeRecord, ...]


@dataclass(frozen=True)
class CycleContext:
    """One loaded journal generation carried through a lifecycle cycle."""

    journal_id: str
    marker: NativeRecord
    state: JournalState
    intent: JournalEntry

    @property
    def nonce(self) -> str:
        return self.intent.nonce

    @property
    def born_at(self) -> int:
        return self.intent.born_at


def facility_key() -> bytes:
    token = os.environ.get(_FACILITY_TOKEN_ENV, "")
    if not token:
        raise RuntimeError("checker lifecycle material is unavailable")
    return token.encode()


def _encode(value: int, width: int) -> str:
    if value < 0:
        raise ValueError("negative encoding value")
    chars = []
    for _ in range(width):
        value, index = divmod(value, _RADIX)
        chars.append(_ALPHABET[index])
    if value:
        raise ValueError("encoding value does not fit")
    return "".join(reversed(chars))


def _decode(value: str) -> int:
    number = 0
    for char in value:
        number = number * _RADIX + _ALPHABET.index(char)
    return number


def _mac(key: bytes, purpose: str, team_id: str, material: str) -> bytes:
    domain = "\0".join((
        "geoserver-xpath", "checker-journal-v1", purpose, team_id, material,
    ))
    return hmac.new(key, domain.encode(), hashlib.sha256).digest()


def _number(
    key: bytes, purpose: str, team_id: str, material: str, bound: int,
) -> int:
    return int.from_bytes(_mac(key, purpose, team_id, material), "big") % bound


def _geometry(
    key: bytes, team_id: str, material: str,
) -> tuple[tuple[int, int], tuple[int, int]]:
    span = GEOMETRY_SPAN[0] + _number(
        key, "span", team_id, material,
        GEOMETRY_SPAN[1] - GEOMETRY_SPAN[0] + 1,
    )
    center_x = GEOMETRY_X[0] + span + _number(
        key, "x", team_id, material,
        GEOMETRY_X[1] - GEOMETRY_X[0] - 2 * span + 1,
    )
    center_y = GEOMETRY_Y[0] + span + _number(
        key, "y", team_id, material,
        GEOMETRY_Y[1] - GEOMETRY_Y[0] - 2 * span + 1,
    )
    slope = -1 if _number(key, "slope", team_id, material, 2) else 1
    return (
        (center_x - span, center_y - slope * span),
        (center_x + span, center_y + slope * span),
    )


def marker_candidates(key: bytes, team_id: str) -> tuple[NativeRecord, ...]:
    candidates = []
    for slot in range(16):
        material = str(slot)
        body = _encode(
            _number(key, "marker-label", team_id, material, _RADIX ** 31), 31
        )
        label = f"META{{M{body}}}"
        category = 1 + _number(key, "marker-category", team_id, material, 9999)
        candidates.append(NativeRecord(
            label, category, _geometry(key, team_id, "marker:" + body)
        ))
    return tuple(candidates)


def _rows(
    client: GeoServerClient, category: int, label: str = "", *, count: int = 3,
) -> list[dict] | None:
    from .image.road_protocol import road_filter

    status, document = client.feature(
        "sf:roads", cql_filter=road_filter(category, label), count=count
    )
    if status != 200 or not isinstance(document, dict):
        return None
    rows = document.get("features")
    if not isinstance(rows, list) or len(rows) > count:
        return None
    matched = document.get("numberMatched", len(rows))
    if (
        isinstance(matched, bool)
        or not isinstance(matched, (int, float))
        or int(matched) != matched
        or matched != len(rows)
    ):
        return None
    return rows


def record_matches(row: object, record: NativeRecord) -> bool:
    if not isinstance(row, dict):
        return False
    properties = row.get("properties")
    geometry = row.get("geometry")
    coordinates = geometry.get("coordinates") if isinstance(geometry, dict) else None
    return (
        isinstance(properties, dict)
        and properties.get("label") == record.label
        and properties.get("cat") == record.category
        and isinstance(coordinates, list)
        and coordinates == [[list(point) for point in record.geometry]]
    )


def ensure_marker(
    client: GeoServerClient, key: bytes, team_id: str,
) -> NativeRecord:
    found = []
    for marker in marker_candidates(key, team_id):
        rows = _rows(client, marker.category, marker.label)
        if rows is None:
            raise RuntimeError("checker journal marker lookup failed")
        if rows:
            if len(rows) != 1 or not record_matches(rows[0], marker):
                raise RuntimeError("checker journal marker is invalid")
            found.append(marker)
    if len(found) > 1:
        raise RuntimeError("checker journal marker is ambiguous")
    if found:
        return found[0]

    # Called during principal provisioning, before any objective is planted.
    for marker in marker_candidates(key, team_id):
        rows = _rows(client, marker.category)
        if rows is None:
            raise RuntimeError("checker journal reservation lookup failed")
        if rows:
            continue
        status, body = client.insert_road(
            marker.label, marker.category, marker.geometry
        )
        rows = _rows(client, marker.category, marker.label)
        if rows and len(rows) == 1 and record_matches(rows[0], marker):
            return marker
        if status != 200 or b"SUCCESS" not in body:
            raise RuntimeError("checker journal marker insertion failed")
        raise RuntimeError("checker journal marker did not converge")
    raise RuntimeError("checker journal category is unavailable")


def locate_marker(
    client: GeoServerClient, key: bytes, team_id: str,
) -> NativeRecord | None:
    found = []
    for marker in marker_candidates(key, team_id):
        rows = _rows(client, marker.category, marker.label)
        if rows is None:
            return None
        if rows:
            if len(rows) != 1 or not record_matches(rows[0], marker):
                return None
            found.append(marker)
    return found[0] if len(found) == 1 else None


def new_entry(now: int) -> JournalEntry:
    nonce = "".join(
        secrets.choice(_ALPHABET) for _ in range(_ENTRY_NONCE_WIDTH)
    )
    return JournalEntry(nonce, now, PHASE_INTENT)


def with_phase(entry: JournalEntry, phase: str) -> JournalEntry:
    if phase not in _PHASES:
        raise ValueError("invalid journal phase")
    return replace(entry, phase=phase)


def entry_label(entry: JournalEntry, key: bytes, team_id: str) -> str:
    phase = _PHASES.index(entry.phase)
    pad = int.from_bytes(_mac(key, "entry-time", team_id, entry.nonce), "big")
    encoded = _encode(
        (entry.born_at * len(_PHASES) + phase + pad) % _TIME_SPACE,
        _TIME_WIDTH,
    )
    identity = entry.nonce + encoded
    tag = _number(
        key, "entry-tag", team_id, identity, _RADIX ** _ENTRY_TAG_WIDTH
    )
    return f"META{{E{identity}{_encode(tag, _ENTRY_TAG_WIDTH)}}}"


def decode_entry(
    label: str, key: bytes, team_id: str, now: int,
) -> JournalEntry | None:
    match = _ENTRY_RE.fullmatch(label)
    if match is None:
        return None
    body = match.group(1)
    nonce = body[:_ENTRY_NONCE_WIDTH]
    encoded = body[
        _ENTRY_NONCE_WIDTH:_ENTRY_NONCE_WIDTH + _TIME_WIDTH
    ]
    identity = nonce + encoded
    expected = _encode(
        _number(
            key, "entry-tag", team_id, identity, _RADIX ** _ENTRY_TAG_WIDTH
        ),
        _ENTRY_TAG_WIDTH,
    )
    if not hmac.compare_digest(body[-_ENTRY_TAG_WIDTH:], expected):
        return None
    pad = int.from_bytes(_mac(key, "entry-time", team_id, nonce), "big")
    plain = (_decode(encoded) - pad) % _TIME_SPACE
    born_at, phase = divmod(plain, len(_PHASES))
    if born_at <= 0 or born_at > now + 300:
        return None
    return JournalEntry(nonce, born_at, _PHASES[phase])


def _entry_digest(labels: tuple[str, ...], key: bytes, team_id: str) -> int:
    material = "\0".join(labels)
    return _number(
        key, "head-digest", team_id, material, _HEAD_DIGEST_LIMIT
    )


def head_label(
    generation: int, entries: tuple[JournalEntry, ...], key: bytes, team_id: str,
) -> str:
    if not 0 <= generation < _HEAD_GENERATION_LIMIT:
        raise ValueError("journal generation does not fit")
    labels = tuple(sorted(entry_label(entry, key, team_id) for entry in entries))
    if len(labels) > CHECKER_POOL_SIZE:
        raise ValueError("journal entry set is too large")
    digest = _entry_digest(labels, key, team_id)
    plain = (generation << 48) | (len(labels) << 44) | digest
    seed = f"{generation}:{len(labels)}:{digest}"
    nonce = _encode(
        _number(key, "head-nonce", team_id, seed, _RADIX ** 3), 3
    )
    pad = _number(
        key, "head-payload", team_id, nonce, 1 << 72
    )
    encoded = _encode(plain ^ pad, _HEAD_PAYLOAD_WIDTH)
    identity = nonce + encoded
    tag = _encode(
        _number(
            key, "head-tag", team_id, identity, _RADIX ** _HEAD_TAG_WIDTH
        ),
        _HEAD_TAG_WIDTH,
    )
    return f"META{{H{identity}{tag}}}"


def decode_head(
    label: str, entries: tuple[JournalEntry, ...], key: bytes, team_id: str,
) -> JournalHead | None:
    match = _HEAD_RE.fullmatch(label)
    if match is None:
        return None
    body = match.group(1)
    nonce = body[:3]
    encoded = body[3:3 + _HEAD_PAYLOAD_WIDTH]
    identity = nonce + encoded
    expected = _encode(
        _number(
            key, "head-tag", team_id, identity, _RADIX ** _HEAD_TAG_WIDTH
        ),
        _HEAD_TAG_WIDTH,
    )
    if not hmac.compare_digest(body[-_HEAD_TAG_WIDTH:], expected):
        return None
    pad = _number(key, "head-payload", team_id, nonce, 1 << 72)
    plain = _decode(encoded) ^ pad
    generation = plain >> 48
    count = (plain >> 44) & 0xF
    digest = plain & (_HEAD_DIGEST_LIMIT - 1)
    if generation >= _HEAD_GENERATION_LIMIT or count > CHECKER_POOL_SIZE:
        return None
    matching: list[tuple[str, ...]] = []
    labels = tuple(sorted(entry_label(entry, key, team_id) for entry in entries))
    for subset in itertools.combinations(labels, count):
        if _entry_digest(subset, key, team_id) == digest:
            matching.append(subset)
            if len(matching) > 1:
                return None
    if len(matching) != 1:
        return None
    return JournalHead(generation, matching[0])


def decoy_record(
    entry: JournalEntry, marker: NativeRecord, key: bytes, team_id: str,
) -> NativeRecord:
    identity = f"{entry.nonce}:{entry.born_at}"
    body = _encode(
        _number(key, "decoy-label", team_id, identity, _RADIX ** 32), 32
    )
    label = f"FLAG{{{body}}}"
    category = 1 + _number(key, "decoy-category", team_id, identity, 9999)
    if category == marker.category:
        category = category % 9999 + 1
    return NativeRecord(label, category, _geometry(key, team_id, "decoy:" + identity))


def entry_record(
    entry: JournalEntry, marker: NativeRecord, key: bytes, team_id: str,
) -> NativeRecord:
    label = entry_label(entry, key, team_id)
    return NativeRecord(
        label, marker.category, _geometry(key, team_id, "entry:" + label)
    )


def head_record(
    generation: int, entries: tuple[JournalEntry, ...], marker: NativeRecord,
    key: bytes, team_id: str,
) -> NativeRecord:
    label = head_label(generation, entries, key, team_id)
    return NativeRecord(
        label, marker.category, _geometry(key, team_id, "head:" + label)
    )


def initialization_record(
    marker: NativeRecord, key: bytes, team_id: str,
) -> NativeRecord:
    body = _encode(
        _number(key, "initialized", team_id, marker.label, _RADIX ** 31), 31
    )
    label = f"META{{I{body}}}"
    return NativeRecord(
        label, marker.category, _geometry(key, team_id, "initialized:" + label)
    )


def ensure_record(
    client: GeoServerClient, record: NativeRecord,
) -> tuple[bool, str]:
    rows = _rows(client, record.category, record.label)
    if rows is None:
        return False, "lookup invalid"
    status = 200
    if not rows:
        status, body = client.insert_road(
            record.label, record.category, record.geometry
        )
        rows = _rows(client, record.category, record.label)
        if not rows and (status != 200 or b"SUCCESS" not in body):
            return False, f"insert={status},absent=True"
    valid = len(rows) == 1 and record_matches(rows[0], record)
    return valid, f"insert={status},unique={valid}"


def delete_record(
    client: GeoServerClient, record: NativeRecord,
) -> tuple[bool, str]:
    rows = _rows(client, record.category, record.label)
    if rows == []:
        return True, "already_absent=True"
    if rows is None or len(rows) != 1 or not record_matches(rows[0], record):
        return False, "locator_unique=False"
    status, _ = client.delete_road(record.label, record.category)
    remaining = _rows(client, record.category, record.label)
    absent = remaining == []
    return (
        absent,
        f"delete={status},locator_query_valid={remaining is not None},"
        f"absent={absent}",
    )


def initialize_journal(
    client: GeoServerClient, key: bytes, team_id: str,
) -> NativeRecord:
    marker = ensure_marker(client, key, team_id)
    initialized = initialization_record(marker, key, team_id)
    initialized_rows = _rows(client, marker.category, initialized.label)
    if initialized_rows is None:
        raise RuntimeError("checker journal initialization lookup failed")
    if initialized_rows:
        if (
            len(initialized_rows) != 1
            or not record_matches(initialized_rows[0], initialized)
        ):
            raise RuntimeError("checker journal initialization is invalid")
        # Once initialized, any missing or malformed head must fail closed.
        load_journal(client, marker, key, team_id, now=int(time.time()))
        return marker

    rows = _rows(client, marker.category, count=JOURNAL_SCAN_LIMIT)
    if rows is None:
        raise RuntimeError("checker journal initialization scan failed")
    records = [row for row in rows if not record_matches(row, marker)]
    empty_head = head_record(0, (), marker, key, team_id)
    if records:
        if len(records) != 1 or not record_matches(records[0], empty_head):
            raise RuntimeError("checker journal has pre-initialization state")
    else:
        present, _ = ensure_record(client, empty_head)
        if not present:
            raise RuntimeError("checker journal head initialization failed")
    present, _ = ensure_record(client, initialized)
    if not present:
        raise RuntimeError("checker journal initialization failed")
    load_journal(client, marker, key, team_id, now=int(time.time()))
    return marker


def load_journal(
    client: GeoServerClient, marker: NativeRecord, key: bytes, team_id: str,
    now: int,
) -> JournalState:
    rows = _rows(client, marker.category, count=JOURNAL_SCAN_LIMIT)
    if rows is None:
        raise RuntimeError("checker journal read is incomplete")
    initialized = initialization_record(marker, key, team_id)
    marker_count = sum(record_matches(row, marker) for row in rows)
    initialized_count = sum(record_matches(row, initialized) for row in rows)
    if marker_count != 1 or initialized_count != 1:
        raise RuntimeError("checker journal anchors are invalid")

    entry_records: list[tuple[JournalEntry, NativeRecord]] = []
    head_rows: list[tuple[str, object]] = []
    seen_labels: set[str] = {marker.label, initialized.label}
    for row in rows:
        properties = row.get("properties") if isinstance(row, dict) else None
        label = properties.get("label") if isinstance(properties, dict) else None
        if not isinstance(label, str):
            raise RuntimeError("checker journal record has no label")
        if label in (marker.label, initialized.label):
            continue
        if label in seen_labels:
            raise RuntimeError("checker journal record is duplicated")
        seen_labels.add(label)
        entry = decode_entry(label, key, team_id, now)
        if entry is not None:
            record = entry_record(entry, marker, key, team_id)
            if not record_matches(row, record):
                raise RuntimeError("checker journal entry is malformed")
            entry_records.append((entry, record))
            continue
        if _HEAD_RE.fullmatch(label):
            head_rows.append((label, row))
            continue
        raise RuntimeError("checker journal contains foreign state")

    entries = tuple(entry for entry, _ in entry_records)
    heads: list[tuple[JournalHead, NativeRecord]] = []
    for label, row in head_rows:
        head = decode_head(label, entries, key, team_id)
        if head is None:
            raise RuntimeError("checker journal head is invalid")
        selected = tuple(
            entry for entry in entries
            if entry_label(entry, key, team_id) in head.labels
        )
        record = head_record(head.generation, selected, marker, key, team_id)
        if record.label != label or not record_matches(row, record):
            raise RuntimeError("checker journal head is malformed")
        heads.append((head, record))
    if not heads:
        raise RuntimeError("checker journal head is missing")
    generation = max(head.generation for head, _ in heads)
    current_heads = [(head, record) for head, record in heads
                     if head.generation == generation]
    if len(current_heads) != 1:
        raise RuntimeError("checker journal generation is ambiguous")
    head, head_native = current_heads[0]
    current_entries = tuple(sorted(
        (
            entry for entry in entries
            if entry_label(entry, key, team_id) in head.labels
        ),
        key=lambda entry: entry_label(entry, key, team_id),
    ))
    current_records = tuple(
        [head_native]
        + [entry_record(entry, marker, key, team_id) for entry in current_entries]
    )
    current_labels = {record.label for record in current_records}
    stale = tuple(
        record for _, record in heads + entry_records
        if record.label not in current_labels
    )
    return JournalState(generation, current_entries, current_records, stale)


def commit_journal(
    client: GeoServerClient, state: JournalState,
    entries: tuple[JournalEntry, ...], marker: NativeRecord,
    key: bytes, team_id: str, now: int,
) -> JournalState:
    labels = [entry_label(entry, key, team_id) for entry in entries]
    if len(labels) > CHECKER_POOL_SIZE or len(set(labels)) != len(labels):
        raise RuntimeError("checker journal update is invalid")
    entries = tuple(sorted(
        entries, key=lambda entry: entry_label(entry, key, team_id)
    ))
    if entries == state.entries and not state.stale:
        return state
    for entry in entries:
        present, _ = ensure_record(
            client, entry_record(entry, marker, key, team_id)
        )
        if not present:
            raise RuntimeError("checker journal entry did not converge")
    generation = state.generation + 1
    next_head = head_record(generation, entries, marker, key, team_id)
    present, _ = ensure_record(client, next_head)
    if not present:
        raise RuntimeError("checker journal head did not converge")
    updated = load_journal(client, marker, key, team_id, now)
    expected = tuple(entry_label(entry, key, team_id) for entry in entries)
    actual = tuple(entry_label(entry, key, team_id) for entry in updated.entries)
    if updated.generation != generation or actual != expected:
        raise RuntimeError("checker journal update did not commit")
    for record in updated.stale:
        deleted, _ = delete_record(client, record)
        if not deleted:
            raise RuntimeError("checker journal stale state did not retire")
    return load_journal(client, marker, key, team_id, now)


def retirement(entry: JournalEntry, key: bytes, team_id: str) -> int:
    identity = f"{entry.nonce}:{entry.born_at}"
    lifetime = CHECKER_LIFETIMES[
        _number(key, "decoy-lifetime", team_id, identity, len(CHECKER_LIFETIMES))
    ]
    return entry.born_at + lifetime


def placement_journal_id(team_id: str) -> str:
    if not team_id:
        raise ValueError("placement journal team is unavailable")
    return team_id + ":objective-placement"


def begin_cycle(
    client: GeoServerClient, key: bytes, journal_id: str, now: int,
) -> JournalEntry:
    """Persist or recover the exact intent before a road mutation."""
    return begin_cycle_context(client, key, journal_id, now).intent


def begin_cycle_context(
    client: GeoServerClient,
    key: bytes,
    journal_id: str,
    now: int,
    *,
    marker: NativeRecord | None = None,
    state: JournalState | None = None,
    resume: JournalEntry | None = None,
) -> CycleContext:
    """Persist/recover an intent and retain the authoritative loaded state."""
    if (marker is None) != (state is None):
        raise ValueError("road lifecycle context is incomplete")
    if marker is None:
        marker = locate_marker(client, key, journal_id)
        if marker is None:
            raise RuntimeError("road lifecycle journal marker is unavailable")
        state = load_journal(client, marker, key, journal_id, now)
    assert state is not None
    if state.stale:
        state = commit_journal(
            client, state, state.entries, marker, key, journal_id, now
        )
    if resume is not None:
        matching = [
            entry for entry in state.entries
            if entry.nonce == resume.nonce and entry.born_at == resume.born_at
        ]
        if (
            len(matching) != 1
            or matching[0].phase not in (PHASE_INTENT, PHASE_ACTIVE)
        ):
            raise RuntimeError("road lifecycle journal trace changed")
        return CycleContext(journal_id, marker, state, matching[0])
    intents = [entry for entry in state.entries if entry.phase == PHASE_INTENT]
    if len(intents) > 1:
        raise RuntimeError("road lifecycle journal intent is ambiguous")
    if intents:
        return CycleContext(journal_id, marker, state, intents[0])
    if any(entry.phase == PHASE_DELETE for entry in state.entries):
        raise RuntimeError("road lifecycle deletion did not converge")
    if len(state.entries) >= CHECKER_POOL_SIZE:
        raise RuntimeError("road lifecycle journal did not converge")
    intent = new_entry(now)
    state = commit_journal(
        client, state, (*state.entries, intent), marker, key, journal_id, now
    )
    return CycleContext(journal_id, marker, state, intent)


def finish_cycle(
    client: GeoServerClient,
    key: bytes,
    journal_id: str,
    intent: JournalEntry,
    now: int,
) -> JournalState:
    """Publish predecessor RECHECKED and replacement ACTIVE in one head."""
    marker = locate_marker(client, key, journal_id)
    if marker is None:
        raise RuntimeError("road lifecycle journal marker is unavailable")
    state = load_journal(client, marker, key, journal_id, now)
    matching = [
        entry for entry in state.entries
        if entry.nonce == intent.nonce and entry.born_at == intent.born_at
    ]
    if matching == [with_phase(intent, PHASE_ACTIVE)]:
        return state
    if matching != [intent]:
        raise RuntimeError("road lifecycle journal intent changed")
    entries = tuple(
        with_phase(entry, PHASE_RECHECKED)
        if entry.phase == PHASE_ACTIVE
        else with_phase(entry, PHASE_ACTIVE)
        if entry == intent
        else entry
        for entry in state.entries
    )
    return commit_journal(
        client, state, entries, marker, key, journal_id, now
    )


def finish_cycle_context(
    client: GeoServerClient,
    key: bytes,
    context: CycleContext,
    now: int,
) -> CycleContext:
    """Publish a carried intent without repeating marker/state discovery."""
    state = context.state
    intent = context.intent
    matching = [
        entry for entry in state.entries
        if entry.nonce == intent.nonce and entry.born_at == intent.born_at
    ]
    active = with_phase(intent, PHASE_ACTIVE)
    if matching == [active]:
        return replace(context, intent=active)
    if matching != [intent]:
        raise RuntimeError("road lifecycle journal intent changed")
    entries = tuple(
        with_phase(entry, PHASE_RECHECKED)
        if entry.phase == PHASE_ACTIVE
        else active
        if entry == intent
        else entry
        for entry in state.entries
    )
    state = commit_journal(
        client, state, entries, context.marker, key, context.journal_id, now
    )
    return replace(context, state=state, intent=active)


def begin_retirement(
    client: GeoServerClient,
    state: JournalState,
    entry: JournalEntry,
    marker: NativeRecord,
    key: bytes,
    journal_id: str,
    now: int,
) -> tuple[JournalState, JournalEntry]:
    """Durably mark one validated RECHECKED road before native deletion."""
    if entry.phase != PHASE_RECHECKED or state.entries.count(entry) != 1:
        raise RuntimeError("road lifecycle retirement is invalid")
    deleting = with_phase(entry, PHASE_DELETE)
    state = commit_journal(
        client, state,
        tuple(deleting if item == entry else item for item in state.entries),
        marker, key, journal_id, now,
    )
    return state, deleting


def finish_retirement(
    client: GeoServerClient,
    state: JournalState,
    deleting: JournalEntry,
    marker: NativeRecord,
    key: bytes,
    journal_id: str,
    now: int,
) -> JournalState:
    """Remove durable DELETE metadata after native absence is confirmed."""
    if deleting.phase != PHASE_DELETE or state.entries.count(deleting) != 1:
        raise RuntimeError("road lifecycle deletion is invalid")
    return commit_journal(
        client, state,
        tuple(item for item in state.entries if item != deleting),
        marker, key, journal_id, now,
    )


def begin_placement_trace(
    client: GeoServerClient, key: bytes, team_id: str, now: int,
    resume: JournalEntry | None = None,
) -> CycleContext:
    """Persist proof-independent intent before an objective road mutation."""
    journal_id = placement_journal_id(team_id)
    return begin_cycle_context(
        client, key, journal_id, now, resume=resume
    )


def finish_placement_trace(
    client: GeoServerClient,
    key: bytes,
    team_id: str,
    context: CycleContext,
    now: int,
    retirement_entry: JournalEntry | None = None,
) -> CycleContext:
    """Commit the exact intent, then stage eligible trace deletion."""
    journal_id = placement_journal_id(team_id)
    if context.journal_id != journal_id:
        raise RuntimeError("objective placement journal context changed")
    context = finish_cycle_context(client, key, context, now)
    if retirement_entry is None:
        return context
    state = context.state
    matching = [
        entry for entry in state.entries
        if entry.nonce == retirement_entry.nonce
        and entry.born_at == retirement_entry.born_at
    ]
    if not matching:
        # A lost response after finish_retirement leaves the exact native
        # retirement pending in the root-owned placement state. The caller
        # still reconfirms native absence before clearing that state.
        return context
    if matching and matching[0].phase == PHASE_RECHECKED:
        state, _ = begin_retirement(
            client, state, matching[0], context.marker, key, journal_id, now
        )
    elif not (len(matching) == 1 and matching[0].phase == PHASE_DELETE):
        raise RuntimeError("objective placement retirement trace changed")
    return replace(context, state=state)


def complete_placement_trace(
    client: GeoServerClient,
    key: bytes,
    team_id: str,
    context: CycleContext,
    now: int,
    retirement_entry: JournalEntry | None = None,
) -> CycleContext:
    """Remove durable DELETE metadata after native retirement is confirmed."""
    journal_id = placement_journal_id(team_id)
    if context.journal_id != journal_id:
        raise RuntimeError("objective placement journal context changed")
    state = context.state
    if retirement_entry is None:
        return context
    matching = [
        entry for entry in state.entries
        if entry.nonce == retirement_entry.nonce
        and entry.born_at == retirement_entry.born_at
    ]
    if not matching:
        return context
    if len(matching) != 1 or matching[0].phase != PHASE_DELETE:
        raise RuntimeError("objective placement deletion trace changed")
    state = finish_retirement(
        client, state, matching[0], context.marker, key, journal_id, now
    )
    return replace(context, state=state)
