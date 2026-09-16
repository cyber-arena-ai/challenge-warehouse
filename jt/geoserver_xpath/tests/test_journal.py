from __future__ import annotations

import re
from dataclasses import replace

import pytest

from challenges.geoserver_xpath import journal


KEY = b"facility-secret"
TEAM = "victim"
NOW = 1_800_000_000


class NativeClient:
    def __init__(self) -> None:
        self.records: dict[int, journal.NativeRecord] = {}
        self.next_id = 0
        self.history: list[tuple[str, str, int]] = []

    def feature(self, _type_name: str, *, cql_filter="", count=1, **_kwargs):
        label_match = re.search(r"label='([^']+)'", cql_filter)
        label = label_match.group(1) if label_match else ""
        self.history.append((
            "GET", label[:6] if label.startswith("META{") else "scan", count,
        ))
        match = re.fullmatch(
            r"cat=(\d+)(?: AND label='([^']+)')?", cql_filter
        )
        assert match is not None
        category = int(match.group(1))
        label = match.group(2)
        matching = [
            (feature_id, record)
            for feature_id, record in self.records.items()
            if record.category == category
            and (label is None or record.label == label)
        ]
        return 200, {
            "numberMatched": len(matching),
            "features": [
                {
                    "id": f"roads.{feature_id}",
                    "properties": {
                        "label": record.label, "cat": record.category,
                    },
                    "geometry": {
                        "type": "MultiLineString",
                        "coordinates": [[list(point) for point in record.geometry]],
                    },
                }
                for feature_id, record in matching[:count]
            ],
        }

    def insert_road(self, label: str, category: int, geometry):
        self.history.append(("POST", label[:6], 0))
        self.next_id += 1
        self.records[self.next_id] = journal.NativeRecord(
            label, category, tuple(tuple(point) for point in geometry)
        )
        return 200, b"SUCCESS"

    def delete_road(self, label: str, category: int):
        self.history.append(("DELETE", label[:6], 0))
        for feature_id, record in list(self.records.items()):
            if record.label == label and record.category == category:
                self.records.pop(feature_id)
        return 200, b"SUCCESS"

    def remove(self, label: str) -> None:
        for feature_id, record in list(self.records.items()):
            if record.label == label:
                self.records.pop(feature_id)


def _initialized() -> tuple[NativeClient, journal.NativeRecord, journal.JournalState]:
    client = NativeClient()
    marker = journal.initialize_journal(client, KEY, TEAM)
    return client, marker, journal.load_journal(client, marker, KEY, TEAM, NOW)


def test_journal_reconstructs_committed_state_and_cleans_lower_replay() -> None:
    client, marker, state = _initialized()
    entry = journal.JournalEntry("ABCDEFG", NOW, journal.PHASE_INTENT)
    state = journal.commit_journal(
        client, state, (entry,), marker, KEY, TEAM, NOW
    )
    active = journal.with_phase(entry, journal.PHASE_ACTIVE)
    state = journal.commit_journal(
        client, state, (active,), marker, KEY, TEAM, NOW
    )

    restarted = journal.load_journal(client, marker, KEY, TEAM, NOW + 60)
    assert restarted.generation == 2
    assert restarted.entries == (active,)

    replay_entry = journal.entry_record(entry, marker, KEY, TEAM)
    replay_head = journal.head_record(1, (entry,), marker, KEY, TEAM)
    assert journal.ensure_record(client, replay_entry)[0]
    assert journal.ensure_record(client, replay_head)[0]
    replayed = journal.load_journal(client, marker, KEY, TEAM, NOW + 60)
    assert replayed.entries == (active,)
    assert {record.label for record in replayed.stale} == {
        replay_entry.label, replay_head.label,
    }
    clean = journal.commit_journal(
        client, replayed, replayed.entries, marker, KEY, TEAM, NOW + 60
    )
    assert clean.entries == (active,)
    assert not clean.stale


def test_journal_fails_on_missing_corrupt_or_ambiguous_committed_state() -> None:
    client, marker, state = _initialized()
    entry = journal.JournalEntry("ABCDEFG", NOW, journal.PHASE_ACTIVE)
    state = journal.commit_journal(
        client, state, (entry,), marker, KEY, TEAM, NOW
    )
    client.remove(journal.entry_label(entry, KEY, TEAM))
    with pytest.raises(RuntimeError, match="head is invalid"):
        journal.load_journal(client, marker, KEY, TEAM, NOW)

    client, marker, _ = _initialized()
    client.insert_road("META{" + "Z" * 32 + "}", marker.category, marker.geometry)
    with pytest.raises(RuntimeError, match="foreign state"):
        journal.load_journal(client, marker, KEY, TEAM, NOW)

    client, marker, state = _initialized()
    first = journal.JournalEntry("ABCDEFG", NOW, journal.PHASE_ACTIVE)
    second = journal.JournalEntry("HIJKLMN", NOW, journal.PHASE_ACTIVE)
    for entry in (first, second):
        assert journal.ensure_record(
            client, journal.entry_record(entry, marker, KEY, TEAM)
        )[0]
        assert journal.ensure_record(
            client, journal.head_record(1, (entry,), marker, KEY, TEAM)
        )[0]
    with pytest.raises(RuntimeError, match="generation is ambiguous"):
        journal.load_journal(client, marker, KEY, TEAM, NOW)


def test_journal_recovers_every_commit_boundary_without_objective_scan() -> None:
    client, marker, state = _initialized()
    intent = journal.JournalEntry("ABCDEFG", NOW, journal.PHASE_INTENT)

    # Entry persisted before the new head is an uncommitted intent and is safe
    # to discard against the still-authoritative empty head.
    intent_record = journal.entry_record(intent, marker, KEY, TEAM)
    assert journal.ensure_record(client, intent_record)[0]
    interrupted = journal.load_journal(client, marker, KEY, TEAM, NOW)
    assert interrupted.entries == ()
    assert interrupted.stale == (intent_record,)
    state = journal.commit_journal(
        client, interrupted, interrupted.entries, marker, KEY, TEAM, NOW
    )
    assert not state.stale

    # Once the next head is present, restart selects the intent even while the
    # predecessor head is still present and then cleans the predecessor.
    assert journal.ensure_record(client, intent_record)[0]
    next_head = journal.head_record(
        state.generation + 1, (intent,), marker, KEY, TEAM
    )
    assert journal.ensure_record(client, next_head)[0]
    committed = journal.load_journal(client, marker, KEY, TEAM, NOW)
    assert committed.entries == (intent,)
    assert committed.stale
    committed = journal.commit_journal(
        client, committed, committed.entries, marker, KEY, TEAM, NOW
    )
    assert committed.entries == (intent,)
    assert not committed.stale


def test_initialized_journal_never_recreates_a_missing_head() -> None:
    client, marker, state = _initialized()
    client.remove(state.current[0].label)
    with pytest.raises(RuntimeError, match="head is missing"):
        journal.initialize_journal(client, KEY, TEAM)


def test_objective_placement_trace_is_restart_durable_and_proof_independent() -> None:
    client = NativeClient()
    journal_id = journal.placement_journal_id(TEAM)
    marker = journal.initialize_journal(client, KEY, journal_id)

    context = journal.begin_placement_trace(client, KEY, TEAM, NOW)
    intent = context.intent
    interrupted = journal.load_journal(client, marker, KEY, journal_id, NOW)
    assert interrupted.entries == (intent,)
    assert intent.phase == journal.PHASE_INTENT

    resumed = journal.begin_placement_trace(client, KEY, TEAM, NOW + 1)
    assert resumed.intent == intent
    journal.finish_placement_trace(client, KEY, TEAM, resumed, NOW + 1)
    committed = journal.load_journal(
        client, marker, KEY, journal_id, NOW + 1
    )
    assert committed.entries == (journal.with_phase(
        intent, journal.PHASE_ACTIVE
    ),)
    assert all("FLAG{proof}" not in record.label for record in client.records.values())

    next_context = journal.begin_placement_trace(client, KEY, TEAM, NOW + 60)
    journal.finish_placement_trace(client, KEY, TEAM, next_context, NOW + 60)
    advanced = journal.load_journal(
        client, marker, KEY, journal_id, NOW + 60
    )
    assert {entry.phase for entry in advanced.entries} == {
        journal.PHASE_ACTIVE, journal.PHASE_RECHECKED,
    }


def test_checker_and_objective_cycles_share_atomic_crash_order() -> None:
    def exercise(journal_id: str, objective: bool) -> list[tuple[str, ...]]:
        client = NativeClient()
        marker = journal.initialize_journal(client, KEY, journal_id)

        def begin(now: int) -> journal.CycleContext:
            if objective:
                return journal.begin_placement_trace(client, KEY, TEAM, now)
            return journal.begin_cycle_context(client, KEY, journal_id, now)

        def finish(context: journal.CycleContext, now: int) -> None:
            if objective:
                journal.finish_placement_trace(client, KEY, TEAM, context, now)
            else:
                journal.finish_cycle_context(client, KEY, context, now)

        phases: list[tuple[str, ...]] = []
        first = begin(NOW)
        state = journal.load_journal(client, marker, KEY, journal_id, NOW)
        phases.append(tuple(entry.phase for entry in state.entries))
        assert begin(NOW + 1).intent == first.intent
        assert journal.load_journal(
            client, marker, KEY, journal_id, NOW + 1
        ).generation == state.generation

        finish(first, NOW + 1)
        state = journal.load_journal(client, marker, KEY, journal_id, NOW + 1)
        phases.append(tuple(entry.phase for entry in state.entries))

        second = begin(NOW + 60)
        staged = journal.load_journal(
            client, marker, KEY, journal_id, NOW + 60
        )
        phases.append(tuple(sorted(entry.phase for entry in staged.entries)))
        finish(second, NOW + 60)
        published = journal.load_journal(
            client, marker, KEY, journal_id, NOW + 60
        )
        phases.append(tuple(sorted(entry.phase for entry in published.entries)))
        assert published.generation == staged.generation + 1

        # An unknown response after the atomic publish resumes the exact head.
        finish(second, NOW + 61)
        assert journal.load_journal(
            client, marker, KEY, journal_id, NOW + 61
        ).generation == published.generation
        return phases

    expected = [
        (journal.PHASE_INTENT,),
        (journal.PHASE_ACTIVE,),
        (journal.PHASE_ACTIVE, journal.PHASE_INTENT),
        (journal.PHASE_ACTIVE, journal.PHASE_RECHECKED),
    ]
    assert exercise(TEAM, False) == expected
    assert exercise(journal.placement_journal_id(TEAM), True) == expected


def test_objective_retirement_is_bound_to_one_exact_trace() -> None:
    client = NativeClient()
    journal_id = journal.placement_journal_id(TEAM)
    marker = journal.initialize_journal(client, KEY, journal_id)
    state = journal.load_journal(client, marker, KEY, journal_id, NOW)
    first = journal.JournalEntry("ABCDEFG", NOW - 120, journal.PHASE_RECHECKED)
    second = journal.JournalEntry("HIJKLMN", NOW - 60, journal.PHASE_RECHECKED)
    intent = journal.JournalEntry("OPQRSTU", NOW, journal.PHASE_INTENT)
    journal.commit_journal(
        client, state, (first, second, intent), marker, KEY, journal_id, NOW
    )

    context = journal.begin_cycle_context(
        client, KEY, journal_id, NOW, marker=marker,
        state=journal.load_journal(client, marker, KEY, journal_id, NOW),
        resume=intent,
    )
    context = journal.finish_placement_trace(
        client, KEY, TEAM, context, NOW, first
    )
    staged = journal.load_journal(client, marker, KEY, journal_id, NOW)
    assert set(staged.entries) == {
        journal.with_phase(first, journal.PHASE_DELETE),
        second,
        journal.with_phase(intent, journal.PHASE_ACTIVE),
    }

    context = journal.complete_placement_trace(
        client, KEY, TEAM, context, NOW, first
    )
    completed = journal.load_journal(client, marker, KEY, journal_id, NOW)
    assert set(completed.entries) == {
        second,
        journal.with_phase(intent, journal.PHASE_ACTIVE),
    }

    # A retry after the META-remove response was lost resumes the exact ACTIVE
    # generation and does not stage or remove the unrelated RECHECKED trace.
    resumed = journal.begin_placement_trace(
        client, KEY, TEAM, NOW,
        resume=journal.JournalEntry(intent.nonce, intent.born_at, journal.PHASE_INTENT),
    )
    journal.finish_placement_trace(client, KEY, TEAM, resumed, NOW, first)
    assert set(journal.load_journal(
        client, marker, KEY, journal_id, NOW
    ).entries) == set(completed.entries)


def test_checker_and_objective_meta_wire_histories_are_identical() -> None:
    checker_client = NativeClient()
    objective_client = NativeClient()
    objective_id = journal.placement_journal_id(TEAM)
    checker_marker = journal.initialize_journal(checker_client, KEY, TEAM)
    objective_marker = journal.initialize_journal(
        objective_client, KEY, objective_id
    )
    checker_state = journal.load_journal(
        checker_client, checker_marker, KEY, TEAM, NOW
    )
    objective_state = journal.load_journal(
        objective_client, objective_marker, KEY, objective_id, NOW
    )
    checker_old = journal.JournalEntry(
        "ABCDEFG", NOW - 60, journal.PHASE_RECHECKED
    )
    objective_old = journal.JournalEntry(
        "ABCDEFG", NOW - 60, journal.PHASE_RECHECKED
    )
    checker_intent = journal.JournalEntry("HIJKLMN", NOW, journal.PHASE_INTENT)
    objective_intent = journal.JournalEntry("HIJKLMN", NOW, journal.PHASE_INTENT)
    journal.commit_journal(
        checker_client, checker_state, (checker_old, checker_intent),
        checker_marker, KEY, TEAM, NOW,
    )
    journal.commit_journal(
        objective_client, objective_state, (objective_old, objective_intent),
        objective_marker, KEY, objective_id, NOW,
    )
    checker_client.history.clear()
    objective_client.history.clear()

    # Both uninterrupted paths perform exactly one marker/load sweep, then
    # carry that generation through ACTIVE/DELETE/removal without rediscovery.
    checker_marker = journal.locate_marker(checker_client, KEY, TEAM)
    assert checker_marker is not None
    checker_state = journal.load_journal(
        checker_client, checker_marker, KEY, TEAM, NOW
    )
    checker_cycle = journal.begin_cycle_context(
        checker_client, KEY, TEAM, NOW,
        marker=checker_marker, state=checker_state, resume=checker_intent,
    )
    objective_cycle = journal.begin_placement_trace(
        objective_client, KEY, TEAM, NOW, resume=objective_intent
    )
    assert checker_client.history == objective_client.history

    checker_cycle = journal.finish_cycle_context(
        checker_client, KEY, checker_cycle, NOW
    )
    checker_state, checker_deleting = journal.begin_retirement(
        checker_client, checker_cycle.state, checker_old, checker_cycle.marker,
        KEY, TEAM, NOW,
    )
    checker_cycle = replace(checker_cycle, state=checker_state)
    objective_cycle = journal.finish_placement_trace(
        objective_client, KEY, TEAM, objective_cycle, NOW, objective_old
    )
    assert checker_client.history == objective_client.history

    checker_state = journal.finish_retirement(
        checker_client, checker_cycle.state, checker_deleting,
        checker_cycle.marker, KEY, TEAM, NOW,
    )
    checker_cycle = replace(checker_cycle, state=checker_state)
    objective_cycle = journal.complete_placement_trace(
        objective_client, KEY, TEAM, objective_cycle, NOW, objective_old
    )
    assert checker_client.history == objective_client.history
