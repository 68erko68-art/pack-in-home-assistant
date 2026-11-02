"""Ordered replay and atomic snapshot acceptance, independent of HA UI."""

import asyncio
from copy import deepcopy
import hashlib
import json

import pytest
from cryptography.exceptions import InvalidSignature, InvalidTag

from packin_pure.crypto import CryptoError, DeviceIdentity, decode64, encode64

from packin_pure.event_log import EventLog, IntegrityError
from packin_pure.protocol import descriptor
from packin_pure.state import PackState


async def decode(frame):
    return deepcopy(frame["testPayload"])


def frame(sequence, identifier=None, **changes):
    identifier = identifier or "task-" + str(sequence)
    payload = {
        "id": identifier,
        "title": "Task " + str(sequence),
        "createdByUserId": "member",
        "schemaVersion": 1,
        "historyJson": "[]",
        "completedAt": None,
    }
    kind, wire, _ = descriptor("chore.upserted", payload)
    return {
        "type": "PACK_EVENT",
        "protocolVersion": 3,
        "syncGeneration": 3,
        "dataEpoch": 2,
        "packId": "pack1",
        "serverSequence": sequence,
        "actorUserId": "member",
        "actorDeviceId": "other-device",
        "deviceSequence": sequence,
        "eventId": "event-" + str(sequence),
        "eventType": "chore.upserted",
        "entityType": kind,
        "entityId": wire,
        "entityVersion": 1,
        "serverTimestamp": "2026-11-01T22:00:00Z",
        "testPayload": payload,
        **changes,
    }


def log():
    return EventLog(PackState("pack1", "member", "member", data_epoch=2), lambda: {}, decode)


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def boundaries(rows):
    digest = hashlib.sha256("".join(encode(row) + "\n" for row in rows).encode()).hexdigest()
    common = {
        "dataEpoch": 2,
        "snapshotHeadSequence": len(rows),
        "rowCount": len(rows),
        "snapshotDigest": digest,
        "snapshotDigestAlgorithm": "SHA-256-JSONL",
        "snapshotKind": "EVENT_LOG_V1",
        "snapshotId": "synthetic-snapshot",
    }
    return {"type": "SNAPSHOT_BEGIN", **common}, {"type": "SNAPSHOT_COMPLETE", **common}


def test_replay_requests_one_bounded_gap_and_applies_contiguous_events_once():
    async def run():
        events = log()
        commands = await events.feed(encode(frame(3)))
        assert commands == [{"type": "FETCH_RANGE", "fromSequence": 1, "toSequence": 2}]
        assert await events.feed(encode(frame(3))) == []
        await events.feed(encode(frame(1)))
        await events.feed(encode(frame(2)))
        assert events.state.last_sequence == 3
        assert len(events.state.chores) == 3
        await events.feed(encode(frame(1)))
        assert events.state.last_sequence == 3 and len(events.state.chores) == 3

    asyncio.run(run())


def test_omitted_rows_advance_without_exposing_a_private_payload():
    async def run():
        events = log()
        await events.feed(encode({"type": "SEQUENCE_ADVANCED", "dataEpoch": 2, "serverSequence": 1}))
        assert events.state.last_sequence == 1 and events.state.chores == {}
        await events.feed(encode(frame(2)))
        assert len(events.state.chores) == 1

    asyncio.run(run())


def test_wrong_epoch_and_unbounded_gap_do_not_advance_the_cursor():
    async def run():
        events = log()
        with pytest.raises(IntegrityError):
            await events.feed(encode(frame(1, dataEpoch=1)))
        assert events.state.last_sequence == 0
        request = await events.feed(encode(frame(10000)))
        assert request == [{"type": "FETCH_RANGE", "fromSequence": 1, "toSequence": 250}]

    asyncio.run(run())


def test_snapshot_commits_only_after_the_complete_matching_digest():
    async def run():
        events = log()
        await events.feed(encode(frame(1, identifier="prior")))
        rows = [{**frame(1, identifier="replacement"), "type": "SNAPSHOT_ROW"}]
        begin, complete = boundaries(rows)
        await events.feed(encode(begin))
        await events.feed(encode(rows[0]))
        assert "prior" in events.state.chores and "replacement" not in events.state.chores
        await events.feed(encode(complete))
        assert "replacement" in events.state.chores and "prior" not in events.state.chores

    asyncio.run(run())


@pytest.mark.parametrize(
    "change", [{"snapshotDigest": "0" * 64}, {"snapshotId": "different"}, {"rowCount": 2}, {"dataEpoch": 3}]
)
def test_snapshot_changed_footer_never_replaces_verified_state(change):
    async def run():
        events = log()
        await events.feed(encode(frame(1, identifier="prior")))
        rows = [{**frame(1), "type": "SNAPSHOT_ROW"}]
        begin, complete = boundaries(rows)
        await events.feed(encode(begin))
        await events.feed(encode(rows[0]))
        with pytest.raises(IntegrityError):
            await events.feed(encode({**complete, **change}))
        assert set(events.state.chores) == {"prior"}

    asyncio.run(run())


def test_snapshot_rows_must_be_contiguous():
    async def run():
        events = log()
        rows = [{**frame(1), "type": "SNAPSHOT_ROW"}, {**frame(3), "type": "SNAPSHOT_ROW"}]
        begin, _ = boundaries(rows)
        await events.feed(encode(begin))
        await events.feed(encode(rows[0]))
        with pytest.raises(IntegrityError):
            await events.feed(encode(rows[1]))
        assert events.state.last_sequence == 0

    asyncio.run(run())


def test_live_event_arriving_during_snapshot_is_applied_after_atomic_commit():
    async def run():
        events = log()
        rows = [{**frame(1), "type": "SNAPSHOT_ROW"}]
        begin, complete = boundaries(rows)
        await events.feed(encode(begin))
        await events.feed(encode(frame(2, identifier="live")))
        await events.feed(encode(rows[0]))
        await events.feed(encode(complete))
        assert events.state.last_sequence == 2 and "live" in events.state.chores

    asyncio.run(run())


def test_signed_but_unauthorized_completion_is_quarantined_without_a_replay_loop():
    async def run():
        events = log()
        original = frame(1, identifier="shared")
        original["testPayload"]["historyJson"] = '[{"kind":"packin_task_assignees_v1","userIds":["other"]}]'
        await events.feed(encode(original))
        candidate = frame(2, identifier="shared", entityVersion=2)
        candidate["testPayload"] = {
            **original["testPayload"],
            "completedAt": 1793570400000,
            "completedByUserId": "member",
        }
        await events.feed(encode(candidate))
        assert events.state.last_sequence == 2
        assert events.state.chores["shared"].get("completedAt") is None
        assert events.metrics["domain_mutations_rejected"] == 1

    asyncio.run(run())


def test_sequence_replay_cannot_resurrect_a_removed_task():
    async def run():
        events = log()
        original = frame(1, identifier="shared")
        await events.feed(encode(original))
        removed = frame(2, identifier="shared", eventType="chore.removed", entityVersion=2)
        removed["testPayload"] = {"id": "shared", "removedAt": 1793570400000}
        await events.feed(encode(removed))
        await events.feed(encode(original))
        assert "shared" not in events.state.chores and events.state.last_sequence == 2

    asyncio.run(run())


def test_own_application_receipt_is_durable_and_not_added_for_forbidden_completion():
    async def run():
        events = log()
        events.device_id = "own-device"
        await events.feed(encode(frame(1, actorDeviceId="own-device")))
        assert events.state.own_applied_events == ["event-1"]
        restored = PackState.restore(events.state.export(), "pack1", "member")
        assert restored.own_applied_events == ["event-1"]

    asyncio.run(run())


def encrypted_frame(identity, sequence, payload, *, actor_device="other-device", version=None):
    value = frame(
        sequence,
        identifier=payload["id"],
        actorDeviceId=actor_device,
        entityVersion=sequence if version is None else version,
    )
    kind, wire, operation = descriptor("chore.upserted", payload)
    encrypted = identity.encrypt_event(
        encode(payload).encode(),
        b"k" * 32,
        pack="pack1",
        event=value["eventId"],
        device=actor_device,
        sequence=sequence,
        event_type="chore.upserted",
        epoch=1,
    )
    value.update(
        entityType=kind,
        entityId=wire,
        operation=operation,
        keyEpoch=1,
        encryptedPayload=encode64(encrypted.encode()),
        signature=encrypted.split(".")[4],
        senderSigningPublicKey=identity.public["signingPublicKey"],
    )
    value.pop("testPayload")
    return value


def forbidden_pair(identity, *, own=False):
    original = frame(1, identifier="shared")["testPayload"]
    original["historyJson"] = '[{"kind":"packin_task_assignees_v1","userIds":["other"]}]'
    candidate = {
        **original,
        "completedAt": 1793570400000,
        "completedByUserId": "member",
    }
    return (
        encrypted_frame(identity, 1, original),
        encrypted_frame(identity, 2, candidate, actor_device="own-device" if own else "other-device"),
    )


def test_real_signed_forbidden_completion_advances_revision_without_domain_change_then_allows_edit():
    async def run():
        identity = DeviceIdentity.generate()
        events = EventLog(PackState("pack1", "member", "member", data_epoch=2), lambda: {1: b"k" * 32})
        original, forbidden = forbidden_pair(identity)
        await events.feed(encode(original))
        prior = deepcopy(events.state.chores["shared"])
        await events.feed(encode(forbidden))
        key = forbidden["entityType"] + ":" + forbidden["entityId"]
        assert events.state.last_sequence == 2 and events.state.revisions[key] == 2
        assert events.state.chores["shared"] == prior
        assert events.metrics["domain_mutations_rejected"] == 1

        corrected = {**prior, "title": "A permitted title change"}
        await events.feed(encode(encrypted_frame(identity, 3, corrected)))
        assert events.state.last_sequence == 3 and events.state.revisions[key] == 3
        assert events.state.chores["shared"]["title"] == "A permitted title change"
        assert events.state.chores["shared"].get("completedAt") is None

    asyncio.run(run())


@pytest.mark.parametrize("field", ["ciphertext", "signature"])
def test_cryptographically_invalid_completion_never_advances_revision_cursor_or_receipts(field):
    async def run():
        identity = DeviceIdentity.generate()
        events = EventLog(PackState("pack1", "member", "member", data_epoch=2), lambda: {1: b"k" * 32})
        events.device_id = "own-device"
        original, invalid = forbidden_pair(identity, own=True)
        await events.feed(encode(original))
        parts = decode64(invalid["encryptedPayload"]).decode().split(".")
        index = 3 if field == "ciphertext" else 4
        damaged = bytearray(decode64(parts[index]))
        damaged[-1] ^= 1
        parts[index] = encode64(bytes(damaged))
        invalid["encryptedPayload"] = encode64(".".join(parts).encode())
        invalid["signature"] = parts[4]
        before = events.state.export()
        with pytest.raises((CryptoError, InvalidSignature, InvalidTag)):
            await events.feed(encode(invalid))
        assert events.state.export() == before
        assert events.metrics["domain_mutations_rejected"] == 0

    asyncio.run(run())


def test_signed_forbidden_snapshot_row_preserves_domain_but_persists_revision_and_rejected_own_receipt():
    async def run():
        identity = DeviceIdentity.generate()
        events = EventLog(PackState("pack1", "member", "member", data_epoch=2), lambda: {1: b"k" * 32})
        events.device_id = "own-device"
        rows = [{**value, "type": "SNAPSHOT_ROW"} for value in forbidden_pair(identity, own=True)]
        begin, complete = boundaries(rows)
        await events.feed(encode(begin))
        for row in rows:
            await events.feed(encode(row))
        assert not events.state.chores
        await events.feed(encode(complete))
        key = rows[1]["entityType"] + ":" + rows[1]["entityId"]
        assert events.state.last_sequence == 2 and events.state.revisions[key] == 2
        assert events.state.chores["shared"].get("completedAt") is None
        assert events.state.own_applied_events == []
        assert events.state.own_rejected_events == ["event-2"]
        restored = PackState.restore(events.state.export(), "pack1", "member")
        assert restored.own_rejected_events == ["event-2"] and restored.revisions[key] == 2

    asyncio.run(run())
