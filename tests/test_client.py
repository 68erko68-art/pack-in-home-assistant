"""Local transport fixtures exercise the real crypto, replay and durable outbox."""

import asyncio
from copy import deepcopy
from types import SimpleNamespace
from datetime import datetime, timezone
import hashlib
import json

import aiohttp
import pytest

from packin_pure import client as client_module
from packin_pure.api import PackInApi, PackInApiError, SCOPES
from packin_pure.client import PackClient, ActionPending, Conflict
from packin_pure.crypto import DeviceIdentity, encode64
from packin_pure.protocol import CAPABILITIES, descriptor
from packin_pure.state import PermissionDenied, occurrence


def run(coro):
    return asyncio.run(coro)


async def client_fixture(cache=None):
    session = aiohttp.ClientSession()
    identity = DeviceIdentity.generate()
    api = PackInApi(
        session,
        identity,
        {
            "pack_id": "pack-a",
            "user_id": "user-a",
            "connection_id": "ha_" + "a" * 32,
            "role": "member",
            "data_epoch": 1,
            "key_epoch": 1,
            "pack_keys": {"1": encode64(b"k" * 32)},
            "scopes": SCOPES,
            "time_zone": "UTC",
            "access_expires_at_ms": int((datetime.now(timezone.utc).timestamp() + 3600) * 1000),
            "members": [{"userId": "user-a", "role": "member", "locationConsent": False}],
        },
    )
    saved, notices, denied = [], [], []

    async def persist(value):
        saved.append(deepcopy(value))

    client = PackClient(
        api,
        cache or {},
        persist,
        lambda: notices.append(True),
        denied.append,
        lambda coro, name: asyncio.create_task(coro, name=name),
    )
    client.log.synced = True
    client.status = "connected"
    client._connection_id = "connection-one"
    client._ready.set()
    sent = []

    async def send(wire):
        sent.append(deepcopy(wire))
        if wire["type"] != "MUTATE":
            return
        assert saved[-1]["outbox"]["wire"] == wire
        frame = {
            **wire,
            "type": "PACK_EVENT",
            "protocolVersion": 3,
            "syncGeneration": 3,
            "packId": "pack-a",
            "actorUserId": "user-a",
            "actorDeviceId": api.data["connection_id"],
            "serverSequence": client.state.last_sequence + 1,
            "entityVersion": wire["baseRevision"] + 1,
            "serverTimestamp": "2026-11-01T23:00:00Z",
        }
        await client._frame(json.dumps(frame))

    client._send = send
    return session, client, saved, sent, denied


def task(identifier="task-a", **changes):
    return {
        "id": identifier,
        "title": "Feed the dog",
        "createdByUserId": "user-a",
        "assignmentMode": "UNASSIGNED",
        "assigneeUserId": None,
        "claimedByUserId": None,
        "historyJson": "[]",
        "createdAt": 1000,
        "updatedAt": 1000,
        "dueAt": None,
        "reminderAt": None,
        "recurrence": None,
        "completedAt": None,
        "completedByUserId": None,
        **changes,
    }


def test_persist_before_send_and_only_verified_event_completes_action():
    async def scenario():
        session, client, saved, sent, _ = await client_fixture()
        try:
            identifier = await client.add_task("Milk bowls")
            assert client.state.chores[identifier]["title"] == "Milk bowls"
            assert client.outbox is None
            assert saved[-1]["state"]["last_sequence"] == 1
            assert sent[0]["deviceSequence"] == 1
            assert sent[0]["expectedPackSequence"] == 0
            assert "payload" not in sent[0]
            assert client.metrics["mutations_verified"] == 1
        finally:
            await session.close()

    run(scenario())


def test_purchase_metadata_and_default_list_are_preserved():
    async def scenario():
        session, client, _, sent, _ = await client_fixture()
        try:
            identifier = await client.add_grocery("Milk", "2 bottles")
            assert [x["eventType"] for x in sent] == ["shopping.list.upserted", "grocery.item.upserted"]
            item = client.state.groceries[identifier]
            item["groupName"] = "Dairy"
            item["extensionFromNewerPhone"] = {"keep": True}
            await client.update_grocery(identifier, {"checked": True})
            item = client.state.groceries[identifier]
            assert item["checked"] and item["purchasedByUserId"] == "user-a"
            assert item["quantity"] == "2 bottles" and item["groupName"] == "Dairy"
            assert item["extensionFromNewerPhone"] == {"keep": True}
            await client.update_grocery(identifier, {"checked": False})
            assert client.state.groceries[identifier]["purchasedAt"] is None
        finally:
            await session.close()

    run(scenario())


@pytest.mark.parametrize("recurrence,due,expected_count", [("daily", 1793500000000, 2), ("weekly", None, 3)])
def test_recurring_completion_records_occurrence_and_advances_parent(recurrence, due, expected_count):
    async def scenario():
        session, client, saved, sent, _ = await client_fixture()
        try:
            client.state.chores["task-a"] = task(recurrence=recurrence, dueAt=due)
            await client.update_task("task-a", {"completed": True})
            assert len(sent) == expected_count
            completed = [x for x in client.state.chores.values() if occurrence(x)]
            assert len(completed) == 1 and completed[0]["completedByUserId"] == "user-a"
            parent = client.state.chores["task-a"]
            assert parent["completedAt"] is None and parent["dueAt"] > completed[0]["completedAt"]
            assert client.workflow is None
            assert any(x["workflow"] is not None for x in saved)
        finally:
            await session.close()

    run(scenario())


def test_unassigned_allowed_other_assignee_denied_multiple_shared_completion():
    async def scenario():
        session, client, _, sent, _ = await client_fixture()
        try:
            client.state.chores["task-a"] = task(assigneeUserId="user-b", assignmentMode="MEMBER")
            with pytest.raises(PermissionDenied):
                await client.update_task("task-a", {"completed": True})
            assert not sent
            client.state.chores["task-a"]["historyJson"] = json.dumps(
                [{"kind": "packin_task_assignees_v1", "userIds": ["user-a", "user-b"]}]
            )
            await client.update_task("task-a", {"completed": True})
            assert client.state.chores["task-a"]["completedByUserId"] == "user-a"
        finally:
            await session.close()

    run(scenario())


def test_immutable_outbox_retries_once_per_connection():
    async def scenario():
        session, client, saved, sent, _ = await client_fixture()
        try:
            client.outbox = {"wire": {"type": "MUTATE", "eventId": "stable-id"}}

            async def capture(value):
                sent.append(deepcopy(value))

            client._send = capture
            await client._send_outbox()
            await client._send_outbox()
            assert len(sent) == 1
            client._connection_id = "connection-two"
            await client._send_outbox()
            assert len(sent) == 2 and sent[0] == sent[1]
        finally:
            await session.close()

    run(scenario())


def test_definite_conflict_does_not_replay_stale_ciphertext():
    async def scenario():
        session, client, saved, sent, _ = await client_fixture()
        try:
            client.outbox = {"wire": {"clientMutationId": "mutation-a", "eventId": "event-a"}}
            client._result = asyncio.get_running_loop().create_future()
            await client._frame(
                json.dumps(
                    {"type": "MUTATION_REJECTED", "clientMutationId": "mutation-a", "code": "stale_pack_sequence"}
                )
            )
            with pytest.raises(Conflict):
                await client._result
            assert client.outbox is None and saved[-1]["outbox"] is None
        finally:
            await session.close()

    run(scenario())


def test_consent_removal_clears_location_immediately_and_diagnostics_redact():
    async def scenario():
        session, client, _, _, denied = await client_fixture()
        try:
            client.locations["user-a"] = "sensitive-coordinates"
            await client._frame(
                json.dumps({"type": "HOME_ASSISTANT_LOCATION_CONSENT", "userId": "user-a", "enabled": False})
            )
            assert not client.locations
            diagnostic = json.dumps(client.diagnostics())
            assert "sensitive" not in diagnostic and "user-a" not in diagnostic and "pack_keys" not in diagnostic
            client.state.chores["task-a"] = task()
            await client._deny("subscription_expired")
            assert not client.state.chores and not client.api.data["pack_keys"]
            assert denied == ["subscription_expired"]
            with pytest.raises(ActionPending):
                await client.add_task("Not authorized")
        finally:
            await session.close()

    run(scenario())


@pytest.mark.parametrize("pause_at", ["request", "decode"])
@pytest.mark.parametrize("control", ["unavailable", "consent", "removed"])
def test_location_clear_during_refresh_cannot_restore_old_position(monkeypatch, pause_at, control):
    async def scenario():
        session, client, _, _, _ = await client_fixture()
        client.api.data["members"] = [
            {"userId": "user-a", "locationConsent": True},
            {"userId": "user-b", "locationConsent": True},
        ]
        client.locations = {"user-a": "previous-a", "user-b": "previous-b"}
        client._last_location_attempt = client_module.time.monotonic() - 61
        paused = asyncio.Event()
        release = asyncio.Event()
        calls = []
        real_to_thread = asyncio.to_thread

        async def wait_for_clear():
            paused.set()
            await release.wait()

        async def locations():
            calls.append(True)
            if pause_at == "request":
                await wait_for_clear()
            return {"locations": []}

        def decode(_, pack_id, keys, allowed, now):
            return {user_id: "response-" + user_id for user_id in allowed}

        async def to_thread(function, *args):
            if function is decode and pause_at == "decode":
                await wait_for_clear()
            return await real_to_thread(function, *args)

        monkeypatch.setattr(client.api, "locations", locations)
        monkeypatch.setattr(client_module, "decode_locations", decode)
        monkeypatch.setattr(asyncio, "to_thread", to_thread)
        refresh = asyncio.create_task(client.refresh_locations())
        try:
            await asyncio.wait_for(paused.wait(), timeout=2)
            frame = {
                "type": {
                    "unavailable": "HOME_ASSISTANT_LOCATION_UNAVAILABLE",
                    "consent": "HOME_ASSISTANT_LOCATION_CONSENT",
                    "removed": "HOME_ASSISTANT_MEMBER_REMOVED",
                }[control],
                "userId": "user-a",
                "enabled": False,
            }
            await client._frame(json.dumps(frame))
            assert client.locations == {"user-b": "previous-b"}
            if control == "consent":
                # A new grant must not make a response to an old request current.
                await client._frame(json.dumps({**frame, "enabled": True}))
            release.set()
            await asyncio.wait_for(refresh, timeout=2)
            assert client.locations == {"user-b": "response-user-b"}
            await client.refresh_locations()
            assert calls == [True]
        finally:
            refresh.cancel()
            await asyncio.gather(refresh, return_exceptions=True)
            await session.close()

    run(scenario())


def test_no_location_request_when_disabled_no_consent_or_cooldown():
    async def scenario():
        session, client, _, _, _ = await client_fixture()
        calls = []

        async def locations():
            calls.append(True)
            return {"locations": []}

        client.api.locations = locations
        try:
            await client.refresh_locations()
            assert not calls
            client.api.data["members"][0]["locationConsent"] = True
            client.location_interval = 0
            await client.refresh_locations()
            assert not calls
            client.location_interval = 600
            await client.refresh_locations()
            await client.refresh_locations()
            assert len(calls) == 1
        finally:
            await session.close()

    run(scenario())


def test_recovered_undated_recurring_workflow_uses_stable_normalized_due():
    async def scenario():
        session, client, _, sent, _ = await client_fixture()
        try:
            now = 1793574000000
            client.state.chores["task-a"] = task(recurrence="daily", dueAt=now)
            client.workflow = {"parent": "task-a", "due": now, "recurrence": "daily", "now": now, "phase": "normalize"}
            await client._recover_workflow()
            assert len(sent) == 2
            assert len([x for x in client.state.chores.values() if occurrence(x)]) == 1
            assert client.workflow is None
        finally:
            await session.close()

    run(scenario())


def test_expired_authorization_never_reports_cached_data_available():
    async def scenario():
        session, client, _, _, _ = await client_fixture()
        try:
            client.api.data["access_expires_at_ms"] = 1
            assert client.available is False
            with pytest.raises(ActionPending):
                await client.add_task("Expired permission")
        finally:
            await session.close()

    run(scenario())


def test_superseded_connection_cannot_restart_from_a_copied_cache():
    async def scenario():
        session, client, saved, _, _ = await client_fixture()
        try:
            client.state.chores["task-a"] = task()
            await client._deny("duplicate_connection")
            assert client.api.data["reauth_reason"] == "duplicate_connection"
            assert client.api.data["members"] == []
            with pytest.raises(PackInApiError):
                await client.api.ensure_session()
            restarted = PackClient(
                client.api,
                saved[-1],
                client.persist,
                client.changed,
                client.auth_failed,
                lambda coro, name: asyncio.create_task(coro, name=name),
            )
            restarted.start()
            assert restarted._blocked and not restarted._tasks
            assert not restarted.state.chores and not restarted.available
        finally:
            await session.close()

    run(scenario())


def test_handshake_epoch_recovery_cancels_old_actions_and_never_loops_on_unchanged_epoch():
    async def scenario():
        session, client, saved, _, _ = await client_fixture()
        calls = []
        try:
            client.state.chores["task-a"] = task()
            client.outbox = {"wire": {"eventId": "old-epoch-action"}}

            async def metadata():
                calls.append(True)
                client.api.data["data_epoch"] = 2
                return {"authorityMode": "v3", "protocolVersion": 3, "syncGeneration": 3, "dataEpoch": 2}

            client.api.metadata = metadata
            assert await client._recover_handshake()
            assert client.state.data_epoch == 2 and not client.state.chores
            assert client.outbox is None and saved[-1]["outbox"] is None
            assert not await client._recover_handshake()
            assert client._blocked and client.status == "attention_required"
            assert len(calls) == 2
        finally:
            await session.close()

    run(scenario())


@pytest.mark.parametrize("status,blocked", [(0, False), (409, True)])
def test_failed_metadata_recovery_uses_backoff_instead_of_immediate_retry(status, blocked):
    async def scenario():
        session, client, _, _, _ = await client_fixture()

        async def metadata():
            raise PackInApiError(
                "network_unavailable" if not status else "home_assistant_sync_upgrade_required", status
            )

        client.api.metadata = metadata
        try:
            assert not await client._recover_handshake()
            assert client._blocked is blocked
        finally:
            await session.close()

    run(scenario())


def test_legacy_handshake_stops_after_one_metadata_check():
    async def scenario():
        session, client, _, _, _ = await client_fixture()
        calls = []

        async def websocket():
            calls.append("handshake")
            raise PackInApiError("home_assistant_sync_upgrade_required", 409)

        async def metadata():
            calls.append("metadata")
            return {"authorityMode": "legacy", "protocolVersion": 3, "syncGeneration": 3, "dataEpoch": 1}

        client.api.websocket = websocket
        client.api.metadata = metadata
        try:
            await asyncio.wait_for(client._connect_loop(), 2)
            assert calls == ["handshake", "metadata"]
            assert client._blocked and not client.available
        finally:
            await session.close()

    run(scenario())


def test_new_member_consent_refreshes_roster_once_without_member_polling():
    async def scenario():
        session, client, _, _, _ = await client_fixture()
        calls = []

        async def metadata():
            calls.append(True)
            client.api.data["members"].append({"userId": "new-member", "locationConsent": True})

        client.api.metadata = metadata
        try:
            frame = json.dumps({"type": "HOME_ASSISTANT_LOCATION_CONSENT", "userId": "new-member", "enabled": True})
            await client._frame(frame)
            await client._frame(frame)
            assert calls == [True]
            assert any(m["userId"] == "new-member" for m in client.api.data["members"])
        finally:
            await session.close()

    run(scenario())


def test_failed_key_request_can_recover_and_success_is_coalesced():
    async def scenario():
        session, client, _, _, _ = await client_fixture()
        calls = []

        async def request_key(epoch):
            calls.append(epoch)
            if len(calls) == 1:
                raise PackInApiError("temporary_failure", 503, 60)

        client.api.request_key = request_key
        try:
            with pytest.raises(PackInApiError):
                await client._hold_for_key(2)
            assert client._waiting_epoch == 2 and 2 not in client._key_requested
            assert not client.available
            await client._hold_for_key(2)
            await client._hold_for_key(2)
            assert calls == [2, 2] and 2 in client._key_requested
        finally:
            await session.close()

    run(scenario())


def test_key_ready_only_resumes_when_the_needed_epoch_is_installed():
    async def scenario():
        session, client, _, sent, _ = await client_fixture()
        calls = []

        async def request_key(epoch):
            calls.append(epoch)

        async def refresh_keys():
            return None

        client.api.request_key = request_key
        client.api.refresh_keys = refresh_keys
        try:
            await client._hold_for_key(2)
            await client._frame(json.dumps({"type": "HOME_ASSISTANT_KEYS_READY"}))
            assert client._waiting_key and not sent
            client.api.data["pack_keys"]["2"] = encode64(b"n" * 32)
            await client._frame(json.dumps({"type": "HOME_ASSISTANT_KEYS_READY"}))
            assert not client._waiting_key and client._waiting_epoch is None
            assert sent == [{"type": "SNAPSHOT"}]
            assert calls == [2]
        finally:
            await session.close()

    run(scenario())


def hello(client, epoch=None, head=7):
    return json.dumps(
        {
            "type": "HELLO",
            "packId": client.state.pack_id,
            "deviceId": client.api.data["connection_id"],
            "userId": client.state.user_id,
            "protocolVersion": 3,
            "syncGeneration": 3,
            "authorityMode": "v3",
            "dataEpoch": client.state.data_epoch if epoch is None else epoch,
            "headSequence": head,
            "nextDeviceSequence": 1,
            "capabilities": CAPABILITIES,
        }
    )


def restarted_client(client, cache):
    return PackClient(
        client.api,
        cache,
        client.persist,
        client.changed,
        client.auth_failed,
        lambda coro, name: asyncio.create_task(coro, name=name),
    )


async def snapshot_row(client, *, complete=True, item=None):
    """A real full-ledger boundary containing a previous-epoch legacy row."""

    async def decrypt(frame):
        return task() if item is None else deepcopy(item)

    client.log._decrypt = decrypt
    row = {
        "type": "SNAPSHOT_ROW",
        "snapshotKind": "EVENT_LOG_V1",
        "protocolVersion": 3,
        "syncGeneration": 3,
        "packId": client.state.pack_id,
        "dataEpoch": client.state.data_epoch,
        "originalDataEpoch": client.state.data_epoch - 1,
        "serverSequence": 1,
        "eventId": "legacy-event",
        "actorUserId": "user-a",
        "actorDeviceId": "phone-a",
        "eventType": "chore.upserted",
        "entityType": "legacy_envelope",
        "entityId": "legacy-event",
        "entityVersion": 1,
        "serverTimestamp": "2026-11-01T23:00:00Z",
    }
    raw = json.dumps(row)
    boundary = {
        "snapshotKind": "EVENT_LOG_V1",
        "snapshotDigestAlgorithm": "SHA-256-JSONL",
        "dataEpoch": client.state.data_epoch,
        "snapshotHeadSequence": 1,
        "rowCount": 1,
        "snapshotId": "snapshot-one",
        "snapshotDigest": hashlib.sha256((raw + "\n").encode()).hexdigest(),
    }
    await client._frame(json.dumps({"type": "SNAPSHOT_BEGIN", **boundary}))
    await client._frame(raw)
    if complete:
        await client._frame(json.dumps({"type": "SNAPSHOT_COMPLETE", **boundary}))
        await client._frame(
            json.dumps(
                {
                    "type": "SYNC_COMPLETE",
                    "headSequence": 1,
                    "lastSequence": 1,
                    "hasMore": False,
                }
            )
        )


def test_first_connection_snapshots_small_previous_epoch_ledger_and_persists_verified_bootstrap():
    async def scenario():
        session, client, saved, sent, _ = await client_fixture()
        try:
            await client._frame(hello(client, epoch=2, head=1))
            assert sent == [{"type": "SNAPSHOT", "capabilities": CAPABILITIES}]
            await snapshot_row(client)
            assert client.state.chores["task-a"]["title"] == "Feed the dog"
            assert client.state.last_sequence == 1 and client.available
            assert saved[-1]["bootstrap_verified"] is True
            assert len(sent) == 1  # Never RESUME 0 repeatedly for omitted old-epoch rows.

            restarted = restarted_client(client, saved[-1])
            restarted._send = client._send
            await restarted._frame(hello(restarted, head=1))
            assert sent[-1] == {"type": "RESUME", "afterSequence": 1, "capabilities": CAPABILITIES}
        finally:
            await session.close()

    run(scenario())


@pytest.mark.parametrize("sequence,marker", [(12, None), (12, True), (0, True)])
def test_healthy_cached_restart_and_offline_reconnect_resume_without_full_snapshot(sequence, marker):
    async def scenario():
        session, client, _, sent, _ = await client_fixture()
        try:
            client.state.last_sequence = sequence
            if sequence:
                client.state.chores["task-a"] = task()
            cache = {"state": client.state.export(), "outbox": {"wire": {"eventId": "pending-action"}}}
            if marker is not None:
                cache["bootstrap_verified"] = marker
            restarted = restarted_client(client, cache)
            restarted._send = client._send
            await restarted._frame(hello(restarted, head=sequence + 2))
            assert sent == [{"type": "RESUME", "afterSequence": sequence, "capabilities": CAPABILITIES}]
            assert restarted.outbox == cache["outbox"]
            assert restarted.state.chores == client.state.chores

            # A dropped transport must keep the same verified cursor and queued action.
            restarted.log.reset_connection()
            await restarted._frame(hello(restarted, head=sequence + 3))
            assert sent[-1] == sent[0] and len(sent) == 2
            assert restarted.outbox == cache["outbox"]
        finally:
            await session.close()

    run(scenario())


def test_hello_epoch_change_cancels_old_action_and_bootstraps_snapshot():
    async def scenario():
        session, client, saved, sent, _ = await client_fixture()
        try:
            client.state.last_sequence = 12
            client.state.chores["task-a"] = task()
            client.outbox = {"wire": {"eventId": "old-action"}}
            client._needs_snapshot = False
            await client._frame(hello(client, epoch=2, head=12))
            assert sent == [{"type": "SNAPSHOT", "capabilities": CAPABILITIES}]
            assert not client.state.chores and client.state.last_sequence == 0
            assert client.outbox is None and saved[-1]["bootstrap_verified"] is False
        finally:
            await session.close()

    run(scenario())


def test_metadata_epoch_recovery_also_requires_snapshot_on_next_hello():
    async def scenario():
        session, client, saved, sent, _ = await client_fixture()
        try:
            client.state.last_sequence = 12
            client._needs_snapshot = False

            async def metadata():
                client.api.data["data_epoch"] = 2
                return {"authorityMode": "v3", "protocolVersion": 3, "syncGeneration": 3, "dataEpoch": 2}

            client.api.metadata = metadata
            assert await client._recover_handshake()
            assert saved[-1]["bootstrap_verified"] is False
            await client._frame(hello(client, head=12))
            assert sent == [{"type": "SNAPSHOT", "capabilities": CAPABILITIES}]
        finally:
            await session.close()

    run(scenario())


def test_interrupted_snapshot_does_not_publish_partial_state_or_resume_as_verified_cache():
    async def scenario():
        session, client, saved, sent, _ = await client_fixture()
        try:
            await client._frame(hello(client, epoch=2, head=1))
            await snapshot_row(client, complete=False)
            assert not client.state.chores and client.state.last_sequence == 0
            await client._save()
            assert saved[-1]["bootstrap_verified"] is False

            restarted = restarted_client(client, saved[-1])
            restarted._send = client._send
            await restarted._frame(hello(restarted, head=1))
            assert sent[-1] == {"type": "SNAPSHOT", "capabilities": CAPABILITIES}
            assert not restarted.state.chores
        finally:
            await session.close()

    run(scenario())


def test_missing_key_during_server_requested_snapshot_restarts_snapshot_not_partial_replay():
    async def scenario():
        session, client, _, sent, _ = await client_fixture()
        try:
            client.state.last_sequence = 12
            client._needs_snapshot = False

            async def request_key(epoch):
                return None

            async def refresh_keys():
                return None

            client.api.request_key = request_key
            client.api.refresh_keys = refresh_keys
            await client._frame(json.dumps({"type": "SNAPSHOT_REQUIRED"}))
            assert sent == [{"type": "SNAPSHOT"}]
            await client._hold_for_key(2)
            client.api.data["pack_keys"]["2"] = encode64(b"n" * 32)
            await client._frame(json.dumps({"type": "HOME_ASSISTANT_KEYS_READY"}))
            assert sent[-1] == {"type": "SNAPSHOT"}
            assert client.state.last_sequence == 12
        finally:
            await session.close()

    run(scenario())


@pytest.mark.parametrize("assignee,allowed", [(None, True), ("user-b", False)])
def test_legacy_snapshot_zero_revision_keeps_assignment_permissions_for_first_v3_edit(assignee, allowed):
    async def scenario():
        session, client, _, sent, _ = await client_fixture()
        try:
            await client._frame(hello(client, epoch=2, head=1))
            item = task(
                assigneeUserId=assignee,
                assignmentMode="MEMBER" if assignee else "UNASSIGNED",
                extensionFromPhone={"keep": True},
            )
            await snapshot_row(client, item=item)
            # Legacy event IDs never masquerade as canonical entity revisions.
            _, wire_id, _ = descriptor("chore.upserted", item)
            assert client.state.revisions.get("chore:" + wire_id, 0) == 0
            client.log._decrypt = client.log._decode
            if allowed:
                await client.update_task("task-a", {"completed": True})
                mutation = sent[-1]
                assert mutation["type"] == "MUTATE"
                assert mutation["baseRevision"] == 0 and mutation["expectedPackSequence"] == 1
                assert client.state.revisions["chore:" + wire_id] == 1
                assert client.state.chores["task-a"]["completedByUserId"] == "user-a"
                assert client.state.chores["task-a"]["extensionFromPhone"] == {"keep": True}
            else:
                with pytest.raises(PermissionDenied):
                    await client.update_task("task-a", {"completed": True})
                assert not any(value["type"] == "MUTATE" for value in sent)
                assert client.state.chores["task-a"]["assigneeUserId"] == "user-b"
        finally:
            await session.close()

    run(scenario())


def test_signed_own_forbidden_completion_settles_rejected_and_never_success_or_workflow_retry():
    async def scenario():
        session, client, saved, _, _ = await client_fixture()
        try:
            original = task(assignmentMode="MEMBER", assigneeUserId="user-b")
            client.state.chores["task-a"] = deepcopy(original)
            kind, wire_id, operation = descriptor("chore.upserted", original)
            client.state.last_sequence = 1
            client.state.revisions[kind + ":" + wire_id] = 1
            payload = {**original, "completedAt": 1793570400000, "completedByUserId": "user-a"}
            event_id = "haevent-forbidden"
            encoded = client.api.identity.encrypt_event(
                json.dumps(payload).encode(),
                b"k" * 32,
                pack="pack-a",
                event=event_id,
                device=client.api.data["connection_id"],
                sequence=1,
                event_type="chore.upserted",
                epoch=1,
            )
            client.outbox = {"wire": {"eventId": event_id}}
            client.workflow = {"parent": "task-a", "phase": "complete"}
            client._result = asyncio.get_running_loop().create_future()
            frame = {
                "type": "PACK_EVENT",
                "protocolVersion": 3,
                "syncGeneration": 3,
                "packId": "pack-a",
                "dataEpoch": 1,
                "serverSequence": 2,
                "eventId": event_id,
                "eventType": "chore.upserted",
                "actorUserId": "user-a",
                "actorDeviceId": client.api.data["connection_id"],
                "deviceSequence": 1,
                "keyEpoch": 1,
                "entityType": kind,
                "entityId": wire_id,
                "entityVersion": 2,
                "operation": operation,
                "serverTimestamp": "2026-11-01T23:00:00Z",
                "encryptedPayload": encode64(encoded.encode()),
                "signature": encoded.split(".")[4],
                "senderSigningPublicKey": client.api.identity.public["signingPublicKey"],
            }
            await client._frame(json.dumps(frame))
            with pytest.raises(PermissionDenied):
                await client._result
            assert client.state.chores["task-a"] == original
            assert client.state.last_sequence == 2 and client.state.revisions[kind + ":" + wire_id] == 2
            assert client.state.own_applied_events == []
            assert client.state.own_rejected_events == [event_id]
            assert client.outbox is None and client.workflow is None
            assert client.metrics["mutations_verified"] == 0 and client.metrics["mutations_rejected"] == 1
            assert saved[-1]["outbox"] is None and saved[-1]["workflow"] is None

            # A crash after a durable quarantine but before outbox settlement is also definitive.
            cache = deepcopy(saved[-1])
            cache["outbox"] = {"wire": {"eventId": event_id}}
            cache["workflow"] = {"parent": "task-a", "phase": "complete"}
            restarted = restarted_client(client, cache)
            restarted._result = asyncio.get_running_loop().create_future()
            await restarted._settle_receipt()
            with pytest.raises(PermissionDenied):
                await restarted._result
            assert restarted.outbox is None and restarted.workflow is None
            assert restarted.metrics["mutations_verified"] == 0
            assert restarted.metrics["mutations_rejected"] == 1
        finally:
            await session.close()

    run(scenario())


@pytest.mark.parametrize(
    "retry_after,cooldown,expected",
    [(0, 0, 5), (120, 0, 120), (0, 45, 45), (120, 180, 180)],
)
def test_recovered_connection_resets_backoff_without_shortening_retry_floors(
    monkeypatch, retry_after, cooldown, expected
):
    async def scenario():
        session, client, _, _, denied = await client_fixture()
        now = [1000.0]
        waits = []
        attempts = []
        renewals = []
        client.outbox = {"wire": {"clientMutationId": "pending-action", "ciphertext": "immutable"}}
        client.workflow = {"action": "pending-workflow"}
        original_outbox = deepcopy(client.outbox)
        original_workflow = deepcopy(client.workflow)

        class Socket:
            closed = False
            close_code = 4003 if retry_after else 1000

            async def receive(self):
                now[0] += 301
                client._retry_not_before = now[0] + cooldown
                return SimpleNamespace(type=aiohttp.WSMsgType.CLOSE, extra="")

            async def close(self):
                self.closed = True

        socket = Socket()

        async def websocket():
            attempts.append(True)
            if len(attempts) <= 6:
                raise aiohttp.ClientConnectionError("offline")
            return socket

        async def ensure_session(*, force=False):
            renewals.append(force)
            raise PackInApiError("rate_limited", 429, retry_after)

        async def sleep(delay):
            waits.append(delay)
            now[0] += delay
            if len(waits) == 7:
                client._stopping = True

        client.api.websocket = websocket
        client.api.ensure_session = ensure_session
        monkeypatch.setattr(client_module, "time", SimpleNamespace(monotonic=lambda: now[0]))
        monkeypatch.setattr(client_module, "asyncio", SimpleNamespace(sleep=sleep, TimeoutError=asyncio.TimeoutError))
        monkeypatch.setattr(client_module, "random", SimpleNamespace(uniform=lambda _low, _high: 1.0))
        try:
            await client._connect_loop()
            assert waits == [5, 15, 30, 60, 300, 900, expected]
            assert len(attempts) == 7
            assert renewals == ([True] if retry_after else [])
            assert socket.closed and client._ws is None
            assert client.outbox == original_outbox
            assert client.workflow == original_workflow
            assert denied == []
        finally:
            await session.close()

    run(scenario())
