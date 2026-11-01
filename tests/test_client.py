"""Local transport fixtures exercise the real crypto, replay and durable outbox."""

import asyncio
from copy import deepcopy
from datetime import datetime, timezone
import json

import aiohttp
import pytest

from packin_pure.api import PackInApi, SCOPES
from packin_pure.client import PackClient, ActionPending, Conflict
from packin_pure.crypto import DeviceIdentity, encode64
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
