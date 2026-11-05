"""Negotiated legacy transport, real native crypto and signed loopback commands."""

import asyncio
from contextlib import asynccontextmanager
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import time

import aiohttp
from aiohttp import web
from cryptography.exceptions import InvalidTag
import pytest

from packin_pure.api import PackInApi, PackInApiError, SCOPES, new_pairing
from packin_pure.client import Conflict, PackClient
from packin_pure.crypto import CryptoError, DeviceIdentity, decode64, decrypt_event, encode64, verify
from packin_pure.protocol import (
    LEGACY_CAPABILITIES,
    LEGACY_COMMAND_MODE,
    LEGACY_GATEWAY_CAPABILITY,
    UnsupportedSchema,
    decode_event,
)
from packin_pure.state import PermissionDenied


@pytest.fixture(autouse=True)
def loopback_transport_only(request):
    import importlib.util

    if importlib.util.find_spec("pytest_homeassistant") is not None:
        request.getfixturevalue("socket_enabled")
        import pytest_socket

        pytest_socket.socket_allow_hosts(["127.0.0.1"])


@asynccontextmanager
async def server(handler):
    app = web.Application()
    app.router.add_route("*", "/{path:.*}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    try:
        yield "http://127.0.0.1:" + str(runner.addresses[0][1])
    finally:
        await runner.cleanup()


def metadata():
    return {
        "authorityMode": "legacy",
        "commandMode": LEGACY_COMMAND_MODE,
        "protocolVersion": 1,
        "syncGeneration": 1,
        "capabilities": LEGACY_CAPABILITIES,
    }


def data():
    return {
        "pack_id": "pack-a",
        "user_id": "user-a",
        "connection_id": "ha_" + "a" * 32,
        "access_token": "a" * 43,
        "refresh_token": "r" * 43,
        "role": "member",
        "data_epoch": 1,
        "key_epoch": 1,
        "pack_keys": {"1": encode64(b"k" * 32)},
        "scopes": SCOPES,
        "time_zone": "UTC",
        "access_expires_at_ms": int(time.time() * 1000) + 3600000,
        "authority_mode": "legacy",
        "command_mode": LEGACY_COMMAND_MODE,
        "protocol_version": 1,
        "sync_generation": 1,
        "capabilities": LEGACY_CAPABILITIES,
    }


def client_for(session, origin=None):
    api = PackInApi(session, DeviceIdentity.generate(), data(), _test_origin=origin)
    saved, denied, sent = [], [], []

    async def persist(value):
        saved.append(deepcopy(value))

    client = PackClient(
        api, {}, persist, lambda: None, denied.append, lambda coro, name: asyncio.create_task(coro, name=name)
    )
    client.log.synced = True
    client.status = "connected"
    client._connection_id = "connection-one"

    async def send(value):
        sent.append(deepcopy(value))

    client._send = send
    return client, saved, denied, sent


def native_frame(client, wire, *, sequence=1):
    return {
        **wire,
        "type": "PACK_EVENT",
        "protocolVersion": 1,
        "syncGeneration": 1,
        "packId": client.state.pack_id,
        "actorUserId": "user-a",
        "actorDeviceId": client.api.data["connection_id"],
        "serverSequence": sequence,
        "entityType": "legacy_envelope",
        "entityId": wire["eventId"],
        "entityVersion": 1,
        "serverTimestamp": "2026-11-04T12:00:00Z",
        "encryption": {
            "scheme": "packin-legacy-envelope-v1",
            "deviceSequence": wire["deviceSequence"],
            "senderSigningPublicKey": client.api.identity.public["signingPublicKey"],
        },
    }


def payload():
    return {
        "id": "task-a",
        "title": "Keep my task",
        "createdByUserId": "user-a",
        "assignmentMode": "MEMBER",
        "assigneeUserId": "user-a",
        "claimedByUserId": None,
        "historyJson": '[{"kind":"packin_task_assignees_v1","userIds":["user-a","member-b"]}]',
        "createdAt": 1000,
        "updatedAt": 2000,
        "completedAt": 2000,
        "completedByUserId": "user-a",
        "dueAt": None,
        "extensionFromPhone": {"retain": True},
    }


def accepted(wire):
    return {
        "type": "MUTATION_ACCEPTED",
        "eventId": wire["eventId"],
        "clientMutationId": wire["clientMutationId"],
        "serverSequence": 1,
    }


def test_pairing_explicitly_advertises_legacy_gateway():
    pairing = new_pairing("Home Assistant", ["tasks:read"])
    assert pairing.request["capabilities"] == [LEGACY_GATEWAY_CAPABILITY]
    assert "dataEpoch" not in pairing.request and "authorityMode" not in pairing.request


@pytest.mark.parametrize("assignee", ["not-in-current-roster", "read-only-member"])
def test_legacy_assign_task_rejects_members_outside_current_writer_roster_before_http(assignee):
    async def scenario():
        async with aiohttp.ClientSession() as session:
            client, _, _, _ = client_for(session)
            client.api.data["members"] = [
                {"userId": "user-a", "role": "member"},
                {"userId": "read-only-member", "role": "read_only"},
            ]
            with pytest.raises(PermissionDenied):
                await client.assign_task("task-a", [assignee])
            assert client.api.metrics["http_requests"] == 0 and client.outbox is None

    asyncio.run(scenario())


def test_legacy_read_only_linking_member_cannot_send_gateway_mutation():
    async def scenario():
        async with aiohttp.ClientSession() as session:
            client, _, _, _ = client_for(session)
            client.state.role = client.api.data["role"] = "read_only"
            with pytest.raises(PermissionDenied):
                await client._mutate("chore.upserted", payload())
            assert client.api.metrics["http_requests"] == 0 and client.outbox is None

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "change",
    [
        {"authorityMode": "cutting_over"},
        {"capabilities": []},
        {"capabilities": None},
        {"commandMode": "v3"},
        {"protocolVersion": 3},
        {"syncGeneration": True},
    ],
)
def test_legacy_metadata_requires_explicit_complete_negotiation(change):
    async def scenario():
        async with aiohttp.ClientSession() as session:
            api = PackInApi(session, DeviceIdentity.generate())
            with pytest.raises(PackInApiError):
                await api._merge_metadata({**metadata(), **change})
            assert "authority_mode" not in api.data

    asyncio.run(scenario())


def test_legacy_hello_and_android_golden_envelope_keep_real_wire_version():
    async def scenario():
        async with aiohttp.ClientSession() as session:
            client, _, _, sent = client_for(session)
            hello = {
                "type": "HELLO",
                **metadata(),
                "packId": "pack-a",
                "userId": "user-a",
                "deviceId": client.api.data["connection_id"],
                "dataEpoch": 1,
                "nextDeviceSequence": 9,
            }
            await client._frame(json.dumps(hello))
            assert sent == [{"type": "SNAPSHOT", "capabilities": LEGACY_CAPABILITIES}]
            assert client.device_sequence == 8
            vector = json.loads((Path(__file__).parent / "fixtures/tink_android.json").read_bytes())
            ctx = vector["context"]
            row = {
                "protocolVersion": 1,
                "syncGeneration": 1,
                "packId": ctx["pack"],
                "eventId": ctx["event"],
                "actorDeviceId": ctx["device"],
                "eventType": ctx["event_type"],
                "keyEpoch": ctx["epoch"],
                "entityType": "legacy_envelope",
                "encryptedPayload": encode64(vector["envelope"].encode()),
                "encryption": {
                    "scheme": "packin-legacy-envelope-v1",
                    "deviceSequence": ctx["sequence"],
                    "senderSigningPublicKey": vector["signing_public"],
                },
            }
            assert decode_event(
                row, ctx["pack"], {ctx["epoch"]: decode64(vector["pack_key"])}, authority_mode="legacy"
            ) == json.loads(decode64(vector["clear"]))
            with pytest.raises(UnsupportedSchema):
                decode_event(row, ctx["pack"], {ctx["epoch"]: decode64(vector["pack_key"])})
            with pytest.raises(UnsupportedSchema):
                await client._frame(json.dumps({**hello, "authorityMode": "v3", "protocolVersion": 3}))

    asyncio.run(scenario())


def test_http_acceptance_waits_for_authenticated_native_echo_and_preserves_payload():
    async def scenario():
        wires, replies = [], asyncio.Event()
        client = None

        async def handler(request):
            raw = await request.read()
            wire = json.loads(raw)
            assert request.path.endswith("/legacy-mutations")
            proof = "|".join(
                (
                    "pack-in-ha-request",
                    "1",
                    "POST",
                    request.raw_path,
                    request.headers["x-packin-ha-time"],
                    request.headers["x-packin-ha-nonce"],
                    hashlib.sha256(raw).hexdigest(),
                    hashlib.sha256(("a" * 43).encode()).hexdigest(),
                )
            )
            verify(
                proof.encode(),
                decode64(request.headers["x-packin-ha-signature"]),
                client.api.identity.public["signingPublicKey"],
            )
            assert saved[-1]["outbox"] == {"wire": wire, "authority_mode": "legacy"}
            clear = decrypt_event(
                decode64(wire["encryptedPayload"]).decode(),
                b"k" * 32,
                client.api.identity.public["signingPublicKey"],
                pack="pack-a",
                event=wire["eventId"],
                device=client.api.data["connection_id"],
                sequence=wire["deviceSequence"],
                event_type=wire["eventType"],
                epoch=1,
            )
            assert json.loads(clear) == payload()
            assert wire["expectedPackSequence"] == 0 and wire["baseRevision"] == 0
            wires.append(wire)
            return web.json_response(accepted(wire))

        async with server(handler) as origin, aiohttp.ClientSession() as session:
            client, saved, _, sent = client_for(session, origin)
            client.state.chores["task-a"] = {**payload(), "completedAt": None, "completedByUserId": None}
            client.device_sequence = 6
            original = client.api.legacy_mutation

            async def observed(wire):
                result = await original(wire)
                replies.set()
                return result

            client.api.legacy_mutation = observed
            operation = asyncio.create_task(client._mutate("chore.upserted", payload()))
            await asyncio.wait_for(replies.wait(), 3)
            assert client.outbox is not None and not client._result.done() and sent == []
            await client._frame(json.dumps(native_frame(client, wires[0])))
            await operation
            assert client.outbox is None and client.state.chores["task-a"]["completedByUserId"] == "user-a"
            assert client.state.chores["task-a"]["historyJson"] == payload()["historyJson"]
            assert client.state.chores["task-a"]["extensionFromPhone"] == {"retain": True}
            assert wires[0]["deviceSequence"] == 7
            assert client.state.device_sequence == 7 and saved[-1]["device_sequence"] == 7
            resumed = PackClient(
                client.api, saved[-1], client.persist, client.changed, client.auth_failed, client.create_task
            )
            assert resumed.device_sequence == 7 and resumed.authority_mode == "legacy"
            await client._frame(json.dumps(native_frame(client, wires[0])))
            assert client.metrics["mutations_verified"] == 1 and client.state.last_sequence == 1

    asyncio.run(scenario())


def test_lost_response_replays_exact_outbox_without_duplicate_native_commit():
    async def scenario():
        bodies, commits = [], {}
        client = None

        async def handler(request):
            raw = await request.read()
            bodies.append(raw)
            wire = json.loads(raw)
            commits.setdefault(wire["eventId"], wire)
            assert commits[wire["eventId"]] == wire
            if len(bodies) == 1:
                request.transport.close()
                return web.Response()
            await client._frame(json.dumps(native_frame(client, wire)))
            return web.json_response(accepted(wire))

        async with server(handler) as origin, aiohttp.ClientSession() as session:
            client, saved, _, _ = client_for(session, origin)
            client.state.chores["task-a"] = {**payload(), "completedAt": None, "completedByUserId": None}
            with pytest.raises(PackInApiError):
                await client._mutate("chore.upserted", payload())
            pending = deepcopy(client.outbox)
            assert pending is not None and saved[-1]["outbox"] == pending
            client._connection_id = "connection-two"
            await client._send_outbox()
            assert bodies[0] == bodies[1] and len(commits) == 1
            assert client.outbox is None and client.state.last_sequence == 1

    asyncio.run(scenario())


def test_verified_echo_winning_http_error_race_still_settles_once():
    async def scenario():
        client = None

        async def handler(request):
            wire = await request.json()
            await client._frame(json.dumps(native_frame(client, wire)))
            return web.json_response({"error": {"code": "mirror_pending"}}, status=503)

        async with server(handler) as origin, aiohttp.ClientSession() as session:
            client, _, _, _ = client_for(session, origin)
            client.state.chores["task-a"] = {**payload(), "completedAt": None, "completedByUserId": None}
            await client._mutate("chore.upserted", payload())
            assert client.outbox is None and client.metrics["mutations_verified"] == 1

    asyncio.run(scenario())


def test_one_real_websocket_replays_legacy_snapshot_and_echoes_http_command():
    async def scenario():
        connection, commands = None, []

        async def handler(request):
            nonlocal connection
            if request.path.endswith("/realtime"):
                assert request.query["protocolVersion"] == "1" and request.query["syncGeneration"] == "1"
                connection = web.WebSocketResponse()
                await connection.prepare(request)
                await connection.send_json(
                    {
                        "type": "HELLO",
                        **metadata(),
                        "packId": "pack-a",
                        "deviceId": client.api.data["connection_id"],
                        "userId": "user-a",
                        "dataEpoch": 1,
                        "headSequence": 0,
                        "nextDeviceSequence": 7,
                    }
                )
                sync = await connection.receive_json()
                assert sync == {"type": "SNAPSHOT", "capabilities": LEGACY_CAPABILITIES}
                boundary = {
                    "snapshotKind": "EVENT_LOG_V1",
                    "snapshotDigestAlgorithm": "SHA-256-JSONL",
                    "snapshotDigest": hashlib.sha256(b"").hexdigest(),
                    "dataEpoch": 1,
                    "snapshotHeadSequence": 0,
                    "rowCount": 0,
                    "snapshotId": "legacy-empty",
                }
                await connection.send_json({"type": "SNAPSHOT_BEGIN", **boundary})
                await connection.send_json({"type": "SNAPSHOT_COMPLETE", **boundary})
                await connection.send_json(
                    {"type": "SYNC_COMPLETE", "headSequence": 0, "lastSequence": 0, "hasMore": False}
                )
                async for message in connection:
                    # Commands must never use the V3 WebSocket MUTATE path.
                    assert message.type != aiohttp.WSMsgType.TEXT
                return connection
            assert request.path.endswith("/legacy-mutations")
            wire = await request.json()
            commands.append(wire)
            await connection.send_json(native_frame(client, wire))
            return web.json_response(accepted(wire))

        async with server(handler) as origin, aiohttp.ClientSession() as session:
            client, saved, _, _ = client_for(session, origin)
            # This case uses the actual PackClient send and receive loop.
            del client._send
            client.log.synced = False
            client._needs_snapshot = True
            client.start()
            try:
                await asyncio.wait_for(client._ready.wait(), 3)
                await client.add_task("Native legacy task")
                assert len(commands) == 1 and commands[0]["deviceSequence"] == 7
                assert next(iter(client.state.chores.values()))["title"] == "Native legacy task"
                assert client.api.metrics["websocket_handshakes"] == 1
                assert client.metrics["mutations_verified"] == 1 and saved[-1]["outbox"] is None
            finally:
                await client.stop()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "status,code,rejected",
    [
        (409, "stale_pack_sequence", True),
        (409, "key_epoch_changed", True),
        (409, "unknown_conflict", False),
        (503, "mirror_pending", False),
    ],
)
def test_only_proven_uncommitted_conflicts_clear_outbox(status, code, rejected):
    async def scenario():
        async def handler(request):
            return web.json_response({"error": {"code": code}}, status=status)

        async with server(handler) as origin, aiohttp.ClientSession() as session:
            client, _, _, _ = client_for(session, origin)
            with pytest.raises(Conflict if rejected else PackInApiError):
                await client._mutate("chore.upserted", payload())
            assert (client.outbox is None) == rejected
            assert client.state.last_sequence == 0 and not client.state.chores

    asyncio.run(scenario())


def test_tampered_native_ciphertext_does_not_advance_legacy_replay():
    async def scenario():
        async with aiohttp.ClientSession() as session:
            client, _, _, _ = client_for(session)
            encoded = client.api.identity.encrypt_event(
                json.dumps(payload()).encode(),
                b"k" * 32,
                pack="pack-a",
                event="event-a",
                device=client.api.data["connection_id"],
                sequence=1,
                event_type="chore.upserted",
                epoch=1,
            )
            wire = {
                "eventId": "event-a",
                "eventType": "chore.upserted",
                "deviceSequence": 1,
                "dataEpoch": 1,
                "keyEpoch": 1,
                "encryptedPayload": encode64(encoded.encode()),
            }
            parts = encoded.split(".")
            ciphertext = bytearray(decode64(parts[3]))
            ciphertext[-1] ^= 1
            parts[3] = encode64(ciphertext)
            wire["encryptedPayload"] = encode64(".".join(parts).encode())
            with pytest.raises((CryptoError, InvalidTag)):
                await client._frame(json.dumps(native_frame(client, wire)))
            assert client.state.last_sequence == 0 and not client.state.chores

    asyncio.run(scenario())


def test_nonempty_native_legacy_snapshot_replays_without_migration_or_key_changes():
    async def scenario():
        async with aiohttp.ClientSession() as session:
            client, saved, _, _ = client_for(session)
            client.log.synced = False
            original_keys = deepcopy(client.api.data["pack_keys"])
            item = {**payload(), "completedAt": None, "completedByUserId": None}
            encoded = client.api.identity.encrypt_event(
                json.dumps(item).encode(),
                b"k" * 32,
                pack="pack-a",
                event="existing-native-event",
                device=client.api.data["connection_id"],
                sequence=7,
                event_type="chore.upserted",
                epoch=1,
            )
            wire = {
                "eventId": "existing-native-event",
                "eventType": "chore.upserted",
                "deviceSequence": 7,
                "dataEpoch": 1,
                "keyEpoch": 1,
                "encryptedPayload": encode64(encoded.encode()),
            }
            row = {**native_frame(client, wire), "type": "SNAPSHOT_ROW", "snapshotKind": "EVENT_LOG_V1"}
            raw = json.dumps(row)
            boundary = {
                "snapshotKind": "EVENT_LOG_V1",
                "snapshotDigestAlgorithm": "SHA-256-JSONL",
                "snapshotDigest": hashlib.sha256((raw + "\n").encode()).hexdigest(),
                "dataEpoch": 1,
                "snapshotHeadSequence": 1,
                "rowCount": 1,
                "snapshotId": "existing-native-ledger",
            }
            await client._frame(json.dumps({"type": "SNAPSHOT_BEGIN", **boundary}))
            await client._frame(raw)
            await client._frame(json.dumps({"type": "SNAPSHOT_COMPLETE", **boundary}))
            await client._frame(
                json.dumps({"type": "SYNC_COMPLETE", "headSequence": 1, "lastSequence": 1, "hasMore": False})
            )
            assert client.state.chores["task-a"]["historyJson"] == item["historyJson"]
            assert client.state.device_sequence == 7 and client.state.data_epoch == 1
            assert client.api.data["pack_keys"] == original_keys and client.authority_mode == "legacy"
            assert saved[-1]["bootstrap_verified"] is True

    asyncio.run(scenario())


def test_old_v3_outbox_cannot_silently_switch_to_legacy_gateway():
    async def scenario():
        async with aiohttp.ClientSession() as session:
            client, _, _, _ = client_for(session)
            client.outbox = {"wire": {"eventId": "old-v3-event"}}
            with pytest.raises(UnsupportedSchema):
                await client._send_outbox()
            assert client.outbox["wire"]["eventId"] == "old-v3-event"
            assert client.api.metrics["http_requests"] == 0
            await client._save()
            cache = {"state": client.state.export()}
            with pytest.raises(UnsupportedSchema):
                PackClient(client.api, cache, client.persist, client.changed, client.auth_failed, client.create_task)

    asyncio.run(scenario())


def test_legacy_mode_or_epoch_change_holds_original_action_without_resetting_pack():
    async def scenario():
        async with aiohttp.ClientSession() as session:
            client, _, _, _ = client_for(session)
            client.outbox = {"wire": {"eventId": "saved-event"}, "authority_mode": "legacy"}
            client.state.chores["retained-task"] = {"id": "retained-task", "title": "Retain history"}
            hello = {
                "type": "HELLO",
                **metadata(),
                "packId": "pack-a",
                "userId": "user-a",
                "deviceId": client.api.data["connection_id"],
                "dataEpoch": 2,
                "nextDeviceSequence": 2,
            }
            with pytest.raises(UnsupportedSchema):
                await client._frame(json.dumps(hello))

            async def changed_metadata():
                return {"authorityMode": "v3", "protocolVersion": 3, "syncGeneration": 3, "dataEpoch": 2}

            client.api.metadata = changed_metadata
            assert await client._recover_handshake() is False
            assert client.outbox["wire"]["eventId"] == "saved-event"
            assert "retained-task" in client.state.chores and client.state.data_epoch == 1

    asyncio.run(scenario())


@pytest.mark.parametrize("new_mode", ["legacy", "v3"])
def test_restart_with_new_epoch_preserves_saved_legacy_projection_and_outbox(new_mode):
    async def scenario():
        async with aiohttp.ClientSession() as session:
            client, saved, _, _ = client_for(session)
            client.outbox = {
                "wire": {"eventId": "saved-event", "encryptedPayload": "saved-ciphertext"},
                "authority_mode": "legacy",
            }
            client.state.chores["retained-task"] = {"id": "retained-task", "title": "Retain history"}
            await client._save()
            cache = saved[-1]
            before = deepcopy(cache)
            client.api.data.update(authority_mode=new_mode, data_epoch=2)
            with pytest.raises(UnsupportedSchema):
                PackClient(client.api, cache, client.persist, client.changed, client.auth_failed, client.create_task)
            assert cache == before and saved == [before]
            assert cache["outbox"]["wire"]["encryptedPayload"] == "saved-ciphertext"
            assert cache["state"]["data_epoch"] == 1 and "retained-task" in cache["state"]["chores"]
            assert client.api.data["pack_keys"] == {"1": encode64(b"k" * 32)}

    asyncio.run(scenario())


@pytest.mark.parametrize("code", ["home_assistant_connection_revoked", "home_assistant_pro_required"])
def test_legacy_command_revocation_and_current_premium_clear_sensitive_cache(code):
    async def scenario():
        async def handler(request):
            return web.json_response({"error": {"code": code}}, status=403)

        async with server(handler) as origin, aiohttp.ClientSession() as session:
            client, saved, denied, _ = client_for(session, origin)
            client.locations["user-a"] = {"latitude": 1}
            with pytest.raises(PackInApiError):
                await client._mutate("chore.upserted", payload())
            assert client.status == "reauth_required" and denied == [code]
            assert client.outbox is None and not client.keys() and not client.locations
            assert saved[-1]["state"]["chores"] == {}

    asyncio.run(scenario())
