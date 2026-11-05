"""Native HA config-entry/entity lifecycle; only the remote transport is mocked."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch
import secrets

import pytest

from homeassistant.components.todo import TodoItem, TodoItemStatus
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers import entity_registry
from homeassistant.helpers.storage import Store
from pytest_homeassistant.common import MockConfigEntry

from custom_components.packin.api import SCOPES
from custom_components.packin.crypto import DeviceIdentity, encode64, seal_cache
from custom_components.packin.protocol import LEGACY_COMMAND_MODE, LEGACY_GATEWAY_CAPABILITY
from custom_components.packin.state import PackState

pytestmark = pytest.mark.usefixtures("enable_custom_integrations")


def config():
    return {
        "identity": DeviceIdentity.generate().export(),
        "connection_id": "ha_" + "a" * 32,
        "pack_id": "test-pack",
        "pack_name": "Test family",
        "user_id": "test-user",
        "role": "member",
        "scopes": SCOPES,
        "data_epoch": 1,
        "authority_mode": "v3",
        "key_epoch": 1,
        "pack_keys": {"1": encode64(b"k" * 32)},
        "access_token": encode64(secrets.token_bytes(32)),
        "refresh_token": encode64(secrets.token_bytes(32)),
        "access_expires_at_ms": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp() * 1000),
        "cache_key": encode64(secrets.token_bytes(32)),
        "members": [{"userId": "test-user", "displayName": "Alex", "role": "member", "locationConsent": False}],
    }


async def setup_entry(hass, cache_connection_id=None, *, authority_mode="v3"):
    data = config()
    data["authority_mode"] = authority_mode
    if authority_mode == "legacy":
        data.update(
            command_mode=LEGACY_COMMAND_MODE,
            capabilities=[LEGACY_GATEWAY_CAPABILITY],
            protocol_version=1,
            sync_generation=1,
        )
    entry = MockConfigEntry(domain="packin", unique_id="test-pack", title="Test family", data=data)
    entry.add_to_hass(hass)
    state = PackState("test-pack", "test-user", "member")
    state.chores["task-a"] = {
        "id": "task-a",
        "title": "Feed the dog",
        "createdByUserId": "test-user",
        "assignmentMode": "UNASSIGNED",
        "historyJson": "[]",
        "dueAt": None,
        "completedAt": None,
    }
    state.groceries["milk"] = {
        "id": "milk",
        "name": "Milk",
        "quantity": "2 bottles",
        "groupName": "Dairy",
        "checked": False,
        "historyJson": "[]",
    }
    from custom_components.packin.crypto import decode64

    cache = {"state": state.export()}
    if authority_mode == "legacy":
        cache["authority_mode"] = authority_mode
    sealed = seal_cache(cache, decode64(data["cache_key"]), "test-pack")
    await Store(hass, 1, "packin." + entry.entry_id, private=True).async_save(
        {"sealed": sealed, "connection_id": cache_connection_id or data["connection_id"]}
    )

    async def metadata(api):
        return dict(api.data)

    with (
        patch("custom_components.packin.api.PackInApi.metadata", metadata),
        patch("custom_components.packin.client.PackClient.start"),
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
    entry.runtime_data.client.log.synced = True
    entry.runtime_data.client.status = "connected"
    entry.runtime_data.notify()
    await hass.async_block_till_done()
    return entry


@pytest.mark.parametrize("authority_mode", ["v3", "legacy"])
async def test_native_entities_load_and_unload_without_network(hass, authority_mode):
    entry = await setup_entry(hass, authority_mode=authority_mode)
    assert entry.runtime_data.client.authority_mode == authority_mode
    assert "milk" in entry.runtime_data.client.state.groceries
    assert len([x for x in hass.states.async_all("todo")]) == 2  # Optional whole-Pack list disabled.
    assert len(hass.states.async_all("calendar")) == 1
    assert len(hass.states.async_all("device_tracker")) == 1
    assert next(iter(hass.states.async_all("device_tracker"))).state == "unavailable"
    assert await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()
    assert not hass.config_entries.async_loaded_entries("packin")


async def test_todo_native_service_preserves_quantity_and_uses_single_shared_client(hass):
    entry = await setup_entry(hass)
    client = entry.runtime_data.client
    todos = hass.data["todo"].entities
    groceries = next(x for x in todos if x.unique_id == "test-pack_groceries")
    chores = next(x for x in todos if x.unique_id == "test-pack_chores")
    assert groceries.client is chores.client is client
    assert "2 bottles" in groceries.todo_items[0].description
    with patch.object(client, "update_grocery", new_callable=AsyncMock) as update:
        await groceries.async_update_todo_item(TodoItem(uid="milk", summary="Milk", status=TodoItemStatus.COMPLETED))
        update.assert_awaited_once_with("milk", {"checked": True})
    await hass.config_entries.async_unload(entry.entry_id)


async def test_dashboard_property_reads_and_calendar_reads_make_no_http(hass):
    entry = await setup_entry(hass)
    client = entry.runtime_data.client
    with patch.object(client.api, "request", new_callable=AsyncMock) as request:
        for _ in range(20):
            for entity in hass.data["todo"].entities:
                _ = entity.todo_items
                _ = entity.available
            for entity in hass.data["device_tracker"].entities:
                assert entity.latitude is None and entity.longitude is None
            for entity in hass.data["calendar"].entities:
                events = await entity.async_get_events(
                    hass, datetime.now(timezone.utc), datetime.now(timezone.utc) + timedelta(days=7)
                )
                assert events == []
        request.assert_not_awaited()
    await hass.config_entries.async_unload(entry.entry_id)


async def test_diagnostics_never_export_identity_tokens_content_or_coordinates(hass):
    entry = await setup_entry(hass)
    from custom_components.packin.diagnostics import async_get_config_entry_diagnostics
    import json

    diagnostic = json.dumps(await async_get_config_entry_diagnostics(hass, entry))
    for private in [
        entry.data["access_token"],
        entry.data["refresh_token"],
        "Feed the dog",
        "test-user",
        "test-pack",
        "latitude",
    ]:
        assert private not in diagnostic
    await hass.config_entries.async_unload(entry.entry_id)


async def test_config_flow_phone_code_and_claim(hass):
    data = config()

    async def start(api, pairing):
        pairing.expires_at = int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp() * 1000)

    with (
        patch("custom_components.packin.api.PackInApi.start_pairing", start),
        patch("custom_components.packin.api.PackInApi.pairing_status", new=AsyncMock(return_value="approved")),
        patch("custom_components.packin.api.PackInApi.claim_pairing", new=AsyncMock(return_value=data)),
        patch("custom_components.packin.async_setup_entry", new=AsyncMock(return_value=True)),
    ):
        result = await hass.config_entries.flow.async_init("packin", context={"source": "user"})
        assert result["type"] == FlowResultType.FORM and result["step_id"] == "user"
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"name": "Family home", "read_only": False, "find_me": True}
        )
        assert result["step_id"] == "pair"
        assert len(result["description_placeholders"]["code"]) == 9
        result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
        assert result["type"] == FlowResultType.CREATE_ENTRY
        assert result["result"].unique_id == "test-pack"


async def test_options_interval_zero_and_ten_minutes(hass):
    entry = await setup_entry(hass)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    assert result["type"] == FlowResultType.FORM
    with patch.object(hass.config_entries, "async_reload", new_callable=AsyncMock) as reload_entry:
        result = await hass.config_entries.options.async_configure(result["flow_id"], {"location_interval": 0})
        await hass.async_block_till_done()
        reload_entry.assert_awaited_once_with(entry.entry_id)
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert entry.options["location_interval"] == 0
    await hass.config_entries.async_unload(entry.entry_id)


async def test_new_connection_does_not_restore_or_replay_previous_identity_cache(hass):
    entry = await setup_entry(hass, cache_connection_id="ha_" + "b" * 32)
    client = entry.runtime_data.client
    assert not client.state.chores
    assert client.outbox is None
    await hass.config_entries.async_unload(entry.entry_id)


async def test_flow_recovers_lost_claim_response_using_same_claim_intent(hass, freezer):
    from custom_components.packin.api import PackInApiError

    data = config()
    calls = []

    async def start(api, pairing):
        pairing.expires_at = int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp() * 1000)

    async def claim(api, pairing):
        if pairing.claim is None:
            pairing.claim = {"claimId": "synthetic-claim"}
        calls.append(deepcopy(pairing.claim))
        if len(calls) == 1:
            raise PackInApiError("network_unavailable")
        return data

    with (
        patch("custom_components.packin.api.PackInApi.start_pairing", start),
        patch(
            "custom_components.packin.api.PackInApi.pairing_status", new=AsyncMock(side_effect=["approved", "claimed"])
        ),
        patch("custom_components.packin.api.PackInApi.claim_pairing", claim),
        patch("custom_components.packin.async_setup_entry", new=AsyncMock(return_value=True)),
    ):
        result = await hass.config_entries.flow.async_init("packin", context={"source": "user"})
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"name": "Home", "read_only": False, "find_me": True}
        )
        result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
        assert result["errors"] == {"base": "unavailable"}
        freezer.tick(timedelta(seconds=6))
        result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
        assert result["type"] == FlowResultType.CREATE_ENTRY
        assert calls[0] == calls[1]


@pytest.mark.parametrize("authority_mode", ["v3", "legacy"])
async def test_native_reload_preserves_pairing_cache_pending_actions_and_entity_identity(hass, authority_mode):
    """Exercise real HA reload and sealed storage while background transport stays stopped."""
    entry = await setup_entry(hass, authority_mode=authority_mode)
    original_client = entry.runtime_data.client
    original_entry_id = entry.entry_id
    original_unique_id = entry.unique_id
    original_data = deepcopy(dict(entry.data))
    original_identity = original_client.api.identity.export()
    original_keys = original_client.keys()
    registry = entity_registry.async_get(hass)

    def registered_entities():
        return {
            (item.entity_id, item.unique_id, item.device_id)
            for item in entity_registry.async_entries_for_config_entry(registry, original_entry_id)
        }

    original_registry = registered_entities()
    assert original_registry
    registered_ids = {entity_id for entity_id, _, _ in original_registry}
    original_loaded_ids = {state.entity_id for state in hass.states.async_all()} & registered_ids
    assert original_loaded_ids

    original_client.state.last_sequence = 12
    original_client.device_sequence = 7
    original_client._needs_snapshot = False
    # These envelopes are opaque to persistence; the transport must not replay them during reload.
    original_client.outbox = {"wire": {"type": "MUTATE", "eventId": "pending-reload-action"}}
    original_client.workflow = {
        "parent": "task-a",
        "due": 1793574000000,
        "recurrence": "daily",
        "now": 1793574000000,
        "phase": "normalize",
    }
    expected_state = deepcopy(original_client.state.export())
    expected_outbox = deepcopy(original_client.outbox)
    expected_workflow = deepcopy(original_client.workflow)
    await original_client._save()

    metadata_calls = []

    async def metadata(api):
        metadata_calls.append(deepcopy(api.data))
        return dict(api.data)

    try:
        with (
            patch("custom_components.packin.api.PackInApi.metadata", metadata),
            patch("custom_components.packin.client.PackClient.start") as start,
            patch("custom_components.packin.api.PackInApi.start_pairing", new_callable=AsyncMock) as pair,
            patch("custom_components.packin.api.PackInApi.claim_pairing", new_callable=AsyncMock) as claim,
        ):
            assert await hass.config_entries.async_reload(original_entry_id)
            await hass.async_block_till_done()
            start.assert_called_once()
            pair.assert_not_awaited()
            claim.assert_not_awaited()

        assert hass.config_entries.async_get_entry(original_entry_id) is entry
        assert entry.unique_id == original_unique_id
        assert dict(entry.data) == original_data
        assert metadata_calls == [original_data]
        reloaded = entry.runtime_data.client
        assert reloaded is not original_client
        assert original_client._stopping
        assert reloaded.authority_mode == authority_mode
        assert reloaded.api.identity.export() == original_identity
        assert reloaded.keys() == original_keys
        assert reloaded.state.export() == expected_state
        assert reloaded.device_sequence == 7
        assert not reloaded._needs_snapshot
        assert reloaded.outbox == expected_outbox
        assert reloaded.workflow == expected_workflow
        assert registered_entities() == original_registry
        assert {state.entity_id for state in hass.states.async_all()} & registered_ids == original_loaded_ids
        assert len(list(hass.config_entries.async_loaded_entries("packin"))) == 1
    finally:
        await hass.config_entries.async_unload(entry.entry_id)
        await hass.async_block_till_done()
