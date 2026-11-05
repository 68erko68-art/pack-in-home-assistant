"""Pack-In: encrypted tasks, groceries, calendar and consenting GPS trackers."""

from __future__ import annotations

from cryptography.exceptions import InvalidTag
import logging

import probatio

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryError, ConfigEntryNotReady, HomeAssistantError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession, async_create_clientsession
from homeassistant.helpers.storage import Store

from .api import PackInApi, PackInApiError, deny_redirect
from .client import PackClient, ActionPending, Conflict
from .const import DOMAIN, PLATFORMS, CONF_LOCATION_INTERVAL, DEFAULT_LOCATION_INTERVAL
from .coordinator import PackCoordinator
from .crypto import DeviceIdentity, decode64, open_cache, seal_cache
from .state import PermissionDenied, ProjectionError

_LOGGER = logging.getLogger(__name__)
CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    async def action(call: ServiceCall) -> None:
        entry = hass.config_entries.async_get_entry(call.data["config_entry_id"])
        if entry is None or entry.domain != DOMAIN or not hasattr(entry, "runtime_data"):
            raise HomeAssistantError("Choose a loaded Pack-In connection")
        client = entry.runtime_data.client
        try:
            if call.service == "assign_task":
                await client.assign_task(call.data["item_id"], call.data["member_ids"])
            elif call.service == "set_quantity":
                await client.update_grocery(call.data["item_id"], {"quantity": call.data["quantity"]})
            elif call.service == "add_grocery":
                await client.add_grocery(call.data["name"], call.data.get("quantity"), call.data.get("list_id"))
        except (ActionPending, Conflict, PermissionDenied, ProjectionError, PackInApiError) as exc:
            raise HomeAssistantError(str(exc)) from None

    base = {probatio.Required("config_entry_id"): str}
    hass.services.async_register(
        DOMAIN,
        "assign_task",
        action,
        schema=probatio.Schema(
            {
                **base,
                probatio.Required("item_id"): str,
                probatio.Required("member_ids"): probatio.All([str], probatio.Length(max=100)),
            }
        ),
    )
    hass.services.async_register(
        DOMAIN,
        "set_quantity",
        action,
        schema=probatio.Schema(
            {
                **base,
                probatio.Required("item_id"): str,
                probatio.Required("quantity"): probatio.Any(None, probatio.All(str, probatio.Length(max=100))),
            }
        ),
    )
    hass.services.async_register(
        DOMAIN,
        "add_grocery",
        action,
        schema=probatio.Schema(
            {
                **base,
                probatio.Required("name"): probatio.All(str, probatio.Length(min=1, max=500)),
                probatio.Optional("quantity"): probatio.All(str, probatio.Length(max=100)),
                probatio.Optional("list_id"): str,
            }
        ),
    )
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    store = Store(hass, 1, DOMAIN + "." + entry.entry_id, private=True)
    if entry.data.get("reauth_reason"):
        await store.async_remove()
        raise ConfigEntryAuthFailed("Reconnect Pack-In in Devices & services")
    identity = await hass.async_add_executor_job(DeviceIdentity.restore, dict(entry.data["identity"]))

    async def checkpoint(data: dict) -> None:
        hass.config_entries.async_update_entry(entry, data=data)

    api = PackInApi(
        async_create_clientsession(hass, middlewares=(deny_redirect,)), identity, dict(entry.data), checkpoint
    )
    try:
        await api.metadata()  # One membership/entitlement check on setup, shared by every entity.
    except PackInApiError as exc:
        if exc.auth_failed:
            await store.async_remove()
            clean = dict(entry.data)
            clean["pack_keys"] = {}
            clean["members"] = []
            clean["reauth_reason"] = exc.code
            hass.config_entries.async_update_entry(entry, data=clean)
            raise ConfigEntryAuthFailed("Reconnect Pack-In to renew permission") from None
        if exc.code == "home_assistant_sync_upgrade_required":
            raise ConfigEntryError("This Pack needs a supported synchronization upgrade in Pack-In") from None
        raise ConfigEntryNotReady("Pack-In is temporarily unavailable") from None

    if api.data.get("authority_mode") not in {"v3", "legacy"}:
        raise ConfigEntryError("This Pack needs a supported synchronization upgrade in Pack-In")

    encrypted = await store.async_load()
    cache = {}
    if encrypted and encrypted.get("connection_id") != api.data["connection_id"]:
        # Re-pairing installs a new identity and cache key. Never replay an old
        # connection's pending actions under the new trusted identity.
        await store.async_remove()
        encrypted = None
    if encrypted and isinstance(encrypted.get("sealed"), str):
        try:
            cache = await hass.async_add_executor_job(
                open_cache, encrypted["sealed"], decode64(api.data["cache_key"], 32), api.data["pack_id"]
            )
        except (ValueError, KeyError, InvalidTag):
            # An unreadable cache is not permission to send queued work again.
            raise ConfigEntryNotReady(
                "Pack-In local cache could not be verified; restore its matching backup"
            ) from None

    coordinator = PackCoordinator(hass, entry, store)

    async def persist(value: dict) -> None:
        sealed = await hass.async_add_executor_job(
            seal_cache, value, decode64(api.data["cache_key"], 32), api.data["pack_id"]
        )
        await store.async_save({"sealed": sealed, "connection_id": api.data["connection_id"]})

    client = PackClient(
        api,
        cache,
        persist,
        coordinator.notify,
        coordinator.authentication_failed,
        lambda coro, name: entry.async_create_background_task(hass, coro, name),
        int(entry.options.get(CONF_LOCATION_INTERVAL, DEFAULT_LOCATION_INTERVAL)) * 60,
    )
    coordinator.client = client
    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    coordinator.start_age_clock()
    entry.async_on_unload(entry.add_update_listener(async_options_updated))
    client.start()
    coordinator.notify()
    return True


async def async_options_updated(hass: HomeAssistant, entry: ConfigEntry) -> None:
    if hasattr(entry, "runtime_data") and dict(entry.options) != entry.runtime_data.options:
        await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    coordinator = entry.runtime_data
    await coordinator.client.stop()
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def async_remove_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    try:
        identity = await hass.async_add_executor_job(DeviceIdentity.restore, dict(entry.data["identity"]))
        api = PackInApi(async_get_clientsession(hass), identity, dict(entry.data))
        await api.disconnect()
    except (PackInApiError, ValueError, KeyError):
        _LOGGER.warning("Pack-In remote disconnection was unavailable; revoke this connection in the phone app")
    await Store(hass, 1, DOMAIN + "." + entry.entry_id, private=True).async_remove()
