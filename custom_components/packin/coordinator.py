"""Push coordinator and encrypted local cache; no periodic Pack downloads."""

from __future__ import annotations

from datetime import timedelta
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .client import PackClient
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


class PackCoordinator(DataUpdateCoordinator[int]):
    def __init__(self, hass: HomeAssistant, entry: ConfigEntry, store: Store) -> None:
        super().__init__(hass, _LOGGER, config_entry=entry, name=DOMAIN, update_interval=None, always_update=True)
        self.entry = entry
        self.store = store
        self.client: PackClient
        self.options = dict(entry.options)
        self._revision = 0

    @callback
    def notify(self) -> None:
        self._revision += 1
        self.async_set_updated_data(self._revision)

    @callback
    def start_age_clock(self) -> None:
        # Local availability/age recalculation only. No HTTP and no Pack polling.
        self.entry.async_on_unload(async_track_time_interval(self.hass, lambda _: self.notify(), timedelta(seconds=60)))

    @callback
    def authentication_failed(self, code: str) -> None:
        self.entry.async_start_reauth(self.hass)
