"""Read-only native Pack-In calendar, including canonical recurrence rules."""

from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import datetime, timedelta, timezone

from homeassistant.components.calendar import CalendarEntity, CalendarEvent
from homeassistant.core import callback
from homeassistant.exceptions import HomeAssistantError

from .calendar_model import expand_events, CalendarModelError
from .entity import PackEntity

PARALLEL_UPDATES = 0


async def async_setup_entry(hass, entry, async_add_entities) -> None:
    if "calendar:read" in entry.runtime_data.client.api.data.get("scopes", []):
        async_add_entities([PackCalendar(entry.runtime_data)])


class PackCalendar(PackEntity, CalendarEntity):
    _attr_icon = "mdi:calendar-heart"
    _attr_supported_features = 0
    _attr_initial_color = "#d8b661"

    def __init__(self, coordinator) -> None:
        super().__init__(coordinator, "calendar", "Calendar")
        self._current = None
        self._projection_task = None
        self._projection_revision = 0

    @property
    def event(self) -> CalendarEvent | None:
        return self._current

    async def async_get_events(self, hass, start_date, end_date) -> list[CalendarEvent]:
        records, overrides = deepcopy(self.client.state.calendar), deepcopy(self.client.state.calendar_overrides)
        try:
            events = await hass.async_add_executor_job(expand_events, records, overrides, start_date, end_date)
        except (CalendarModelError, ValueError, KeyError):
            raise HomeAssistantError("A Pack-In calendar event uses unsupported dates or recurrence") from None
        return [
            CalendarEvent(start=x.start, end=x.end, summary=x.summary, description=x.description, uid=x.uid)
            for x in events
        ]

    async def _project_next(self) -> None:
        while True:
            revision = self._projection_revision
            now = datetime.now(timezone.utc)
            try:
                events = await self.async_get_events(self.hass, now - timedelta(days=1), now + timedelta(days=366))
                current = next((x for x in events if x.end_datetime_local > now), None)
            except HomeAssistantError:
                current = None
            if revision != self._projection_revision:
                continue
            self._current = current
            if self.hass is not None:
                # CalendarEntity notifies its event subscribers from this supported write path.
                self.async_write_ha_state()
            return

    @callback
    def _handle_coordinator_update(self) -> None:
        self._projection_revision += 1
        if self._projection_task is None or self._projection_task.done():
            self._projection_task = self.coordinator.entry.async_create_background_task(
                self.hass, self._project_next(), "Pack-In local calendar projection"
            )
        super()._handle_coordinator_update()

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self._handle_coordinator_update()

    async def async_will_remove_from_hass(self) -> None:
        if self._projection_task is not None:
            self._projection_task.cancel()
            await asyncio.gather(self._projection_task, return_exceptions=True)
        await super().async_will_remove_from_hass()
