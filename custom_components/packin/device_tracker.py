"""Consenting members on Home Assistant's native map, without location history."""

from __future__ import annotations

from datetime import datetime, timezone

from homeassistant.components.device_tracker import TrackerEntity, SourceType
from homeassistant.core import callback

from .entity import PackEntity

PARALLEL_UPDATES = 0


async def async_setup_entry(hass, entry, async_add_entities) -> None:
    coordinator = entry.runtime_data
    if "locations:read" not in coordinator.client.api.data.get("scopes", []):
        return
    known = set()

    @callback
    def add_members() -> None:
        additions = []
        for member in coordinator.client.api.data.get("members", []):
            identifier = member.get("userId")
            if identifier and identifier not in known:
                known.add(identifier)
                additions.append(PackTracker(coordinator, identifier, member.get("displayName") or "Pack member"))
        if additions:
            async_add_entities(additions)

    add_members()
    entry.async_on_unload(coordinator.async_add_listener(add_members))


class PackTracker(PackEntity, TrackerEntity):
    _attr_source_type = SourceType.GPS
    _attr_icon = "mdi:map-marker-account"

    def __init__(self, coordinator, user_id: str, name: str) -> None:
        super().__init__(coordinator, "location_" + user_id, name + " location")
        self.user_id = user_id

    @property
    def available(self) -> bool:
        location = self.client.locations.get(self.user_id)
        consent = any(
            m.get("userId") == self.user_id and m.get("locationConsent")
            for m in self.client.api.data.get("members", [])
        )
        return bool(
            self.client.available
            and self.client.location_interval
            and consent
            and location
            and location.age_seconds(datetime.now(timezone.utc)) <= max(900, self.client.location_interval * 3)
        )

    @property
    def latitude(self) -> float | None:
        return self.client.locations[self.user_id].latitude if self.available else None

    @property
    def longitude(self) -> float | None:
        return self.client.locations[self.user_id].longitude if self.available else None

    @property
    def location_accuracy(self) -> int:
        return round(self.client.locations[self.user_id].accuracy) if self.available else 0

    @property
    def extra_state_attributes(self) -> dict:
        location = self.client.locations.get(self.user_id)
        return {
            "observed_at": location.observed_at.isoformat() if location and self.available else None,
            "synchronized_at": location.synchronized_at.isoformat() if location and self.available else None,
            "location_age_seconds": round(location.age_seconds(datetime.now(timezone.utc)))
            if location and self.available
            else None,
        }
