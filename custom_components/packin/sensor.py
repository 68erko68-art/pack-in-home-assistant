"""Optional local synchronization and member status sensors."""

from __future__ import annotations


from homeassistant.components.sensor import SensorEntity, SensorDeviceClass
from homeassistant.const import EntityCategory

from .entity import PackEntity

PARALLEL_UPDATES = 0


async def async_setup_entry(hass, entry, async_add_entities) -> None:
    coordinator = entry.runtime_data
    async_add_entities(
        [
            PackStatus(coordinator, key, name)
            for key, name in [
                ("synchronization", "Synchronization"),
                ("last_event_sync", "Last event synchronization"),
                ("last_location_fetch", "Last location retrieval"),
                ("pending", "Pending actions"),
                ("members", "Members"),
            ]
        ]
    )


class PackStatus(PackEntity, SensorEntity):
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator, key, name) -> None:
        super().__init__(coordinator, key, name)
        self.key = key
        self._attr_entity_registry_enabled_default = key == "synchronization"
        if key in {"last_event_sync", "last_location_fetch"}:
            self._attr_device_class = SensorDeviceClass.TIMESTAMP
        self._attr_icon = "mdi:sync" if key == "synchronization" else "mdi:information-outline"

    @property
    def available(self) -> bool:
        return True

    @property
    def native_value(self):
        if self.key == "synchronization":
            return self.client.status
        if self.key == "last_event_sync":
            return self.client.last_sync
        if self.key == "last_location_fetch":
            return self.client.last_location_fetch
        if self.key == "pending":
            return int(self.client.outbox is not None)
        return len(self.client.api.data.get("members", [])) if not self.client._blocked else 0

    @property
    def extra_state_attributes(self):
        if self.key == "synchronization":
            return {"error_category": self.client.error}
        if self.key == "members" and not self.client._blocked:
            # Deliberately no keys, contact details, avatars or coordinates.
            return {
                "members": [
                    {
                        "name": m.get("displayName") or "Pack member",
                        "member_id": m["userId"],
                        "role": m.get("role"),
                        "location_sharing": bool(m.get("locationConsent")),
                    }
                    for m in self.client.api.data.get("members", [])
                ]
            }
        return None
