"""Shared, stable Pack entity identity."""

from __future__ import annotations

from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import PackCoordinator


class PackEntity(CoordinatorEntity[PackCoordinator]):
    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(self, coordinator: PackCoordinator, key: str, name: str) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = coordinator.client.state.pack_id + "_" + key
        self._attr_name = name

    @property
    def client(self):
        return self.coordinator.client

    @property
    def available(self) -> bool:
        return self.client.available

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={(DOMAIN, self.client.state.pack_id)},
            manufacturer="Pack-In",
            model="Home Assistant connection",
            name=self.client.api.data.get("pack_name", "Pack-In"),
        )
