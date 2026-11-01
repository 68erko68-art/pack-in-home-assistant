"""Explicit batched Find Me refresh, with the same server/client cooldown."""

from homeassistant.components.button import ButtonEntity
from homeassistant.exceptions import HomeAssistantError

from .api import PackInApiError
from .entity import PackEntity

PARALLEL_UPDATES = 0


async def async_setup_entry(hass, entry, async_add_entities) -> None:
    if "locations:read" in entry.runtime_data.client.api.data.get("scopes", []):
        async_add_entities([PackLocationRefresh(entry.runtime_data)])


class PackLocationRefresh(PackEntity, ButtonEntity):
    _attr_icon = "mdi:crosshairs-gps"

    def __init__(self, coordinator) -> None:
        super().__init__(coordinator, "refresh_locations", "Refresh locations")

    async def async_press(self) -> None:
        try:
            await self.client.refresh_locations()
        except PackInApiError as exc:
            raise HomeAssistantError("Pack-In could not retrieve locations: " + exc.code) from None
