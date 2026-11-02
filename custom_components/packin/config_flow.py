"""Password-free phone approval; no Firebase tokens or YAML for users."""

from __future__ import annotations

import time
import hashlib
from typing import Any

import probatio

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult, OptionsFlow
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import PackInApi, PackInApiError, new_pairing
from .const import DOMAIN, CONF_LOCATION_INTERVAL, LOCATION_INTERVALS, DEFAULT_LOCATION_INTERVAL


class PackInFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self) -> None:
        self._pairing = None
        self._api = None
        self._next_check = 0.0

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return PackInOptions()

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors = {}
        if user_input is not None:
            scopes = ["tasks:read", "groceries:read", "calendar:read", "members:read"]
            if not user_input.get("read_only", False):
                scopes += ["tasks:write", "groceries:write"]
            if user_input.get("find_me", True):
                scopes += ["locations:read"]
            self._pairing = await self.hass.async_add_executor_job(new_pairing, user_input["name"], scopes)
            self._api = PackInApi(async_get_clientsession(self.hass), self._pairing.identity)
            try:
                await self._api.start_pairing(self._pairing)
                return await self.async_step_pair()
            except PackInApiError as exc:
                errors["base"] = "unavailable" if exc.status != 429 else "rate_limited"
        return self.async_show_form(
            step_id="user",
            data_schema=probatio.Schema(
                {
                    probatio.Required("name", default="Home Assistant"): probatio.All(
                        str, probatio.Length(min=1, max=80)
                    ),
                    probatio.Optional("read_only", default=False): bool,
                    probatio.Optional("find_me", default=True): bool,
                }
            ),
            errors=errors,
        )

    async def async_step_pair(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if self._pairing is None or self._api is None:
            return await self.async_step_user()
        if time.time() * 1000 >= self._pairing.expires_at:
            return self.async_abort(reason="pairing_expired")
        errors = {}
        if user_input is not None:
            if time.monotonic() < self._next_check:
                errors["base"] = "rate_limited"
            else:
                self._next_check = time.monotonic() + 5
                try:
                    state = await self._api.pairing_status(self._pairing)
                    if state == "denied" or (state == "claimed" and self._pairing.claim is None):
                        return self.async_abort(reason="pairing_denied")
                    if state == "pending":
                        errors["base"] = "approval_pending"
                    else:
                        data = await self._api.claim_pairing(self._pairing)
                        await self.async_set_unique_id(data["pack_id"])
                        if self.source in {"reauth", "reconfigure"}:
                            entry = (
                                self._get_reauth_entry() if self.source == "reauth" else self._get_reconfigure_entry()
                            )
                            if data["pack_id"] != entry.unique_id:
                                await self._api.disconnect()
                                return self.async_abort(reason="wrong_pack")
                            return self.async_update_reload_and_abort(entry, data_updates=data)
                        existing = self.hass.config_entries.async_entry_for_domain_unique_id(DOMAIN, data["pack_id"])
                        if existing is not None:
                            await self._api.disconnect()
                            return self.async_abort(reason="already_configured")
                        return self.async_create_entry(title=data.get("pack_name", "Pack-In"), data=data)
                except PackInApiError as exc:
                    errors["base"] = (
                        "rate_limited"
                        if exc.status == 429
                        else "waiting_for_keys"
                        if exc.code == "current_pack_key_required"
                        else "unavailable"
                    )
        return self.async_show_form(
            step_id="pair",
            data_schema=probatio.Schema({}),
            errors=errors,
            description_placeholders={
                "code": self._pairing.user_code,
                "fingerprint": hashlib.sha256(
                    (
                        self._pairing.identity.public["encryptionPublicKey"]
                        + "|"
                        + self._pairing.identity.public["signingPublicKey"]
                    ).encode()
                ).hexdigest()[:24],
            },
        )

    async def async_step_reauth(self, entry_data: dict[str, Any]) -> ConfigFlowResult:
        return await self.async_step_user()

    async def async_step_reconfigure(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        return await self.async_step_user(user_input)


class PackInOptions(OptionsFlow):
    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)
        return self.async_show_form(
            step_id="init",
            data_schema=probatio.Schema(
                {
                    probatio.Required(
                        CONF_LOCATION_INTERVAL,
                        default=self.config_entry.options.get(CONF_LOCATION_INTERVAL, DEFAULT_LOCATION_INTERVAL),
                    ): probatio.In(LOCATION_INTERVALS)
                }
            ),
        )
