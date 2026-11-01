"""Allowlisted diagnostics: no credentials, identities, payloads or coordinates."""


async def async_get_config_entry_diagnostics(hass, entry) -> dict:
    if not hasattr(entry, "runtime_data"):
        return {"status": "not_loaded"}
    return entry.runtime_data.client.diagnostics()
