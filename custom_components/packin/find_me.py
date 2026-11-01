"""Consented, ephemeral GPS projection. Coordinates are never persisted here."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import math
from typing import Any

from .crypto import CryptoError, decrypt_event
from .protocol import MissingKey


@dataclass(frozen=True, repr=False)
class MemberLocation:
    user_id: str
    latitude: float
    longitude: float
    accuracy: float
    observed_at: datetime
    synchronized_at: datetime

    def age_seconds(self, now: datetime) -> float:
        return max(0, (now - self.observed_at).total_seconds())


def _instant(value: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise CryptoError("Invalid location timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise CryptoError("Location timestamp must include a time zone")
    return parsed.astimezone(timezone.utc)


def decode_locations(
    rows: list[dict[str, Any]], pack_id: str, keys: dict[int, bytes], consented: set[str], now: datetime
) -> dict[str, MemberLocation]:
    if len(rows) > 100 or now.tzinfo is None:
        raise CryptoError("Invalid location batch")
    result: dict[str, MemberLocation] = {}
    for row in rows:
        user_id = row.get("user_id")
        if user_id not in consented:
            # Consent is enforced on the server and again in the HA projection.
            continue
        epoch = row.get("key_epoch")
        if type(epoch) is not int or epoch < 1:
            raise CryptoError("Invalid location key epoch")
        if epoch not in keys:
            raise MissingKey(epoch)
        clear = decrypt_event(
            row.get("encrypted_payload"),
            keys[epoch],
            row.get("signing_public_key"),
            pack=pack_id,
            event=row.get("event_id"),
            device=row.get("device_id"),
            sequence=row.get("device_sequence"),
            event_type="find_me.location",
            epoch=epoch,
        )
        payload = json.loads(clear)
        if (
            not isinstance(payload, dict)
            or type(payload.get("schemaVersion")) is not int
            or payload["schemaVersion"] != 1
        ):
            raise CryptoError("Unsupported location payload")
        observed = _instant(payload.get("observedAt"))
        if observed != _instant(row.get("observed_at")):
            raise CryptoError("Location observation metadata does not match its signature")
        latitude, longitude, accuracy = (payload.get(name) for name in ("latitude", "longitude", "accuracyMeters"))
        if any(
            type(value) not in (int, float) or not math.isfinite(value) for value in (latitude, longitude, accuracy)
        ):
            raise CryptoError("Invalid location coordinates or accuracy")
        if not -90 <= latitude <= 90 or not -180 <= longitude <= 180 or not 0 <= accuracy <= 1_000_000:
            raise CryptoError("Location coordinates or accuracy are out of range")
        if (observed - now).total_seconds() > 300:
            raise CryptoError("Location observation is in the future")
        location = MemberLocation(user_id, latitude, longitude, accuracy, observed, now)
        if user_id not in result or location.observed_at > result[user_id].observed_at:
            result[user_id] = location
    return result
