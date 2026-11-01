"""Canonical Pack Sync V3 identities and authenticated event decoding."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any

from .crypto import CryptoError, decode64, decrypt_event

PROTOCOL_VERSION = 3
SYNC_GENERATION = 3
CAPABILITIES = [
    "CLIENT_MUTATION_RECONCILIATION_V1",
    "DEVICE_SEQUENCE_V1",
    "EVENT_LOG_SNAPSHOT_V1",
    "SNAPSHOT_DIGEST_V1",
    "UNSUPPORTED_SCHEMA_HOLD_V1",
    "SCOPED_EVENT_LOG_V1",
]
KNOWN_EVENTS = {
    "chore.upserted",
    "chore.removed",
    "grocery.item.upserted",
    "grocery.item.removed",
    "shopping.list.upserted",
    "shopping.list.removed",
    "shopping.pack.reference.updated",
    "calendar.event.upserted",
    "calendar.event.removed",
    "calendar.event.cancelled",
    "calendar.event.restored",
    "calendar.event.override.upserted",
    "calendar.event.series.split",
    "member.profile.upserted",
}
TYPES = {
    "chore": "chore",
    "grocery.item": "grocery-item",
    "shopping.list": "shopping-list",
    "calendar.event": "calendar-event",
}


class UnsupportedSchema(ValueError):
    """Keep the cursor before data this version cannot safely interpret."""


class MissingKey(ValueError):
    def __init__(self, epoch: int):
        self.epoch = epoch
        super().__init__("An authorized Pack key is required")


def opaque(value: str) -> str:
    return "v3_" + hashlib.sha256(value.encode()).hexdigest()[:48]


def descriptor(event_type: str, payload: dict[str, Any]) -> tuple[str, str, str]:
    if event_type.startswith("calendar.event.override."):
        kind = "calendar-override"
        logical = str(payload.get("seriesEventId", "")) + ":" + str(payload.get("occurrenceDate", ""))
    else:
        category = next((key for key in TYPES if event_type.startswith(key + ".")), None)
        if category is None:
            raise UnsupportedSchema("Unsupported Pack entity category")
        kind = TYPES[category]
        logical = payload.get("id")
    if not isinstance(logical, str) or not logical:
        raise UnsupportedSchema("A stable item identity is required")
    operation = (
        "DELETE" if event_type.endswith((".removed", ".deleted", ".cleared")) or payload.get("deleted") else "UPSERT"
    )
    return kind, opaque("entity:" + kind + ":" + logical), operation


@dataclass(frozen=True)
class DecodedEvent:
    event_type: str
    payload: dict[str, Any]
    actor: str
    accepted_ms: int
    entity_type: str
    entity_id: str
    entity_version: int


def decode_event(frame: dict[str, Any], pack_id: str, pack_keys: dict[int, bytes]) -> dict[str, Any]:
    if frame.get("packId") != pack_id:
        raise CryptoError("Event belongs to another Pack")
    if frame.get("protocolVersion") != PROTOCOL_VERSION or frame.get("syncGeneration") != SYNC_GENERATION:
        raise UnsupportedSchema("Install the current Pack-In integration")
    epoch = frame.get("keyEpoch")
    if type(epoch) is not int or epoch < 1:
        raise CryptoError("Invalid Pack key epoch")
    if epoch not in pack_keys:
        raise MissingKey(epoch)
    sequence = frame.get("deviceSequence")
    sender = frame.get("senderSigningPublicKey")
    legacy = frame.get("encryption")
    if frame.get("entityType") == "legacy_envelope" and isinstance(legacy, dict):
        if legacy.get("scheme") != "packin-legacy-envelope-v1":
            raise UnsupportedSchema("Unsupported legacy event")
        sequence = legacy.get("deviceSequence")
        sender = legacy.get("senderSigningPublicKey")
    if not isinstance(sender, str) or not sender:
        raise CryptoError("Sender signing identity is missing")
    try:
        encoded = decode64(frame.get("encryptedPayload"), 1_500_000).decode("utf8")
    except UnicodeError as exc:
        raise CryptoError("Invalid encrypted envelope encoding") from exc
    parts = encoded.split(".")
    if parts and parts[0] != "1":
        raise UnsupportedSchema("Unsupported encrypted event version")
    if frame.get("signature") is not None and (
        len(parts) != 5 or decode64(frame["signature"], 80) != decode64(parts[4], 80)
    ):
        raise CryptoError("Event signature metadata does not match")
    clear = decrypt_event(
        encoded,
        pack_keys[epoch],
        sender,
        pack=pack_id,
        event=frame.get("eventId"),
        device=frame.get("actorDeviceId"),
        sequence=sequence,
        event_type=frame.get("eventType"),
        epoch=epoch,
    )
    try:
        payload = json.loads(clear)
    except (ValueError, UnicodeError) as exc:
        raise CryptoError("Invalid encrypted event payload") from exc
    if not isinstance(payload, dict):
        raise CryptoError("Invalid encrypted event payload")
    if type(payload.get("schemaVersion", 1)) is not int or payload.get("schemaVersion", 1) != 1:
        raise UnsupportedSchema("Unsupported encrypted payload version")
    if frame.get("eventType") not in KNOWN_EVENTS:
        raise UnsupportedSchema("Unsupported Pack event type")
    if payload.get("packId", pack_id) != pack_id:
        raise CryptoError("Decrypted item belongs to another Pack")
    return payload
