"""One ordered event-log projection per Pack; no polling or HTTP here."""

from __future__ import annotations

import asyncio
from collections import Counter
from datetime import datetime
import hashlib
import hmac
import json
from typing import Any, Awaitable, Callable

from .protocol import PROTOCOL_VERSION, SYNC_GENERATION, UnsupportedSchema, decode_event
from .state import PackState, ProjectionError


class IntegrityError(ValueError):
    """Keep the prior verified projection after an invalid replay or snapshot."""


class EventLog:
    def __init__(
        self,
        state: PackState,
        keys: Callable[[], dict[int, bytes]],
        decrypt: Callable[..., Awaitable[dict[str, Any]]] | None = None,
    ) -> None:
        self.state = state
        self.keys = keys
        self.metrics: Counter[str] = Counter()
        self.synced = False
        self._pending: dict[int, tuple[dict[str, Any], int]] = {}
        self._pending_bytes = 0
        self._range: tuple[int, int] | None = None
        self._snapshot: dict[str, Any] | None = None
        self._decrypt = decrypt or self._decode

    async def _decode(self, frame: dict[str, Any]) -> dict[str, Any]:
        return await asyncio.to_thread(decode_event, frame, self.state.pack_id, self.keys())

    @staticmethod
    def _integer(value: Any, minimum: int = 0) -> int:
        if type(value) is not int or not minimum <= value <= 2**53 - 1:
            raise IntegrityError("Invalid sequence metadata")
        return value

    @staticmethod
    def _timestamp(frame: dict[str, Any]) -> int:
        try:
            value = datetime.fromisoformat(frame["serverTimestamp"].replace("Z", "+00:00"))
            if value.tzinfo is None:
                raise ValueError()
            return int(value.timestamp() * 1000)
        except (KeyError, TypeError, ValueError):
            raise IntegrityError("Invalid event acceptance time") from None

    def reset_connection(self) -> None:
        self.synced = False
        self._pending.clear()
        self._pending_bytes = 0
        self._range = None
        self._snapshot = None

    def abort_snapshot(self) -> None:
        self._snapshot = None
        self.synced = False

    def _envelope_metadata(self, frame: dict[str, Any]) -> int:
        if frame.get("dataEpoch") != self.state.data_epoch:
            raise IntegrityError("Event data epoch does not match")
        if (
            frame.get("protocolVersion", PROTOCOL_VERSION) != PROTOCOL_VERSION
            or frame.get("syncGeneration", SYNC_GENERATION) != SYNC_GENERATION
        ):
            raise UnsupportedSchema("Unsupported event-log protocol")
        return self._integer(frame.get("serverSequence"), 1)

    async def _apply(self, target: PackState, frame: dict[str, Any]) -> None:
        if frame.get("type") == "SEQUENCE_ADVANCED" or frame.get("scopeOmitted") is True:
            self.metrics["scoped_rows_omitted"] += 1
            return
        payload = await self._decrypt(frame)
        if frame.get("actorDeviceId") == getattr(self, "device_id", None):
            target.device_sequence = max(target.device_sequence, self._integer(frame.get("deviceSequence"), 1))
        try:
            target.apply(
                frame["eventType"],
                payload,
                frame.get("actorUserId", ""),
                self._timestamp(frame),
                entity_type=frame.get("entityType", ""),
                entity_id=frame.get("entityId", ""),
                entity_version=self._integer(frame.get("entityVersion"), 1),
            )
        except (ProjectionError, ValueError, KeyError, TypeError):
            # Keep the accepted transport head, like Android, while quarantining
            # forbidden domain fields. This runs only after successful decryption
            # and signature verification, never for a cryptographic failure.
            entity_type, entity_id = frame.get("entityType"), frame.get("entityId")
            if (
                isinstance(entity_type, str) and entity_type and entity_type != "legacy_envelope"
                and isinstance(entity_id, str) and entity_id
            ):
                key = entity_type + ":" + entity_id
                target.revisions[key] = max(
                    target.revisions.get(key, 0), self._integer(frame.get("entityVersion"), 1)
                )
            if frame.get("actorDeviceId") == getattr(self, "device_id", None) and isinstance(frame.get("eventId"), str):
                target.own_rejected_events = [*target.own_rejected_events[-199:], frame["eventId"]]
            self.metrics["domain_mutations_rejected"] += 1
            return
        if frame.get("actorDeviceId") == getattr(self, "device_id", None) and isinstance(frame.get("eventId"), str):
            target.own_applied_events = [*target.own_applied_events[-199:], frame["eventId"]]

    async def feed(self, raw: str) -> list[dict[str, Any]]:
        if not isinstance(raw, str) or len(raw.encode("utf8")) > 1_600_000:
            raise IntegrityError("Event frame exceeds limit")
        try:
            frame = json.loads(raw)
        except ValueError:
            raise IntegrityError("Invalid event frame") from None
        if not isinstance(frame, dict):
            raise IntegrityError("Invalid event frame")
        kind = frame.get("type")
        if kind in {"PACK_EVENT", "SEQUENCE_ADVANCED"}:
            sequence = self._envelope_metadata(frame)
            if sequence <= self.state.last_sequence:
                self.metrics["duplicate_events"] += 1
                return []
            if self._snapshot is not None and sequence <= self._snapshot["boundary"]["snapshotHeadSequence"]:
                return []
            if self._snapshot is not None or sequence > self.state.last_sequence + 1:
                if sequence not in self._pending:
                    size = len(raw.encode("utf8"))
                    self._pending[sequence] = (frame, size)
                    self._pending_bytes += size
                if len(self._pending) > 250 or self._pending_bytes > 4_000_000:
                    raise IntegrityError("Replay gap exceeds buffer limit")
                if self._snapshot is not None:
                    return []
                end = min(sequence - 1, self.state.last_sequence + 250)
                requested = (self.state.last_sequence + 1, end)
                if self._range == requested:
                    return []
                self._range = requested
                self.metrics["gap_requests"] += 1
                return [{"type": "FETCH_RANGE", "fromSequence": requested[0], "toSequence": requested[1]}]
            await self._apply(self.state, frame)
            self.state.last_sequence = sequence
            self.metrics["events_applied"] += 1
            while self.state.last_sequence + 1 in self._pending:
                following, size = self._pending.pop(self.state.last_sequence + 1)
                self._pending_bytes -= size
                await self._apply(self.state, following)
                self.state.last_sequence += 1
            if not self._pending:
                self._pending_bytes = 0
                self._range = None
            return []
        if kind == "SNAPSHOT_REQUIRED":
            self.synced = False
            self.metrics["snapshots_requested"] += 1
            return [{"type": "SNAPSHOT"}]
        if kind == "SNAPSHOT_BEGIN":
            head = self._integer(frame.get("snapshotHeadSequence"))
            count = self._integer(frame.get("rowCount"))
            if (
                frame.get("snapshotKind") != "EVENT_LOG_V1"
                or frame.get("snapshotDigestAlgorithm") != "SHA-256-JSONL"
                or frame.get("dataEpoch") != self.state.data_epoch
                or count != head
                or count > 100000
                or not isinstance(frame.get("snapshotDigest"), str)
                or len(frame["snapshotDigest"]) != 64
            ):
                raise IntegrityError("Unsupported or oversized event-log snapshot")
            staged = PackState(
                self.state.pack_id,
                self.state.user_id,
                self.state.role,
                self.state.data_epoch,
                device_sequence=self.state.device_sequence,
            )
            staged.snapshot_mode = True
            self._snapshot = {"state": staged, "boundary": frame, "hasher": hashlib.sha256(), "rows": 0, "bytes": 0}
            self.synced = False
            return []
        if kind == "SNAPSHOT_ROW":
            snapshot = self._snapshot
            if snapshot is None:
                raise IntegrityError("Snapshot row has no verified boundary")
            sequence = self._envelope_metadata(frame)
            if sequence != snapshot["rows"] + 1:
                raise IntegrityError("Snapshot rows must be contiguous")
            if frame.get("packId") != self.state.pack_id:
                raise IntegrityError("Snapshot row belongs to another Pack")
            snapshot["hasher"].update((raw + "\n").encode("utf8"))
            snapshot["bytes"] += len(raw.encode("utf8")) + 1
            if snapshot["bytes"] > 32_000_000 or snapshot["rows"] >= snapshot["boundary"]["rowCount"]:
                raise IntegrityError("Snapshot exceeds advertised limits")
            await self._apply(snapshot["state"], frame)
            snapshot["rows"] += 1
            snapshot["state"].last_sequence = sequence
            return []
        if kind == "SNAPSHOT_COMPLETE":
            snapshot = self._snapshot
            if snapshot is None:
                raise IntegrityError("Snapshot completion has no boundary")
            begin = snapshot["boundary"]
            fields = (
                "dataEpoch",
                "snapshotHeadSequence",
                "rowCount",
                "snapshotDigest",
                "snapshotDigestAlgorithm",
                "snapshotId",
                "snapshotKind",
            )
            if any(frame.get(key) != begin.get(key) for key in fields) or snapshot["rows"] != begin["rowCount"]:
                raise IntegrityError("Snapshot completion boundary changed")
            if not hmac.compare_digest(snapshot["hasher"].hexdigest(), begin["snapshotDigest"]):
                raise IntegrityError("Snapshot digest does not match")
            snapshot["state"].finish_snapshot_visibility()
            self.state = snapshot["state"]
            self._snapshot = None
            self._pending = {key: value for key, value in self._pending.items() if key > self.state.last_sequence}
            self._pending_bytes = sum(value[1] for value in self._pending.values())
            self._range = None
            while self.state.last_sequence + 1 in self._pending:
                following, size = self._pending.pop(self.state.last_sequence + 1)
                self._pending_bytes -= size
                await self._apply(self.state, following)
                self.state.last_sequence += 1
            self.metrics["snapshots_verified"] += 1
            return []
        if kind == "SYNC_COMPLETE":
            head = self._integer(frame.get("headSequence"))
            last = self._integer(frame.get("lastSequence"))
            if last > head:
                raise IntegrityError("Sync cursor is beyond the Pack head")
            if frame.get("hasMore") is True or head > self.state.last_sequence or self._pending:
                return [{"type": "RESUME", "afterSequence": self.state.last_sequence}]
            self.synced = True
            return []
        if kind == "SYNC_BEGIN":
            self.synced = False
            return []
        return []
