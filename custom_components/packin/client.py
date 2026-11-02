"""One shared, outbound-only synchronization client per connected Pack."""

from __future__ import annotations

import asyncio
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import json
import random
import time
from typing import Any, Awaitable, Callable, Coroutine
from uuid import uuid4

import aiohttp
from cryptography.exceptions import InvalidSignature, InvalidTag

from .api import PackInApi, PackInApiError
from .crypto import CryptoError, decode64, encode64
from .event_log import EventLog, IntegrityError
from .find_me import decode_locations
from .protocol import CAPABILITIES, PROTOCOL_VERSION, SYNC_GENERATION, MissingKey, UnsupportedSchema, descriptor
from .state import PackState, PermissionDenied, ProjectionError, new_id, occurrence, recurring_advance

BACKOFF = (5, 15, 30, 60, 300, 900)


class ActionPending(ValueError):
    """The durable action is still awaiting an authoritative result."""


class Conflict(ValueError):
    """The server definitely rejected a stale action; reread before retrying."""


class PackClient:
    def __init__(
        self,
        api: PackInApi,
        cache: dict[str, Any],
        persist: Callable[[dict[str, Any]], Awaitable[None]],
        changed: Callable[[], None],
        auth_failed: Callable[[str], None],
        create_task: Callable[[Coroutine[Any, Any, Any], str], asyncio.Task],
        location_interval: int = 600,
    ) -> None:
        self.api = api
        data = api.data
        state = (
            PackState.restore(cache["state"], data["pack_id"], data["user_id"])
            if cache.get("state")
            else (PackState(data["pack_id"], data["user_id"], data["role"], data["data_epoch"]))
        )
        if state.data_epoch != data["data_epoch"] or data.get("reauth_reason"):
            state = PackState(data["pack_id"], data["user_id"], data["role"], data["data_epoch"])
            cache = {}
        state.role = data["role"]
        self.log = EventLog(state, self.keys)
        self.log.device_id = data["connection_id"]
        # Older nonempty caches already have an ordered, verified replay cursor.
        # A new/empty projection must bootstrap from the complete event ledger:
        # RESUME only includes the current data epoch on the server.
        self._needs_snapshot = not bool(cache.get("bootstrap_verified", state.last_sequence > 0))
        self.outbox = deepcopy(cache.get("outbox"))
        self.workflow = deepcopy(cache.get("workflow"))
        self.device_sequence = max(
            int(data.get("device_sequence", 0)), state.device_sequence, int(cache.get("device_sequence", 0))
        )
        self.persist = persist
        self.changed = changed
        self.auth_failed = auth_failed
        self.create_task = create_task
        self.location_interval = location_interval
        self.locations: dict[str, Any] = {}
        self.last_location_fetch: datetime | None = None
        self.last_sync: datetime | None = None
        self.status = "starting"
        self.error: str | None = None
        self.metrics: Counter[str] = Counter()
        self._tasks: list[asyncio.Task] = []
        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self._stopping = False
        self._ready = asyncio.Event()
        self._save_lock = asyncio.Lock()
        self._actions = asyncio.Lock()
        self._location_lock = asyncio.Lock()
        self._key_request_lock = asyncio.Lock()
        self._wake_locations = asyncio.Event()
        self._last_location_attempt = 0.0
        self._last_metadata_attempt = 0.0
        self._result: asyncio.Future | None = None
        self._sent_connection: str | None = None
        self._connection_id = ""
        self._key_requested: set[int] = set()
        self._waiting_key = False
        self._waiting_epoch: int | None = None
        self._blocked = bool(data.get("reauth_reason"))
        self._workflow_task: asyncio.Task | None = None

    @property
    def state(self) -> PackState:
        return self.log.state

    @property
    def available(self) -> bool:
        return (
            self.status == "connected"
            and self.log.synced
            and not self._blocked
            and self.api.data.get("access_expires_at_ms", 0) > int(time.time() * 1000)
        )

    def keys(self) -> dict[int, bytes]:
        return {int(key): decode64(value, 32) for key, value in self.api.data.get("pack_keys", {}).items()}

    def _notify(self) -> None:
        self.changed()

    async def _save(self) -> None:
        async with self._save_lock:
            value = {
                "state": self.state.export(),
                "outbox": deepcopy(self.outbox),
                "workflow": deepcopy(self.workflow),
                "device_sequence": self.device_sequence,
                "bootstrap_verified": not self._needs_snapshot,
            }
            await self.persist(value)

    def start(self) -> None:
        if self._tasks or self._blocked:
            return
        self._tasks = [
            self.create_task(self._connect_loop(), "Pack-In synchronization"),
            self.create_task(self._location_loop(), "Pack-In batched locations"),
            self.create_task(self._renew_loop(), "Pack-In session renewal"),
        ]

    async def stop(self, *, clear: bool = False) -> None:
        self._stopping = True
        self._ready.clear()
        if self._ws is not None:
            await self._ws.close()
        if self._workflow_task is not None:
            self._tasks.append(self._workflow_task)
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        self.locations.clear()
        self.status = "disconnected"
        if self._result and not self._result.done():
            self._result.set_exception(ActionPending("Pack-In was unloaded; the action is saved"))
        if clear:
            self.outbox = self.workflow = None
            self.log.state = PackState(self.state.pack_id, self.state.user_id, "read_only", self.state.data_epoch)
            self._needs_snapshot = True
        await self._save()
        self._notify()

    async def _deny(self, code: str) -> None:
        self._blocked = True
        self._ready.clear()
        self.status = "reauth_required"
        self.error = code
        self.locations.clear()
        self.outbox = self.workflow = None
        self.log.state = PackState(self.state.pack_id, self.state.user_id, "read_only", self.state.data_epoch)
        self._needs_snapshot = True
        self.api.data["pack_keys"] = {}
        self.api.data["members"] = []
        self.api.data["reauth_reason"] = code
        await self.api._save()
        await self._save()
        if self._result and not self._result.done():
            self._result.set_exception(PermissionDenied("Reconnect Pack-In in Devices & services"))
        if self._ws is not None:
            await self._ws.close()
        self.auth_failed(code)
        self._notify()

    async def _request_epoch_once(self, epoch: int) -> None:
        async with self._key_request_lock:
            if epoch not in self._key_requested:
                # A failed or lost request remains eligible for bounded recovery.
                await self.api.request_key(epoch)
                self._key_requested.add(epoch)

    async def _hold_for_key(self, epoch: int) -> None:
        self._waiting_key = True
        self._waiting_epoch = epoch
        self._ready.clear()
        self.log.abort_snapshot()
        self.status = "waiting_for_phone"
        self._notify()
        await self._request_epoch_once(epoch)

    async def _send(self, value: dict[str, Any]) -> None:
        if self._ws is None or self._ws.closed:
            raise ActionPending("Pack-In is reconnecting; the action is saved")
        await self._ws.send_json(value, dumps=lambda obj: json.dumps(obj, ensure_ascii=False, separators=(",", ":")))

    def _sync_request(self) -> dict[str, Any]:
        if self._needs_snapshot:
            return {"type": "SNAPSHOT"}
        return {"type": "RESUME", "afterSequence": self.state.last_sequence}

    async def _send_outbox(self) -> None:
        if self.outbox and self.log.synced and not self._waiting_key and self._sent_connection != self._connection_id:
            self._sent_connection = self._connection_id
            self.metrics["mutation_sends"] += 1
            await self._send(self.outbox["wire"])

    async def _settle_receipt(self) -> None:
        if not self.outbox:
            return
        event_id = self.outbox["wire"]["eventId"]
        if event_id in self.state.own_rejected_events:
            self.outbox = self.workflow = None
            self._sent_connection = None
            self.metrics["mutations_rejected"] += 1
            await self._save()
            if self._result and not self._result.done():
                self._result.set_exception(PermissionDenied("Pack-In rejected this action's permissions"))
            return
        if event_id not in self.state.own_applied_events:
            return
        self.outbox = None
        self._sent_connection = None
        self.metrics["mutations_verified"] += 1
        await self._save()
        if self._result and not self._result.done():
            self._result.set_result(None)

    async def _frame(self, raw: str) -> None:
        if self._blocked:
            return
        try:
            frame = json.loads(raw)
        except ValueError:
            raise IntegrityError("Invalid server frame") from None
        if not isinstance(frame, dict):
            raise IntegrityError("Invalid server frame")
        kind = frame.get("type")
        if kind == "HELLO":
            if (
                frame.get("packId") != self.state.pack_id
                or frame.get("deviceId") != self.api.data["connection_id"]
                or frame.get("userId") != self.state.user_id
                or frame.get("protocolVersion") != PROTOCOL_VERSION
                or frame.get("syncGeneration") != SYNC_GENERATION
                or frame.get("authorityMode") != "v3"
            ):
                raise UnsupportedSchema("Unsupported Pack-In synchronization")
            if not set(CAPABILITIES[:-1]) <= set(frame.get("capabilities", [])):
                raise UnsupportedSchema("Required synchronization capabilities are missing")
            if frame.get("dataEpoch") != self.state.data_epoch:
                # A reset invalidates queued actions as well as the old cache.
                self.outbox = self.workflow = None
                self.log.state = PackState(
                    self.state.pack_id, self.state.user_id, self.api.data["role"], int(frame["dataEpoch"])
                )
                self._needs_snapshot = True
                self.api.data["data_epoch"] = int(frame["dataEpoch"])
                await self.api._save()
                await self._save()
            next_sequence = frame.get("nextDeviceSequence")
            if type(next_sequence) is not int or next_sequence < 1:
                raise IntegrityError("Missing device sequence")
            self.device_sequence = max(self.device_sequence, next_sequence - 1)
            await self._send({**self._sync_request(), "capabilities": CAPABILITIES})
            return
        if (
            kind == "MUTATION_REJECTED"
            and self.outbox
            and frame.get("clientMutationId") == self.outbox["wire"]["clientMutationId"]
        ):
            if frame.get("retryable") is True:
                # One bounded retry after a new connection; the immutable action stays saved.
                raise PackInApiError("mutation_rate_limited", 429, max(60, int(frame.get("retryAfterSeconds", 60))))
            code = frame.get("code")
            self.outbox = None
            self._sent_connection = None
            await self._save()
            if self._result and not self._result.done():
                problem = (
                    Conflict("The item changed; retry from the latest state")
                    if code in {"stale_pack_sequence", "stale_entity_revision", "key_epoch_changed"}
                    else PermissionDenied("Pack-In rejected this action")
                )
                self._result.set_exception(problem)
            self.metrics["mutations_rejected"] += 1
            return
        if kind == "HOME_ASSISTANT_LOCATION_CONSENT":
            user_id = frame.get("userId")
            if (
                frame.get("enabled") is True
                and not any(m.get("userId") == user_id for m in self.api.data.get("members", []))
                and time.monotonic() - self._last_metadata_attempt >= 60
            ):
                self._last_metadata_attempt = time.monotonic()
                await self.api.metadata()
            for member in self.api.data.get("members", []):
                if member.get("userId") == user_id:
                    member["locationConsent"] = frame.get("enabled") is True
            self.locations.pop(user_id, None)
            self._wake_locations.set()
            self._notify()
            return
        if kind in {"HOME_ASSISTANT_LOCATION_UNAVAILABLE", "HOME_ASSISTANT_MEMBER_REMOVED"}:
            user_id = frame.get("userId")
            self.locations.pop(user_id, None)
            if kind == "HOME_ASSISTANT_MEMBER_REMOVED":
                self.api.data["members"] = [m for m in self.api.data.get("members", []) if m.get("userId") != user_id]
            self._notify()
            return
        if kind == "HOME_ASSISTANT_KEYS_READY":
            await self.api.refresh_keys()
            if self._waiting_epoch is not None and self._waiting_epoch not in self.keys():
                await self._hold_for_key(self._waiting_epoch)
                return
            self._waiting_key = False
            self._waiting_epoch = None
            self.log.reset_connection()
            await self._send(self._sync_request())
            return
        if kind == "KEY_EPOCH_CHANGED":
            epoch = frame.get("keyEpoch") or frame.get("currentKeyEpoch")
            if type(epoch) is int:
                self.api.data["key_epoch"] = epoch
                await self.api._save()
            await self.api.refresh_keys()
            if type(epoch) is int and epoch not in self.keys():
                await self._hold_for_key(epoch)
            return
        if self._waiting_key:
            return
        if kind in {"SNAPSHOT_REQUIRED", "SNAPSHOT_BEGIN"}:
            self._needs_snapshot = True
        before = self.state.last_sequence
        responses = await self.log.feed(raw)
        if kind == "SNAPSHOT_COMPLETE":
            self._needs_snapshot = False
        for response in responses:
            await self._send(response)
        if self.state.last_sequence != before or kind == "SNAPSHOT_COMPLETE":
            self.last_sync = datetime.now(timezone.utc)
            await self._settle_receipt()
            await self._save()
            self._notify()
        if self.log.synced:
            self.status = "connected"
            self.error = None
            self._ready.set()
            await self._settle_receipt()
            await self._send_outbox()
            if (
                self.workflow
                and not self.outbox
                and not self._actions.locked()
                and (self._workflow_task is None or self._workflow_task.done())
            ):
                self._workflow_task = self.create_task(
                    self._recover_workflow(), "Pack-In recurring completion recovery"
                )
            self._notify()

    async def _connect_loop(self) -> None:
        failures = 0
        while not self._stopping and not self._blocked:
            started = time.monotonic()
            delay = BACKOFF[min(failures, len(BACKOFF) - 1)]
            try:
                self.status = "connecting"
                self._notify()
                self._connection_id = uuid4().hex
                self._sent_connection = None
                self.log.reset_connection()
                if self._waiting_epoch is not None:
                    if self._waiting_epoch not in self.keys():
                        await self.api.refresh_keys()
                    if self._waiting_epoch in self.keys():
                        self._waiting_key = False
                        self._waiting_epoch = None
                    else:
                        await self._hold_for_key(self._waiting_epoch)
                self._ws = await self.api.websocket()
                self.metrics["connections"] += 1
                close_reason = ""
                while not self._ws.closed:
                    message = await self._ws.receive()
                    if message.type == aiohttp.WSMsgType.TEXT:
                        try:
                            await self._frame(message.data)
                        except MissingKey as exc:
                            await self._hold_for_key(exc.epoch)
                    elif message.type == aiohttp.WSMsgType.ERROR:
                        raise PackInApiError("connection_unavailable")
                    elif message.type in {aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSING}:
                        close_reason = str(message.extra or "")
                        break
                reason = self._ws.close_code
                if close_reason == "superseded_connection":
                    await self._deny("duplicate_connection")
                    break
                if reason == 4003:
                    # The close text arrives as CLOSED in some aiohttp versions;
                    # metadata/renewal gives the authoritative revocation decision.
                    await self.api.ensure_session(force=True)
            except PackInApiError as exc:
                self.error = exc.code
                delay = max(delay, exc.retry_after)
                if exc.status == 409:
                    # Refresh once only when the server proves a new data epoch.
                    # Unsupported Packs/protocols must not become retry storms.
                    if await self._recover_handshake():
                        continue
                if exc.auth_failed:
                    await self._deny(exc.code)
                    break
                if exc.status in (400, 404, 410, 422):
                    self._blocked = True
                    self.status = "attention_required"
                    self._notify()
            except (
                CryptoError,
                InvalidSignature,
                InvalidTag,
                IntegrityError,
                UnsupportedSchema,
                KeyError,
                ValueError,
                TypeError,
            ) as exc:
                self.error = "unsupported_schema" if isinstance(exc, UnsupportedSchema) else "event_integrity_failed"
                self.status = "attention_required"
                self._blocked = True
            except (aiohttp.ClientError, OSError, asyncio.TimeoutError):
                self.error = "network_unavailable"
            finally:
                self._ready.clear()
                if self._ws is not None:
                    await self._ws.close()
                self._ws = None
            if self._stopping or self._blocked:
                break
            self.status = "offline"
            self._notify()
            failures = 0 if time.monotonic() - started > 300 else failures + 1
            self.metrics["reconnect_waits"] += 1
            await asyncio.sleep(delay * random.uniform(1.0, 1.2))

    async def _recover_handshake(self) -> bool:
        old_epoch = self.state.data_epoch
        try:
            result = await self.api.metadata()
        except PackInApiError as exc:
            if exc.auth_failed:
                await self._deny(exc.code)
                return False
            if exc.status == 409:
                self._blocked = True
                self.status = "attention_required"
                self.error = exc.code
                self._notify()
            # A failed network metadata check uses the ordinary bounded backoff.
            return False
        if (
            result.get("authorityMode") != "v3"
            or result.get("protocolVersion") != PROTOCOL_VERSION
            or result.get("syncGeneration") != SYNC_GENERATION
            or type(result.get("dataEpoch")) is not int
            or result["dataEpoch"] <= old_epoch
        ):
            self._blocked = True
            self.status = "attention_required"
            self.error = "synchronization_upgrade_required"
            self._notify()
            return False
        self.outbox = self.workflow = None
        self.locations.clear()
        self.log.state = PackState(self.state.pack_id, self.state.user_id, self.api.data["role"], result["dataEpoch"])
        self.log.reset_connection()
        self._needs_snapshot = True
        await self._save()
        self.metrics["epoch_recoveries"] += 1
        if self._result and not self._result.done():
            self._result.set_exception(Conflict("Pack-In data was reset; the old action was cancelled"))
        self._notify()
        return True

    async def _renew_loop(self) -> None:
        while not self._stopping and not self._blocked:
            expires = self.api.data.get("access_expires_at_ms", 0) / 1000
            await asyncio.sleep(max(30, expires - time.time() - 90))
            if self._blocked:
                return
            try:
                await self.api.ensure_session(force=True)
                self.state.role = self.api.data["role"]
                if self._ws is not None:
                    await self._ws.close()
            except PackInApiError as exc:
                if exc.auth_failed:
                    await self._deny(exc.code)
                    if self._ws is not None:
                        await self._ws.close()
                    return
                await asyncio.sleep(max(60, exc.retry_after))

    async def refresh_locations(self) -> None:
        async with self._location_lock:
            if (
                self._blocked
                or not self.location_interval
                or not self.available
                or "locations:read" not in self.api.data.get("scopes", [])
                or not any(m.get("locationConsent") for m in self.api.data.get("members", []))
                or time.monotonic() - self._last_location_attempt < 60
            ):
                return
            self._last_location_attempt = time.monotonic()
            result = await self.api.locations()
            now = datetime.now(timezone.utc)
            allowed = {m["userId"] for m in self.api.data.get("members", []) if m.get("locationConsent")}
            self.locations = await asyncio.to_thread(
                decode_locations, result.get("locations", []), self.state.pack_id, self.keys(), allowed, now
            )
            self.last_location_fetch = now
            self._notify()

    async def _location_loop(self) -> None:
        while not self._stopping and not self._blocked:
            self._wake_locations.clear()
            try:
                await asyncio.wait_for(self._ready.wait(), timeout=60)
                await self.refresh_locations()
            except asyncio.TimeoutError:
                pass
            except PackInApiError as exc:
                self.error = exc.code
                if exc.auth_failed:
                    await self._deny(exc.code)
                    return
            except MissingKey as exc:
                try:
                    await self._request_epoch_once(exc.epoch)
                    self.error = "location_key_required"
                except PackInApiError as problem:
                    self.error = problem.code
                    if problem.auth_failed:
                        await self._deny(problem.code)
                        return
                self.locations.clear()
            except (CryptoError, InvalidSignature, InvalidTag, ValueError, KeyError):
                self.locations.clear()
                self.error = "location_integrity_failed"
            self._notify()  # Refresh the age/availability without a network request.
            try:
                await asyncio.wait_for(self._wake_locations.wait(), timeout=self.location_interval or 600)
            except asyncio.TimeoutError:
                pass

    async def _mutate(self, event_type: str, payload: dict[str, Any]) -> None:
        if not self.available:
            raise ActionPending("Pack-In must be connected before making a change")
        if self.outbox:
            raise ActionPending("A previous Pack-In action is awaiting confirmation")
        self.state.require_writer()
        kind, identifier, operation = descriptor(event_type, payload)
        scope = "tasks:write" if kind == "chore" else "groceries:write"
        if scope not in self.api.data.get("scopes", []):
            raise PermissionDenied("This connection does not have write permission")
        event_id = new_id("haevent")
        self.device_sequence += 1
        epoch = self.api.data["key_epoch"]
        key = self.keys().get(epoch)
        if key is None:
            raise ActionPending("Open Pack-In to approve the new Pack key")
        encoded = await asyncio.to_thread(
            self.api.identity.encrypt_event,
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(),
            key,
            pack=self.state.pack_id,
            event=event_id,
            device=self.api.data["connection_id"],
            sequence=self.device_sequence,
            event_type=event_type,
            epoch=epoch,
        )
        wire = {
            "type": "MUTATE",
            "eventId": event_id,
            "clientMutationId": new_id("hamutation"),
            "activityId": new_id("haactivity"),
            "dataEpoch": self.state.data_epoch,
            "deviceSequence": self.device_sequence,
            "eventType": event_type,
            "entityType": kind,
            "entityId": identifier,
            "operation": operation,
            "baseRevision": self.state.revisions.get(kind + ":" + identifier, 0),
            "expectedPackSequence": self.state.last_sequence,
            "origin": "USER",
            "keyEpoch": epoch,
            "encryptedPayload": encode64(encoded.encode()),
            "signature": encoded.split(".")[4],
            "senderSigningPublicKey": self.api.identity.public["signingPublicKey"],
        }
        self.outbox = {"wire": wire}
        self._sent_connection = None
        self._result = asyncio.get_running_loop().create_future()
        self._result.add_done_callback(lambda future: future.exception() if not future.cancelled() else None)
        await self._save()  # Persist identity, sequence and exact ciphertext before the send.
        await self._send_outbox()
        try:
            await asyncio.wait_for(asyncio.shield(self._result), timeout=30)
        except asyncio.TimeoutError:
            raise ActionPending("Pack-In is still confirming this saved action") from None

    async def update_task(self, identifier: str, changes: dict[str, Any]) -> None:
        async with self._actions:
            for attempt in range(2):
                now = int(time.time() * 1000)
                plans = self.state.task_changes(identifier, changes, now, self.api.data.get("time_zone", "UTC"))
                if len(plans) > 1:
                    current = self.state.chores[identifier]
                    self.workflow = {
                        "parent": identifier,
                        "due": current.get("dueAt") or now,
                        "recurrence": current.get("recurrence"),
                        "now": now,
                        "phase": "complete" if current.get("dueAt") is not None else "normalize",
                    }
                    await self._save()
                    await self._finish_workflow()
                    return
                if not plans:
                    return
                try:
                    await self._mutate("chore.upserted", plans[0])
                    return
                except Conflict:
                    if attempt:
                        raise
                    await self._resync()

    async def _resync(self) -> None:
        self._ready.clear()
        self.log.synced = False
        await self._send({"type": "RESUME", "afterSequence": self.state.last_sequence})
        await asyncio.wait_for(self._ready.wait(), timeout=30)

    async def _finish_workflow(self) -> None:
        workflow = self.workflow
        if workflow is None:
            return
        parent = self.state.chores.get(workflow["parent"])
        if parent is None or parent.get("recurrence") != workflow["recurrence"]:
            self.workflow = None
            await self._save()
            return
        now = workflow["now"]
        if workflow["phase"] == "normalize":
            if parent.get("dueAt") is None:
                normalized = deepcopy(parent)
                normalized.update(dueAt=workflow["due"], updatedAt=now)
                await self._mutate("chore.upserted", normalized)
                parent = self.state.chores[parent["id"]]
            workflow["phase"] = "complete"
            await self._save()
        if workflow["phase"] == "complete":
            if parent.get("dueAt") != workflow.get("due"):
                self.workflow = None
                await self._save()
                return
            plans = self.state.task_changes(
                parent["id"], {"completed": True}, now, self.api.data.get("time_zone", "UTC")
            )
            completed = plans[0]
            if completed["id"] not in self.state.chores:
                await self._mutate("chore.upserted", completed)
            workflow["phase"] = "advance"
            await self._save()
        # Merge into the fresh parent, preserving concurrent title/assignment edits.
        parent = self.state.chores.get(workflow["parent"])
        if (
            parent
            and parent.get("dueAt") == workflow.get("due")
            and parent.get("recurrence") == workflow["recurrence"]
            and parent.get("completedAt") is None
        ):
            next_due, reminder = recurring_advance(parent, now, self.api.data.get("time_zone", "UTC"))
            advanced = deepcopy(parent)
            advanced.update(
                dueAt=next_due,
                reminderAt=reminder,
                completedAt=None,
                completedByUserId=None,
                updatedAt=int(time.time() * 1000),
            )
            await self._mutate("chore.upserted", advanced)
        self.workflow = None
        await self._save()

    async def _recover_workflow(self) -> None:
        async with self._actions:
            if self.outbox or not self.available:
                return
            try:
                await self._finish_workflow()
            except (ActionPending, Conflict, PermissionDenied, ProjectionError):
                self.error = "recurring_action_pending"
                self._notify()

    async def add_task(self, title: str, due_at: int | None = None) -> str:
        async with self._actions:
            if not isinstance(title, str) or not title.strip() or len(title) > 500:
                raise ProjectionError("Enter a task name")
            now = int(time.time() * 1000)
            identifier = new_id("task")
            await self._mutate(
                "chore.upserted",
                {
                    "id": identifier,
                    "title": title.strip(),
                    "dueAt": due_at,
                    "reminderAt": None,
                    "recurrence": None,
                    "assigneeUserId": None,
                    "assignmentMode": "UNASSIGNED",
                    "claimedByUserId": None,
                    "createdByUserId": self.state.user_id,
                    "completedAt": None,
                    "completedByUserId": None,
                    "historyJson": "[]",
                    "createdAt": now,
                    "updatedAt": now,
                },
            )
            return identifier

    async def assign_task(self, identifier: str, members: list[str]) -> None:
        allowed = {m["userId"] for m in self.api.data.get("members", []) if m.get("role") != "read_only"}
        if not set(members) <= allowed:
            raise PermissionDenied("Choose current Pack members")
        await self.update_task(identifier, {"assignees": members})

    async def remove_item(self, category: str, identifier: str) -> None:
        async with self._actions:
            items = self.state.chores if category == "task" else self.state.groceries
            if identifier not in items:
                return
            if category == "task" and occurrence(items[identifier]):
                raise PermissionDenied("Completed recurring occurrences are kept as history")
            if category != "task" and not self.state.grocery_visible(items[identifier]):
                raise PermissionDenied("This list is not available")
            await self._mutate(
                "chore.removed" if category == "task" else "grocery.item.removed",
                {"id": identifier, "deleted": True, "updatedAt": int(time.time() * 1000)},
            )

    async def update_grocery(self, identifier: str, changes: dict[str, Any]) -> None:
        async with self._actions:
            for attempt in range(2):
                payload = self.state.grocery_change(identifier, changes, int(time.time() * 1000))
                try:
                    await self._mutate("grocery.item.upserted", payload)
                    return
                except Conflict:
                    if attempt:
                        raise
                    await self._resync()

    async def add_grocery(self, name: str, quantity: str | None = None, list_id: str | None = None) -> str:
        async with self._actions:
            if not isinstance(name, str) or not name.strip() or len(name) > 500:
                raise ProjectionError("Enter an item name")
            if quantity is not None and (not isinstance(quantity, str) or len(quantity) > 100):
                raise ProjectionError("Invalid quantity")
            now = int(time.time() * 1000)
            list_id = list_id or "pack-shopping-" + self.state.pack_id
            parent = self.state.shopping_lists.get(list_id)
            if parent is None:
                if list_id != "pack-shopping-" + self.state.pack_id:
                    raise PermissionDenied("Choose an existing shared shopping list")
                await self._mutate(
                    "shopping.list.upserted",
                    {
                        "id": list_id,
                        "name": "Groceries",
                        "ownerUserId": self.state.user_id,
                        "shareMode": "PACK",
                        "sharedWithJson": "[]",
                        "createdAt": now,
                        "updatedAt": now,
                        "deletedAt": None,
                    },
                )
            elif not self.state._list_visible(parent, self.state.user_id):
                raise PermissionDenied("This list is not shared with you")
            identifier = new_id("grocery")
            await self._mutate(
                "grocery.item.upserted",
                {
                    "id": identifier,
                    "name": name.strip(),
                    "quantity": quantity,
                    "checked": False,
                    "shoppingListId": list_id,
                    "groupName": None,
                    "claimedByUserId": None,
                    "purchasedAt": None,
                    "purchasedByUserId": None,
                    "historyJson": "[]",
                    "createdAt": now,
                    "updatedAt": now,
                },
            )
            return identifier

    def diagnostics(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "error_category": self.error,
            "protocol_version": PROTOCOL_VERSION,
            "sync_generation": SYNC_GENERATION,
            "last_sequence": self.state.last_sequence,
            "pending_mutations": int(self.outbox is not None),
            "recurring_action_pending": self.workflow is not None,
            "location_interval_seconds": self.location_interval,
            "last_event_sync": self.last_sync.isoformat() if self.last_sync else None,
            "last_location_fetch": self.last_location_fetch.isoformat() if self.last_location_fetch else None,
            "transport": dict(self.api.metrics),
            "replay": dict(self.log.metrics),
            "client": dict(self.metrics),
        }
