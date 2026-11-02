"""Ordered, local Pack projections and metadata-preserving mutation plans."""

from __future__ import annotations

import calendar
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import json
from typing import Any
from uuid import uuid4
from zoneinfo import ZoneInfo

from .protocol import descriptor

ASSIGNEES_KIND = "packin_task_assignees_v1"
OCCURRENCE_KIND = "recurring_task_occurrence_v1"
COLLECTIONS = {
    "chore": "chores",
    "grocery.item": "groceries",
    "shopping.list": "shopping_lists",
    "calendar.event": "calendar",
}


class ProjectionError(ValueError):
    """A signed event violates the canonical domain contract."""


class PermissionDenied(ValueError):
    """The linking member cannot perform this operation."""


def history(record: dict[str, Any]) -> list[Any]:
    value = record.get("historyJson", "[]")
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, list) or len(value) > 10000:
        raise ProjectionError("Invalid item history")
    return deepcopy(value)


def assignees(record: dict[str, Any]) -> set[str]:
    rows = history(record)
    for row in reversed(rows):
        if isinstance(row, dict) and row.get("kind") == ASSIGNEES_KIND:
            values = row.get("userIds")
            if (
                not isinstance(values, list)
                or len(values) > 100
                or any(not isinstance(v, str) or not v.strip() or len(v) > 128 for v in values)
            ):
                raise ProjectionError("Invalid assignment")
            return set(values)
    user = (
        record.get("claimedByUserId")
        if str(record.get("assignmentMode", "")).upper() == "ANYONE"
        else (record.get("assigneeUserId") or record.get("claimedByUserId"))
    )
    return {user} if isinstance(user, str) and user else set()


def occurrence(record: dict[str, Any]) -> dict[str, Any] | None:
    rows = history(record)
    if rows and isinstance(rows[0], dict) and rows[0].get("kind") == OCCURRENCE_KIND:
        return rows[0]
    return None


def may_complete(record: dict[str, Any], actor: str) -> bool:
    selected = assignees(record)
    return bool(actor) and (not selected or actor in selected)


def _history_json(value: list[Any]) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _next_date(value: datetime, recurrence: str) -> datetime:
    if recurrence in ("daily", "weekly"):
        return value + timedelta(days=1 if recurrence == "daily" else 7)
    year = value.year + (1 if recurrence == "yearly" else 0)
    month = value.month + (1 if recurrence == "monthly" else 0)
    if month > 12:
        year, month = year + 1, 1
    return value.replace(year=year, month=month, day=min(value.day, calendar.monthrange(year, month)[1]))


def recurring_advance(record: dict[str, Any], now_ms: int, time_zone: str) -> tuple[int, int | None]:
    recurrence = str(record.get("recurrence", "")).lower()
    if recurrence not in {"daily", "weekly", "monthly", "yearly"}:
        raise ProjectionError("This task has an unsupported recurrence")
    value = datetime.fromtimestamp((record.get("dueAt") or now_ms) / 1000, ZoneInfo(time_zone))
    # Bounded even for centuries-old imported data; reject rather than spin.
    for _ in range(100000):
        value = _next_date(value, recurrence)
        next_due = int(value.timestamp() * 1000)
        if next_due > now_ms:
            break
    else:
        raise ProjectionError("Task recurrence exceeds the supported range")
    offset = (
        (record["dueAt"] - record["reminderAt"])
        if (record.get("dueAt") is not None and record.get("reminderAt") is not None)
        else None
    )
    reminder = next_due - offset if offset is not None else None
    return next_due, reminder if reminder is not None and reminder > now_ms else None


@dataclass
class PackState:
    pack_id: str
    user_id: str
    role: str = "read_only"
    data_epoch: int = 1
    last_sequence: int = 0
    device_sequence: int = 0
    own_applied_events: list[str] = field(default_factory=list, repr=False)
    own_rejected_events: list[str] = field(default_factory=list, repr=False)
    chores: dict[str, dict[str, Any]] = field(default_factory=dict)
    groceries: dict[str, dict[str, Any]] = field(default_factory=dict)
    shopping_lists: dict[str, dict[str, Any]] = field(default_factory=dict)
    calendar: dict[str, dict[str, Any]] = field(default_factory=dict)
    calendar_overrides: dict[str, dict[str, Any]] = field(default_factory=dict)
    hidden_lists: list[str] = field(default_factory=list)
    snapshot_mode: bool = field(default=False, repr=False)
    revisions: dict[str, int] = field(default_factory=dict)
    tombstones: dict[str, int] = field(default_factory=dict)

    def export(self) -> dict[str, Any]:
        return deepcopy(
            {
                name: getattr(self, name)
                for name in (
                    "pack_id",
                    "user_id",
                    "role",
                    "data_epoch",
                    "last_sequence",
                    "device_sequence",
                    "own_applied_events",
                    "own_rejected_events",
                    "chores",
                    "groceries",
                    "shopping_lists",
                    "calendar",
                    "calendar_overrides",
                    "hidden_lists",
                    "revisions",
                    "tombstones",
                )
            }
        )

    @classmethod
    def restore(cls, value: dict[str, Any], pack_id: str, user_id: str) -> PackState:
        if value.get("pack_id") != pack_id or value.get("user_id") != user_id:
            raise ProjectionError("Cached Pack identity does not match")
        return cls(**deepcopy(value))

    def collection(self, kind: str) -> dict[str, dict[str, Any]]:
        if kind not in COLLECTIONS:
            raise ProjectionError("Unsupported item type")
        return getattr(self, COLLECTIONS[kind])

    def apply(
        self,
        event_type: str,
        payload: dict[str, Any],
        actor: str,
        accepted_ms: int,
        *,
        entity_type: str = "",
        entity_id: str = "",
        entity_version: int = 0,
    ) -> None:
        kind = next((key for key in COLLECTIONS if event_type.startswith(key + ".")), None)
        if kind is None:
            return
        if payload.get("packId", self.pack_id) != self.pack_id:
            raise ProjectionError("Item belongs to another Pack")
        if entity_type and entity_type != "legacy_envelope":
            expected_type, expected_id, _ = descriptor(event_type, payload)
            if entity_type != expected_type or entity_id != expected_id:
                raise ProjectionError("Item wire identity does not match the signed payload")
            if entity_version <= self.revisions.get(entity_type + ":" + entity_id, 0):
                raise ProjectionError("Item revision did not advance")
        if kind == "calendar.event" and "original" in payload and "future" in payload:
            original, future = payload["original"], payload["future"]
            if (
                not isinstance(original, dict)
                or not isinstance(future, dict)
                or not original.get("id")
                or not future.get("id")
            ):
                raise ProjectionError("Invalid calendar series split")
            if any(value.get("packId", self.pack_id) != self.pack_id for value in (original, future)):
                raise ProjectionError("Calendar split belongs to another Pack")
            self.apply("calendar.event.upserted", original, actor, accepted_ms)
            self.apply("calendar.event.upserted", future, actor, accepted_ms)
            if entity_type and entity_type != "legacy_envelope":
                self.revisions[entity_type + ":" + entity_id] = entity_version
            return
        if kind == "calendar.event" and "seriesEventId" in payload:
            from datetime import date

            series = payload.get("seriesEventId")
            day = date.fromisoformat(payload.get("occurrenceDate", "")).isoformat()
            if not isinstance(series, str) or not series:
                raise ProjectionError("Invalid calendar occurrence")
            key = series + ":" + day
            replacement = payload.get("replacement")
            if payload.get("status", "ACTIVE") == "ACTIVE" and replacement is None:
                self.calendar_overrides.pop(key, None)
                for item in self.calendar.values():
                    if item.get("seriesId", item["id"]) == series:
                        values = item.get("excludedDates", item.get("excludedDatesJson", []))
                        values = json.loads(values) if isinstance(values, str) else values
                        item["excludedDates"] = [value for value in values if value != day]
            else:
                if replacement is not None:
                    if not isinstance(replacement, dict):
                        raise ProjectionError("Invalid calendar replacement")
                    self.apply("calendar.event.upserted", replacement, actor, accepted_ms)
                self.calendar_overrides[key] = deepcopy(payload)
            if entity_type and entity_type != "legacy_envelope":
                self.revisions[entity_type + ":" + entity_id] = entity_version
            return
        identifier = payload.get("id")
        if not isinstance(identifier, str) or not identifier or len(identifier) > 256:
            raise ProjectionError("Item identity is invalid")
        if payload.get("packId", self.pack_id) != self.pack_id:
            raise ProjectionError("Item belongs to another Pack")
        collection = self.collection(kind)
        current = collection.get(identifier)
        tombstone_id = kind + ":" + identifier
        is_removed = event_type.endswith(".removed")
        if is_removed and kind == "calendar.event" and current is not None:
            payload = {**payload, "status": "REMOVED"}
            is_removed = False
        if is_removed:
            if kind == "shopping.list":
                owner = (current or payload).get("ownerUserId")
                if owner != actor:
                    raise ProjectionError("Only the list owner can remove it")
                self.groceries = {
                    key: value for key, value in self.groceries.items() if value.get("shoppingListId") != identifier
                }
            collection.pop(identifier, None)
            self.tombstones[tombstone_id] = accepted_ms
        else:
            # The caller has checked the authoritative Pack sequence. Device clocks
            # cannot override the ordering already accepted by the shared event log.
            candidate = {**deepcopy(current or {}), **deepcopy(payload), "id": identifier}
            candidate["updatedAt"] = accepted_ms
            if kind == "calendar.event" and "status" not in payload:
                if event_type == "calendar.event.cancelled":
                    candidate["status"] = "CANCELLED"
                elif event_type == "calendar.event.restored":
                    candidate["status"] = "ACTIVE"
            if kind == "chore":
                candidate.setdefault("historyJson", "[]")
                candidate.setdefault("assignmentMode", "UNASSIGNED")
                candidate.setdefault("createdByUserId", actor)
                if accepted_ms >= 1793511601000:
                    self._authorize_task(current, candidate, actor)
            if kind == "shopping.list":
                owner = candidate.get("ownerUserId") or actor
                if owner != actor and (current or {}).get("ownerUserId") != actor:
                    raise ProjectionError("Only the list owner can change sharing")
                candidate["ownerUserId"] = owner
                if not self.snapshot_mode and not self._list_visible(candidate, self.user_id):
                    if identifier not in self.hidden_lists:
                        self.hidden_lists.append(identifier)
                    collection.pop(identifier, None)
                    self.groceries = {
                        key: value for key, value in self.groceries.items() if value.get("shoppingListId") != identifier
                    }
                    return
            if kind == "grocery.item":
                if accepted_ms >= 1793511601000:
                    purchase_changed = (
                        bool(
                            candidate.get("checked")
                            or candidate.get("purchasedAt")
                            or candidate.get("purchasedByUserId")
                        )
                        if current is None
                        else any(
                            current.get(field) != candidate.get(field)
                            for field in ("checked", "purchasedAt", "purchasedByUserId")
                        )
                    )
                    if purchase_changed:
                        claimant = (current or candidate).get("claimedByUserId")
                        if claimant and claimant != actor:
                            raise ProjectionError("Grocery purchase is assigned to another member")
                        if current and current.get("claimedByUserId") != candidate.get("claimedByUserId"):
                            raise ProjectionError("Assign and purchase the item as separate actions")
                        if candidate.get("checked") and candidate.get("purchasedByUserId") != actor:
                            raise ProjectionError("Grocery purchaser does not match the sender")
                        if not candidate.get("checked") and candidate.get("purchasedByUserId") is not None:
                            raise ProjectionError("Unpurchased item has a purchaser")
                list_id = candidate.get("shoppingListId")
                parent = self.shopping_lists.get(list_id) if list_id else None
                if (
                    not self.snapshot_mode
                    and list_id
                    and (
                        parent is None
                        or not self._list_visible(parent, self.user_id)
                        or not self._list_visible(parent, actor)
                    )
                ):
                    raise ProjectionError("Shopping list is not shared with this member")
            collection[identifier] = candidate
            self.tombstones.pop(tombstone_id, None)
        # Legacy envelopes have their own event IDs, not canonical entity revisions.
        if entity_type and entity_type != "legacy_envelope" and entity_version > 0:
            self.revisions[entity_type + ":" + entity_id] = entity_version

    def _authorize_task(self, current: dict[str, Any] | None, candidate: dict[str, Any], actor: str) -> None:
        if not actor:
            raise ProjectionError("Task actor is missing")
        if current is not None and candidate.get("createdByUserId") != current.get("createdByUserId"):
            raise ProjectionError("Task creator cannot be changed")
        item_occurrence = occurrence(candidate)
        if current is None and candidate.get("completedAt") is not None:
            if item_occurrence is None:
                raise ProjectionError("A new task cannot already be completed")
            parent = self.chores.get(item_occurrence.get("parentTaskId"))
            occurrence_key = (parent or {}).get("dueAt") or (parent or {}).get("updatedAt")
            expected_ids = {
                f"task-occurrence-{(parent or {}).get('id')}-{occurrence_key}",
                f"chore-occurrence-{(parent or {}).get('id')}-{occurrence_key}",
            }
            if (
                parent is None
                or not may_complete(parent, actor)
                or not parent.get("recurrence")
                or item_occurrence.get("recurrence") != str(parent["recurrence"]).lower()
                or candidate["id"] not in expected_ids
                or candidate.get("createdByUserId") != parent.get("createdByUserId")
                or candidate.get("completedByUserId") != actor
                or assignees(parent) != assignees(candidate)
            ):
                raise ProjectionError("Recurring completion is not authorized")
            return
        if current is None and candidate.get("createdByUserId") != actor:
            raise ProjectionError("A new task must name its authenticated creator")
        completion_changed = current is not None and (
            current.get("completedAt") != candidate.get("completedAt")
            or current.get("completedByUserId") != candidate.get("completedByUserId")
        )
        if completion_changed:
            if (
                not may_complete(current, actor)
                or assignees(current) != assignees(candidate)
                or (current.get("completedAt") is not None and candidate.get("completedAt") is not None)
            ):
                raise ProjectionError("Task completion is not authorized")
            if candidate.get("completedAt") is not None and candidate.get("completedByUserId") != actor:
                raise ProjectionError("Task completer does not match the sender")
        if candidate.get("completedAt") is None and candidate.get("completedByUserId") is not None:
            raise ProjectionError("Incomplete task has a completer")

    def finish_snapshot_visibility(self) -> None:
        visible = {
            identifier for identifier, item in self.shopping_lists.items() if self._list_visible(item, self.user_id)
        }
        self.hidden_lists = sorted((set(self.hidden_lists) | (set(self.shopping_lists) - visible)) - visible)
        self.shopping_lists = {key: value for key, value in self.shopping_lists.items() if key in visible}
        self.groceries = {
            key: value
            for key, value in self.groceries.items()
            if not value.get("shoppingListId") or value.get("shoppingListId") in visible
        }
        self.snapshot_mode = False

    def require_writer(self) -> None:
        if self.role.lower() not in {"owner", "administrator", "member"}:
            raise PermissionDenied("This Pack is read only")

    def grocery_visible(self, item: dict[str, Any]) -> bool:
        list_id = item.get("shoppingListId")
        if not list_id:
            return True
        parent = self.shopping_lists.get(list_id)
        return parent is not None and self._list_visible(parent, self.user_id)

    @staticmethod
    def _list_visible(parent: dict[str, Any], user_id: str) -> bool:
        if parent.get("deletedAt") is not None:
            return False
        if parent.get("ownerUserId") == user_id:
            return True
        mode = str(parent.get("shareMode", "PRIVATE")).upper()
        if mode == "PACK":
            return True
        values = parent.get("sharedWithJson", "[]")
        values = json.loads(values) if isinstance(values, str) else values
        return mode == "SELECTED" and isinstance(values, list) and user_id in values

    def task_changes(
        self, identifier: str, changes: dict[str, Any], now_ms: int, time_zone: str = "UTC"
    ) -> list[dict[str, Any]]:
        self.require_writer()
        current = self.chores.get(identifier)
        if current is None:
            raise ProjectionError("Task no longer exists")
        if occurrence(current) is not None:
            raise PermissionDenied("Completed recurring occurrences are kept as history")
        if not set(changes) <= {"title", "dueAt", "completed", "assignees"}:
            raise ProjectionError("Unsupported task change")
        next_item = deepcopy(current)
        completing = changes.get("completed")
        if completing is not None and not isinstance(completing, bool):
            raise ProjectionError("Completion must be true or false")
        if completing is not None:
            if not may_complete(current, self.user_id):
                raise PermissionDenied("Only an assignee can complete this task")
            if "assignees" in changes:
                raise PermissionDenied("Assign and complete the task as separate actions")
            if bool(current.get("completedAt")) == completing and len(changes) == 1:
                return []
            if completing and current.get("recurrence"):
                if len(changes) != 1:
                    raise ProjectionError("Complete recurring tasks separately from other edits")
                if current.get("dueAt") is None:
                    # Give an undated recurring task a stable shared occurrence key
                    # before the canonical occurrence/advance pair is sent.
                    normalized = deepcopy(current)
                    normalized.update(dueAt=now_ms, updatedAt=now_ms)
                    temporary = PackState.restore(self.export(), self.pack_id, self.user_id)
                    temporary.chores[identifier] = normalized
                    return [normalized, *temporary.task_changes(identifier, changes, now_ms, time_zone)]
                next_due, next_reminder = recurring_advance(current, now_ms, time_zone)
                occurrence_key = current.get("dueAt") or current["updatedAt"]
                prefix = "chore" if "dedicated_chore" in str(current.get("historyJson", "")).lower() else "task"
                completed = deepcopy(current)
                completed.update(
                    id=f"{prefix}-occurrence-{identifier}-{occurrence_key}",
                    completedAt=now_ms,
                    completedByUserId=self.user_id,
                    recurrence=None,
                    createdAt=now_ms,
                    updatedAt=now_ms,
                )
                completed["historyJson"] = _history_json(
                    [
                        {
                            "kind": OCCURRENCE_KIND,
                            "parentTaskId": identifier,
                            "recurrence": current["recurrence"],
                            "scheduledDueAt": current.get("dueAt"),
                            "scheduledReminderAt": current.get("reminderAt"),
                            "nextDueAt": next_due,
                            "nextReminderAt": next_reminder,
                        },
                        {"kind": ASSIGNEES_KIND, "userIds": sorted(assignees(current))},
                    ]
                )
                next_item.update(
                    dueAt=next_due, reminderAt=next_reminder, completedAt=None, completedByUserId=None, updatedAt=now_ms
                )
                return [completed, next_item]
            rows = history(current)
            rows.append(
                {
                    "completedAt": current.get("completedAt"),
                    "completedByUserId": current.get("completedByUserId"),
                    "at": now_ms,
                }
            )
            next_item.update(
                completedAt=now_ms if completing else None,
                completedByUserId=self.user_id if completing else None,
                reminderAt=None if completing else current.get("reminderAt"),
                historyJson=_history_json(rows),
            )
        if "title" in changes:
            title = changes["title"]
            if not isinstance(title, str) or not title.strip() or len(title) > 500:
                raise ProjectionError("Enter a task name")
            next_item["title"] = title.strip()
        if "dueAt" in changes:
            due = changes["dueAt"]
            if due is not None and (type(due) is not int or due < 0):
                raise ProjectionError("Invalid task due date")
            next_item["dueAt"] = due
        if "assignees" in changes:
            if current.get("completedAt") is not None:
                raise PermissionDenied("Reopen the task before changing its assignment")
            values = changes["assignees"]
            if (
                not isinstance(values, list)
                or len(values) > 100
                or any(not isinstance(v, str) or not v or len(v) > 128 for v in values)
            ):
                raise ProjectionError("Choose current Pack members")
            rows = [row for row in history(current) if not isinstance(row, dict) or row.get("kind") != ASSIGNEES_KIND]
            selected = sorted(set(values))
            rows.append({"kind": ASSIGNEES_KIND, "userIds": selected})
            next_item.update(
                assigneeUserId=selected[0] if selected else None,
                assignmentMode="MEMBER" if selected else "UNASSIGNED",
                claimedByUserId=None,
                historyJson=_history_json(rows),
            )
        next_item["updatedAt"] = now_ms
        return [next_item]

    def grocery_change(self, identifier: str, changes: dict[str, Any], now_ms: int) -> dict[str, Any]:
        self.require_writer()
        current = self.groceries.get(identifier)
        if current is None or not self.grocery_visible(current):
            raise ProjectionError("Grocery item is not available")
        if not set(changes) <= {"name", "quantity", "checked"}:
            raise ProjectionError("Unsupported grocery change")
        result = deepcopy(current)
        if "checked" in changes:
            checked = changes["checked"]
            if not isinstance(checked, bool):
                raise ProjectionError("Purchased must be true or false")
            claimant = current.get("claimedByUserId")
            if claimant and claimant != self.user_id:
                raise PermissionDenied("This item is assigned to another member")
            rows = history(current)
            rows.append(
                {
                    "checked": bool(current.get("checked")),
                    "purchasedAt": current.get("purchasedAt"),
                    "purchasedByUserId": current.get("purchasedByUserId"),
                    "at": now_ms,
                }
            )
            result.update(
                checked=checked,
                purchasedAt=now_ms if checked else None,
                purchasedByUserId=self.user_id if checked else None,
                historyJson=_history_json(rows),
            )
        if "name" in changes:
            name = changes["name"]
            if not isinstance(name, str) or not name.strip() or len(name) > 500:
                raise ProjectionError("Enter an item name")
            result["name"] = name.strip()
        if "quantity" in changes:
            quantity = changes["quantity"]
            if quantity is not None and (not isinstance(quantity, str) or len(quantity) > 100):
                raise ProjectionError("Invalid quantity")
            result["quantity"] = quantity
        result["updatedAt"] = now_ms
        return result


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"
