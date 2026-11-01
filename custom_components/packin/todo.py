"""Native Home Assistant to-do lists backed entirely by local Pack state."""

from __future__ import annotations

from datetime import date, datetime, time, timezone
from typing import Any

from homeassistant.components.todo import TodoItem, TodoItemStatus, TodoListEntity, TodoListEntityFeature
from homeassistant.core import callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.util import dt as dt_util

from .api import PackInApiError
from .client import ActionPending, Conflict
from .entity import PackEntity
from .state import assignees, may_complete, occurrence, PermissionDenied, ProjectionError

PARALLEL_UPDATES = 0


async def async_setup_entry(hass, entry, async_add_entities) -> None:
    coordinator = entry.runtime_data
    scopes = coordinator.client.api.data.get("scopes", [])
    entities = []
    if "tasks:read" in scopes:
        entities.extend([PackTodo(coordinator, "chores"), PackTodo(coordinator, "pack_chores")])
    if "groceries:read" in scopes:
        entities.append(PackTodo(coordinator, "groceries"))
    async_add_entities(entities)


def due_ms(value: date | datetime | None) -> int | None:
    if value is None:
        return None
    stamp = value if isinstance(value, datetime) else datetime.combine(value, time.min)
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=dt_util.DEFAULT_TIME_ZONE)
    return int(stamp.timestamp() * 1000)


class PackTodo(PackEntity, TodoListEntity):
    def __init__(self, coordinator, category: str) -> None:
        names = {"chores": "Your chores", "pack_chores": "Pack chores", "groceries": "Groceries"}
        super().__init__(coordinator, category, names[category])
        self.category = category
        self._attr_icon = "mdi:cart-outline" if category == "groceries" else "mdi:clipboard-check-outline"
        self._attr_entity_registry_enabled_default = category != "pack_chores"
        scope = "groceries:write" if category == "groceries" else "tasks:write"
        self._attr_supported_features = TodoListEntityFeature(0)
        if category != "pack_chores" and scope in self.client.api.data.get("scopes", []):
            self._attr_supported_features = (
                TodoListEntityFeature.CREATE_TODO_ITEM
                | TodoListEntityFeature.UPDATE_TODO_ITEM
                | TodoListEntityFeature.DELETE_TODO_ITEM
            )
            if category == "chores":
                self._attr_supported_features |= (
                    TodoListEntityFeature.SET_DUE_DATE_ON_ITEM | TodoListEntityFeature.SET_DUE_DATETIME_ON_ITEM
                )
        self._rebuild()

    def _member_name(self, identifier: str | None) -> str:
        return next(
            (
                m.get("displayName") or "Pack member"
                for m in self.client.api.data.get("members", [])
                if m.get("userId") == identifier
            ),
            "Pack member",
        )

    @callback
    def _rebuild(self) -> None:
        items = []
        records = self.client.state.groceries if self.category == "groceries" else self.client.state.chores
        for identifier, item in records.items():
            if self.category == "groceries" and not self.client.state.grocery_visible(item):
                continue
            if self.category == "chores" and (
                not may_complete(item, self.client.state.user_id) or occurrence(item) is not None
            ):
                continue
            completed = item.get("checked") if self.category == "groceries" else item.get("completedAt") is not None
            details = []
            if self.category == "groceries":
                if item.get("quantity"):
                    details.append("Quantity: " + item["quantity"])
                if item.get("groupName"):
                    details.append("Group: " + item["groupName"])
                if item.get("claimedByUserId"):
                    details.append("Assigned: " + self._member_name(item["claimedByUserId"]))
                if item.get("purchasedByUserId"):
                    details.append("Bought by: " + self._member_name(item["purchasedByUserId"]))
            else:
                assigned = sorted(assignees(item))
                details.append(
                    "Assigned: " + (", ".join(self._member_name(x) for x in assigned) if assigned else "Anyone")
                )
                if item.get("completedByUserId"):
                    details.append("Completed by: " + self._member_name(item["completedByUserId"]))
                if item.get("recurrence"):
                    details.append("Repeats: " + str(item["recurrence"]))
            due = item.get("dueAt") if self.category != "groceries" else None
            stamp = item.get("purchasedAt") if self.category == "groceries" else item.get("completedAt")
            items.append(
                TodoItem(
                    uid=identifier,
                    summary=item.get("name" if self.category == "groceries" else "title", ""),
                    status=TodoItemStatus.COMPLETED if completed else TodoItemStatus.NEEDS_ACTION,
                    due=datetime.fromtimestamp(due / 1000, timezone.utc) if due is not None else None,
                    description="\n".join(details) or None,
                    completed=datetime.fromtimestamp(stamp / 1000, timezone.utc) if stamp else None,
                )
            )
        self._attr_todo_items = sorted(
            items,
            key=lambda item: (
                item.status == TodoItemStatus.COMPLETED,
                item.due.timestamp() if isinstance(item.due, datetime) else float("inf"),
                (item.summary or "").casefold(),
                item.uid or "",
            ),
        )

    @callback
    def _handle_coordinator_update(self) -> None:
        self._rebuild()
        super()._handle_coordinator_update()

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self._handle_coordinator_update()

    async def _action(self, awaitable) -> Any:
        try:
            return await awaitable
        except (ActionPending, Conflict, PermissionDenied, ProjectionError, PackInApiError) as exc:
            raise HomeAssistantError(str(exc)) from None

    async def async_create_todo_item(self, item: TodoItem) -> None:
        if self.category == "pack_chores":
            raise HomeAssistantError("Use Your chores to add work")
        if item.status not in {None, TodoItemStatus.NEEDS_ACTION}:
            raise HomeAssistantError("Create an unfinished item first")
        if self.category == "groceries":
            await self._action(self.client.add_grocery(item.summary or ""))
        else:
            await self._action(self.client.add_task(item.summary or "", due_ms(item.due)))

    async def async_update_todo_item(self, item: TodoItem) -> None:
        if self.category == "pack_chores":
            raise HomeAssistantError("Pack chores is read only")
        records = self.client.state.groceries if self.category == "groceries" else self.client.state.chores
        current = records.get(item.uid)
        if current is None:
            raise HomeAssistantError("This item no longer exists")
        changes = {}
        name = "name" if self.category == "groceries" else "title"
        if item.summary is not None and item.summary != current.get(name):
            changes[name] = item.summary
        if self.category == "chores" and due_ms(item.due) != current.get("dueAt"):
            changes["dueAt"] = due_ms(item.due)
        if item.status is not None:
            done = item.status == TodoItemStatus.COMPLETED
            prior = (
                bool(current.get("checked")) if self.category == "groceries" else current.get("completedAt") is not None
            )
            if done != prior:
                changes["checked" if self.category == "groceries" else "completed"] = done
        if changes:
            await self._action(
                self.client.update_grocery(item.uid, changes)
                if self.category == "groceries"
                else self.client.update_task(item.uid, changes)
            )

    async def async_delete_todo_items(self, uids: list[str]) -> None:
        if self.category == "pack_chores":
            raise HomeAssistantError("Pack chores is read only")
        for identifier in uids:
            await self._action(
                self.client.remove_item("grocery" if self.category == "groceries" else "task", identifier)
            )
