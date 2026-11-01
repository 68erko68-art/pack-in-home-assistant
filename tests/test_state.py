"""Canonical task ownership, history, shopping visibility and recurrence."""

import json
from copy import deepcopy
from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

import packin_pure.state as state

NOW = 1793568000000


def chore(assigned=()):
    rows = [{"kind": state.ASSIGNEES_KIND, "userIds": list(assigned)}]
    return {
        "id": "task1",
        "title": "Wash pillows",
        "createdByUserId": "owner",
        "assignmentMode": "MEMBER" if assigned else "UNASSIGNED",
        "assigneeUserId": assigned[0] if assigned else None,
        "completedAt": None,
        "completedByUserId": None,
        "dueAt": NOW - 1000,
        "reminderAt": NOW - 60000,
        "recurrence": None,
        "historyJson": json.dumps(rows),
        "createdAt": NOW - 100000,
        "updatedAt": NOW - 1000,
        "futureField": {"preserve": ["all", "metadata"]},
    }


def pack(task=None, user="member", role="member"):
    p = state.PackState("pack1", user, role)
    if task is not None:
        p.chores[task["id"]] = deepcopy(task)
    return p


@pytest.mark.parametrize(
    "assigned,user,allowed",
    [
        ((), "member", True),
        (("member",), "member", True),
        (("member", "other"), "member", True),
        (("other",), "member", False),
        (("other",), "owner", False),
    ],
)
def test_completion_ownership(assigned, user, allowed):
    p = pack(chore(assigned), user=user)
    if allowed:
        result = p.task_changes("task1", {"completed": True}, NOW)[0]
        assert result["completedAt"] == NOW
        assert result["completedByUserId"] == user
        assert state.assignees(result) == set(assigned)
        assert result["futureField"] == {"preserve": ["all", "metadata"]}
    else:
        with pytest.raises(state.PermissionDenied):
            p.task_changes("task1", {"completed": True}, NOW)


def test_one_shared_completion():
    p = pack(chore(("member", "other")))
    completed = p.task_changes("task1", {"completed": True}, NOW)[0]
    p.apply("chore.upserted", completed, "member", NOW)
    p.user_id = "other"
    assert p.task_changes("task1", {"completed": True}, NOW + 1) == []


def test_completion_cannot_be_hidden_in_reassignment():
    p = pack(chore(("other",)))
    with pytest.raises(state.PermissionDenied):
        p.task_changes("task1", {"assignees": ["member"], "completed": True}, NOW)


def test_assignment_preserves_existing_history():
    original = chore()
    history = json.loads(original["historyJson"])
    history.insert(0, {"kind": "custom_category", "value": "Bathroom"})
    original["historyJson"] = json.dumps(history)
    p = pack(original)
    changed = p.task_changes("task1", {"assignees": ["member", "other"]}, NOW)[0]
    assert json.loads(changed["historyJson"])[0] == history[0]
    assert state.assignees(changed) == {"member", "other"}
    assert changed["completedAt"] is None


def test_title_edit_keeps_reminder_assignments_and_future_metadata():
    p = pack(chore(("member", "other")))
    original = deepcopy(p.chores["task1"])
    changed = p.task_changes("task1", {"title": "Fresh title"}, NOW)[0]
    for key, value in original.items():
        if key not in {"title", "updatedAt"}:
            assert changed[key] == value
    assert p.chores["task1"] == original


def test_incoming_forged_completion_rejected():
    p = pack(chore(("other",)))
    candidate = {**chore(("other",)), "completedAt": NOW, "completedByUserId": "member"}
    with pytest.raises(state.ProjectionError):
        p.apply("chore.upserted", candidate, "member", NOW)
    assert p.chores["task1"]["completedAt"] is None


def test_incoming_cannot_change_creator():
    p = pack(chore())
    with pytest.raises(state.ProjectionError):
        p.apply("chore.upserted", {"id": "task1", "createdByUserId": "attacker"}, "member", NOW)


def test_historical_completion_uses_canonical_permission_cutover():
    p = pack()
    candidate = {**chore(), "completedAt": 1793000000000, "completedByUserId": "old-member"}
    p.apply("chore.upserted", candidate, "old-member", 1793000000000)
    assert p.chores["task1"]["completedByUserId"] == "old-member"


def test_recurring_task_creates_occurrence_and_advances_parent():
    original = chore(("member",))
    original["recurrence"] = "weekly"
    p = pack(original)
    completed, next_task = p.task_changes("task1", {"completed": True}, NOW, "Atlantic/Reykjavik")
    assert completed["id"].startswith("task-occurrence-task1-")
    assert state.occurrence(completed)["parentTaskId"] == "task1"
    assert next_task["completedAt"] is None
    assert next_task["dueAt"] > NOW
    assert next_task["futureField"] == original["futureField"]
    p.apply("chore.upserted", completed, "member", NOW)
    p.apply("chore.upserted", next_task, "member", NOW)
    assert len(p.chores) == 2


def test_recurring_month_end_matches_java_plus_months():
    due = int(datetime(2026, 1, 31, 9, tzinfo=ZoneInfo("UTC")).timestamp() * 1000)
    p = pack({**chore(), "dueAt": due, "recurrence": "monthly"})
    _, next_task = p.task_changes("task1", {"completed": True}, due + 1000)
    expected = int(datetime(2026, 2, 28, 9, tzinfo=ZoneInfo("UTC")).timestamp() * 1000)
    assert next_task["dueAt"] == expected


def test_recurring_dst_preserves_local_clock():
    due = int(datetime(2026, 10, 24, 9, tzinfo=ZoneInfo("Europe/Prague")).timestamp() * 1000)
    p = pack({**chore(), "dueAt": due, "recurrence": "daily"})
    _, next_task = p.task_changes("task1", {"completed": True}, due + 1000, "Europe/Prague")
    actual = datetime.fromtimestamp(next_task["dueAt"] / 1000, ZoneInfo("Europe/Prague"))
    assert actual.hour == 9 and actual.day == 25
    assert next_task["dueAt"] - due == 25 * 3600 * 1000


def test_task_reopen_keeps_completion_history():
    original = {**chore(("member",)), "completedAt": NOW - 1, "completedByUserId": "member"}
    p = pack(original)
    result = p.task_changes("task1", {"completed": False}, NOW)[0]
    assert result["completedAt"] is None
    assert result["completedByUserId"] is None
    assert json.loads(result["historyJson"])[-1]["completedAt"] == NOW - 1


@pytest.mark.parametrize("role", ["read_only", "removed", "unknown"])
def test_non_writer_cannot_mutate(role):
    p = pack(chore(), role=role)
    with pytest.raises(state.PermissionDenied):
        p.task_changes("task1", {"title": "Changed"}, NOW)


def shopping(p):
    p.apply(
        "shopping.list.upserted",
        {"id": "list1", "ownerUserId": "owner", "shareMode": "PACK", "sharedWithJson": "[]", "title": "Groceries"},
        "owner",
        NOW,
    )
    p.apply(
        "grocery.item.upserted",
        {
            "id": "milk",
            "name": "Milk",
            "quantity": "2 L",
            "checked": False,
            "shoppingListId": "list1",
            "groupName": "Dairy",
            "historyJson": "[]",
            "future": {"keep": True},
        },
        "owner",
        NOW,
    )


def test_grocery_purchased_preserves_quantity_and_metadata():
    p = pack()
    shopping(p)
    result = p.grocery_change("milk", {"checked": True}, NOW + 1)
    assert result["quantity"] == "2 L"
    assert result["shoppingListId"] == "list1"
    assert result["future"] == {"keep": True}
    assert result["purchasedByUserId"] == "member"
    p.apply("grocery.item.upserted", result, "member", NOW + 1)
    result = p.grocery_change("milk", {"checked": False}, NOW + 2)
    assert result["purchasedAt"] is None
    assert json.loads(result["historyJson"])[-1]["purchasedByUserId"] == "member"
    assert len(p.groceries) == 1


def test_other_member_claim_cannot_be_completed():
    p = pack()
    shopping(p)
    p.groceries["milk"]["claimedByUserId"] = "other"
    with pytest.raises(state.PermissionDenied):
        p.grocery_change("milk", {"checked": True}, NOW + 1)


def test_sharing_removal_purges_active_private_items():
    p = pack()
    shopping(p)
    p.apply("shopping.list.upserted", {"id": "list1", "shareMode": "PRIVATE"}, "owner", NOW + 1)
    assert "list1" not in p.shopping_lists
    assert "milk" not in p.groceries


def test_only_owner_can_change_shopping_visibility():
    p = pack()
    shopping(p)
    with pytest.raises(state.ProjectionError):
        p.apply("shopping.list.upserted", {"id": "list1", "shareMode": "PRIVATE"}, "member", NOW + 1)


def test_selected_list_hidden_from_unselected_member():
    p = pack()
    p.apply(
        "shopping.list.upserted",
        {"id": "list1", "ownerUserId": "owner", "shareMode": "SELECTED", "sharedWithJson": '["other"]'},
        "owner",
        NOW,
    )
    assert not p.shopping_lists


def test_private_grocery_cannot_be_injected_without_parent():
    p = pack()
    with pytest.raises(state.ProjectionError):
        p.apply("grocery.item.upserted", {"id": "milk", "shoppingListId": "missing"}, "owner", NOW)


def test_legacy_event_does_not_invent_domain_revision():
    p = pack()
    p.apply(
        "chore.upserted", chore(), "owner", NOW, entity_type="legacy_envelope", entity_id="legacy1", entity_version=1
    )
    assert p.revisions == {}
    p.apply(
        "chore.upserted",
        {"id": "task1", "title": "Changed"},
        "member",
        NOW,
        entity_type="chore",
        entity_id=state.descriptor("chore.upserted", {"id": "task1"})[1],
        entity_version=2,
    )
    assert p.revisions["chore:" + state.descriptor("chore.upserted", {"id": "task1"})[1]] == 2


def test_authoritative_later_recreation_is_not_blocked_by_an_old_device_clock():
    p = pack(chore())
    p.apply("chore.removed", {"id": "task1", "removedAt": NOW}, "member", NOW)
    p.apply("chore.upserted", chore(), "owner", NOW + 1)
    assert p.chores["task1"]["updatedAt"] == NOW + 1
    assert p.chores["task1"]["title"] == "Wash pillows"


def test_cache_cannot_cross_pack_or_account():
    p = pack(chore())
    assert state.PackState.restore(p.export(), "pack1", "member").chores == p.chores
    with pytest.raises(state.ProjectionError):
        state.PackState.restore(p.export(), "other-pack", "member")
    with pytest.raises(state.ProjectionError):
        state.PackState.restore(p.export(), "pack1", "other-member")


def test_wire_identity_is_the_canonical_android_hash():
    import hashlib

    expected = "v3_" + hashlib.sha256(b"entity:chore:task1").hexdigest()[:48]
    assert state.descriptor("chore.upserted", {"id": "task1"}) == ("chore", expected, "UPSERT")
    p = pack(chore())
    with pytest.raises(state.ProjectionError):
        p.apply(
            "chore.upserted",
            {"id": "task1"},
            "member",
            NOW,
            entity_type="chore",
            entity_id="wrong-wire-id",
            entity_version=1,
        )


def test_calendar_override_and_series_split_do_not_require_outer_id():
    p = pack()
    base = {
        "id": "event1",
        "seriesId": "event1",
        "title": "School",
        "startsAt": NOW,
        "status": "ACTIVE",
        "excludedDates": ["2026-11-02"],
    }
    p.apply("calendar.event.upserted", base, "owner", NOW)
    p.apply(
        "calendar.event.override.upserted",
        {"seriesEventId": "event1", "occurrenceDate": "2026-11-02", "status": "CANCELLED", "replacement": None},
        "owner",
        NOW + 1,
    )
    assert "event1:2026-11-02" in p.calendar_overrides
    p.apply(
        "calendar.event.restored",
        {"seriesEventId": "event1", "occurrenceDate": "2026-11-02", "status": "ACTIVE", "replacement": None},
        "owner",
        NOW + 2,
    )
    assert not p.calendar_overrides
    assert p.calendar["event1"]["excludedDates"] == []
    p.apply(
        "calendar.event.series.split",
        {
            "original": {**base, "recurrence": {"until": "2026-11-01"}},
            "future": {**base, "id": "event2", "seriesId": "event2"},
        },
        "owner",
        NOW + 3,
    )
    assert set(p.calendar) == {"event1", "event2"}


def test_calendar_removal_retains_metadata_for_restore():
    p = pack()
    p.apply(
        "calendar.event.upserted",
        {
            "id": "event1",
            "title": "Family",
            "startsAt": NOW,
            "notes": "Keep these notes",
            "future": {"preserved": True},
        },
        "owner",
        NOW,
    )
    p.apply("calendar.event.removed", {"id": "event1", "removedAt": NOW + 1}, "member", NOW + 1)
    assert p.calendar["event1"]["status"] == "REMOVED"
    p.apply("calendar.event.restored", {"id": "event1"}, "owner", NOW + 2)
    assert p.calendar["event1"]["status"] == "ACTIVE"
    assert p.calendar["event1"]["notes"] == "Keep these notes"


def test_task_creator_and_occurrence_identity_cannot_be_forged():
    p = pack()
    with pytest.raises(state.ProjectionError):
        p.apply("chore.upserted", chore(), "attacker", NOW)
    parent = {**chore(("member",)), "recurrence": "weekly"}
    p.chores["task1"] = parent
    completed = p.task_changes("task1", {"completed": True}, NOW)[0]
    with pytest.raises(state.ProjectionError):
        p.apply("chore.upserted", {**completed, "id": "forged-occurrence"}, "member", NOW)


def test_undated_recurring_completion_normalizes_one_stable_shared_due_date():
    p = pack({**chore(("member",)), "dueAt": None, "recurrence": "daily"})
    normalized, completed, advanced = p.task_changes("task1", {"completed": True}, NOW)
    assert normalized["dueAt"] == NOW
    assert completed["id"] == f"task-occurrence-task1-{NOW}"
    p.apply("chore.upserted", normalized, "member", NOW)
    p.apply("chore.upserted", completed, "member", NOW)
    p.apply("chore.upserted", advanced, "member", NOW)
    assert p.chores["task1"]["dueAt"] > NOW


def test_snapshot_replay_uses_final_list_visibility_without_losing_previously_private_items():
    p = pack()
    p.snapshot_mode = True
    p.apply("shopping.list.upserted", {"id": "list1", "ownerUserId": "owner", "shareMode": "PRIVATE"}, "owner", NOW)
    p.apply("grocery.item.upserted", {"id": "milk", "shoppingListId": "list1", "name": "Milk"}, "owner", NOW + 1)
    p.apply("shopping.list.upserted", {"id": "list1", "shareMode": "PACK"}, "owner", NOW + 2)
    p.finish_snapshot_visibility()
    assert p.groceries["milk"]["name"] == "Milk"
    assert not p.snapshot_mode
    p.apply("shopping.list.upserted", {"id": "list1", "shareMode": "PRIVATE"}, "owner", NOW + 3)
    assert not p.groceries and not p.shopping_lists
    assert p.hidden_lists == ["list1"]


def test_snapshot_never_commits_a_currently_private_list():
    p = pack()
    p.snapshot_mode = True
    p.apply("shopping.list.upserted", {"id": "private", "ownerUserId": "owner", "shareMode": "PRIVATE"}, "owner", NOW)
    p.apply(
        "grocery.item.upserted", {"id": "secret", "shoppingListId": "private", "name": "Private item"}, "owner", NOW + 1
    )
    p.finish_snapshot_visibility()
    assert p.groceries == {} and p.shopping_lists == {}
