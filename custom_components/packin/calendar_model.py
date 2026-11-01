"""Read-only calendar projection matching Pack-In's canonical local-date rules."""

from __future__ import annotations

import calendar
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
import json
from typing import Any
from zoneinfo import ZoneInfo

WEEKDAYS = ["MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY", "SATURDAY", "SUNDAY"]


class CalendarModelError(ValueError):
    """Calendar metadata cannot be represented safely."""


@dataclass(frozen=True)
class Occurrence:
    uid: str
    summary: str
    start: date | datetime
    end: date | datetime
    description: str | None


def _object(value: Any, default: Any) -> Any:
    if value is None:
        return default
    return json.loads(value) if isinstance(value, str) else value


def is_occurrence(start: date, day: date, rule: dict[str, Any]) -> bool:
    if day < start:
        return False
    until = rule.get("until")
    if until and day > date.fromisoformat(until):
        return False
    interval = max(1, int(rule.get("interval", 1)))
    frequency = rule.get("frequency", "NONE")
    days = (day - start).days
    if frequency == "NONE":
        return day == start
    if frequency == "DAILY":
        return days % interval == 0
    if frequency == "WEEKLY":
        start_week = start - timedelta(days=start.weekday())
        day_week = day - timedelta(days=day.weekday())
        weeks = (day_week - start_week).days // 7
        valid = rule.get("daysOfWeek") or [WEEKDAYS[start.weekday()]]
        if any(value not in WEEKDAYS for value in valid):
            raise CalendarModelError("Unsupported recurrence day")
        return weeks % interval == 0 and WEEKDAYS[day.weekday()] in valid
    if frequency == "MONTHLY" or (frequency == "CUSTOM" and rule.get("customUnit", "WEEKS") == "MONTHS"):
        months = (day.year - start.year) * 12 + day.month - start.month
        target = min(start.day, calendar.monthrange(day.year, day.month)[1])
        return months % interval == 0 and day.day == target
    if frequency == "CUSTOM":
        unit = rule.get("customUnit", "WEEKS")
        if unit == "DAYS":
            return days % interval == 0
        if unit == "WEEKS":
            return (days // 7) % interval == 0 and day.weekday() == start.weekday()
    raise CalendarModelError("Unsupported calendar recurrence")


def _local_time(day: date, template: datetime, zone: ZoneInfo) -> datetime:
    value = datetime.combine(day, template.timetz().replace(tzinfo=None), zone).replace(fold=0)
    # Java LocalDateTime.atZone shifts nonexistent spring-forward times forward.
    restored = value.astimezone(timezone.utc).astimezone(zone)
    return restored if restored.replace(tzinfo=None) != value.replace(tzinfo=None) else value


def expand_events(
    records: dict[str, dict[str, Any]], overrides: dict[str, dict[str, Any]], range_start: datetime, range_end: datetime
) -> list[Occurrence]:
    if range_start.tzinfo is None or range_end.tzinfo is None or range_end <= range_start:
        raise CalendarModelError("Use a timezone-aware calendar range")
    if range_end - range_start > timedelta(days=3660):
        raise CalendarModelError("Choose a calendar range of ten years or less")
    result: list[Occurrence] = []
    expansion_steps = 0
    for record in records.values():
        if record.get("status", "ACTIVE") != "ACTIVE":
            continue
        try:
            zone = ZoneInfo(record.get("timeZoneId", "UTC"))
            original_start = datetime.fromtimestamp(record["startsAt"] / 1000, zone)
            if type(record.get("allDay", False)) is not bool:
                raise CalendarModelError("Invalid all-day calendar flag")
            all_day = record.get("allDay", False)
            original_end = (
                datetime.fromtimestamp(record["endsAt"] / 1000, zone)
                if record.get("endsAt") is not None
                else original_start + timedelta(days=1 if all_day else 0)
            )
            if original_end < original_start:
                original_end += timedelta(days=1)
            # A timed event with no explicit end is visible at its start.
            if not all_day and original_end == original_start:
                original_end += timedelta(minutes=1)
            duration_days = (original_end.date() - original_start.date()).days
            rule = _object(record.get("recurrence", record.get("recurrenceJson")), {"frequency": "NONE"})
            if not isinstance(rule, dict):
                raise CalendarModelError("Invalid recurrence metadata")
            exclusions = _object(record.get("excludedDates", record.get("excludedDatesJson")), [])
            if not isinstance(exclusions, list) or any(not isinstance(value, str) for value in exclusions):
                raise CalendarModelError("Invalid calendar exclusions")
            excluded = set(exclusions)
            first = max(
                original_start.date(), range_start.astimezone(zone).date() - timedelta(days=max(1, duration_days))
            )
            last = range_end.astimezone(zone).date()
            if rule.get("frequency", "NONE") == "NONE":
                first = last = original_start.date()
            day = first
            while day <= last:
                expansion_steps += 1
                if expansion_steps > 200000:
                    raise CalendarModelError("Choose a smaller calendar range")
                key = str(record.get("seriesId", record["id"])) + ":" + day.isoformat()
                if (
                    is_occurrence(original_start.date(), day, rule)
                    and day.isoformat() not in excluded
                    and key not in overrides
                ):
                    start = _local_time(day, original_start, zone)
                    end = _local_time(day + timedelta(days=duration_days), original_end, zone)
                    if end <= start:
                        end = start + (original_end - original_start)
                    if end > range_start and start < range_end:
                        result.append(
                            Occurrence(
                                uid=record["id"] + ":" + day.isoformat(),
                                summary=str(record.get("title", "")),
                                start=day if all_day else start,
                                end=(day + timedelta(days=max(1, duration_days))) if all_day else end,
                                description=record.get("notes"),
                            )
                        )
                day += timedelta(days=1)
                if len(result) > 10000:
                    raise CalendarModelError("Too many calendar occurrences for this range")
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, CalendarModelError):
                raise
            raise CalendarModelError("Invalid Pack calendar metadata") from exc
    return sorted(result, key=lambda item: (item.start.isoformat(), item.uid))
