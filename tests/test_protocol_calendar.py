"""Real Android-library vectors and the canonical Kotlin calendar contract."""

from datetime import date, datetime, timezone
import json
from pathlib import Path

import pytest
import packin_pure.crypto as crypto
import packin_pure.protocol as protocol
from packin_pure.calendar_model import CalendarModelError, expand_events, is_occurrence


def vector_frame():
    vector = json.loads((Path(__file__).parent / "fixtures/tink_android.json").read_text(encoding="utf8"))
    context = vector["context"]
    frame = {
        "type": "PACK_EVENT",
        "protocolVersion": 3,
        "syncGeneration": 3,
        "packId": context["pack"],
        "eventId": context["event"],
        "actorDeviceId": context["device"],
        "deviceSequence": context["sequence"],
        "eventType": context["event_type"],
        "keyEpoch": context["epoch"],
        "senderSigningPublicKey": vector["signing_public"],
        "encryptedPayload": crypto.encode64(vector["envelope"].encode()),
        "signature": vector["envelope"].split(".")[-1],
    }
    return vector, frame


def test_decodes_the_actual_android_library_wire_envelope():
    vector, frame = vector_frame()
    result = protocol.decode_event(frame, vector["context"]["pack"], {7: crypto.decode64(vector["pack_key"])})
    assert result["id"] == "synthetic-chore"


def test_live_legacy_metadata_uses_original_device_sequence():
    vector, frame = vector_frame()
    frame.update(
        entityType="legacy_envelope",
        deviceSequence=999,
        encryption={
            "scheme": "packin-legacy-envelope-v1",
            "deviceSequence": 11,
            "senderSigningPublicKey": vector["signing_public"],
            "idempotencyKey": "synthetic",
        },
    )
    assert (
        protocol.decode_event(frame, vector["context"]["pack"], {7: crypto.decode64(vector["pack_key"])})["id"]
        == "synthetic-chore"
    )


def test_wrong_pack_missing_key_and_future_protocol_fail_closed():
    vector, frame = vector_frame()
    with pytest.raises(crypto.CryptoError):
        protocol.decode_event(frame, "another-pack", {7: crypto.decode64(vector["pack_key"])})
    with pytest.raises(protocol.MissingKey) as error:
        protocol.decode_event(frame, vector["context"]["pack"], {})
    assert error.value.epoch == 7
    with pytest.raises(protocol.UnsupportedSchema):
        protocol.decode_event(
            {**frame, "protocolVersion": 4}, vector["context"]["pack"], {7: crypto.decode64(vector["pack_key"])}
        )


def test_plaintext_or_mismatched_signature_metadata_is_never_used():
    vector, frame = vector_frame()
    with pytest.raises((crypto.CryptoError, UnicodeError)):
        protocol.decode_event(
            {**frame, "encryptedPayload": None, "payload": {"title": "untrusted"}},
            vector["context"]["pack"],
            {7: crypto.decode64(vector["pack_key"])},
        )
    with pytest.raises(crypto.CryptoError):
        protocol.decode_event(
            {**frame, "signature": crypto.encode64(b"x" * 70)},
            vector["context"]["pack"],
            {7: crypto.decode64(vector["pack_key"])},
        )


def event(start="2026-10-31T09:00:00+00:00", end="2026-10-31T10:00:00+00:00", **changes):
    def millis(value):
        return int(datetime.fromisoformat(value).timestamp() * 1000)

    return {
        "id": "family-event",
        "seriesId": "family-event",
        "title": "Family plans",
        "startsAt": millis(start),
        "endsAt": millis(end),
        "allDay": False,
        "timeZoneId": "UTC",
        "recurrence": {"frequency": "NONE"},
        "excludedDates": [],
        "status": "ACTIVE",
        "notes": "Bring snacks",
        **changes,
    }


def expand(record, start="2026-10-01T00:00:00+00:00", end="2026-12-01T00:00:00+00:00", overrides=None):
    return expand_events(
        {record["id"]: record}, overrides or {}, datetime.fromisoformat(start), datetime.fromisoformat(end)
    )


def test_calendar_all_day_end_is_exclusive():
    rows = expand(event(start="2026-10-31T00:00:00+00:00", end="2026-11-01T00:00:00+00:00", allDay=True))
    assert rows[0].start == date(2026, 10, 31)
    assert rows[0].end == date(2026, 11, 1)
    assert rows[0].description == "Bring snacks"


def test_calendar_dates_and_notes_remain_stable():
    item = event()
    a, b = expand(item), expand(item, start="2026-10-30T00:00:00+00:00")
    assert a[0].uid == b[0].uid
    assert a[0].start.tzinfo is not None
    assert a[0].description == item["notes"]


@pytest.mark.parametrize("status", ["CANCELLED", "REMOVED"])
def test_cancelled_or_removed_event_is_hidden(status):
    assert expand(event(status=status)) == []


def test_monthly_recurrence_clamps_each_month_from_original_day():
    item = event(
        start="2026-01-31T09:00:00+00:00",
        end="2026-01-31T10:00:00+00:00",
        recurrence={"frequency": "MONTHLY", "interval": 1},
    )
    rows = expand(item, start="2026-01-01T00:00:00+00:00", end="2026-04-01T00:00:00+00:00")
    assert [value.start.date() for value in rows] == [date(2026, 1, 31), date(2026, 2, 28), date(2026, 3, 31)]


def test_weekly_days_until_and_exclusions_match_kotlin():
    item = event(
        start="2026-10-26T09:00:00+00:00",
        end="2026-10-26T10:00:00+00:00",
        recurrence={"frequency": "WEEKLY", "interval": 1, "daysOfWeek": ["MONDAY", "WEDNESDAY"], "until": "2026-11-04"},
        excludedDates=["2026-10-28"],
    )
    rows = expand(item)
    assert [value.start.date() for value in rows] == [date(2026, 10, 26), date(2026, 11, 2), date(2026, 11, 4)]


def test_override_hides_original_and_replacement_is_a_separate_stable_event():
    original = event(recurrence={"frequency": "DAILY"})
    replacement = event(
        id="replacement",
        seriesId="replacement",
        title="Later",
        start="2026-11-01T13:00:00+00:00",
        end="2026-11-01T14:00:00+00:00",
    )
    rows = expand_events(
        {"original": original, "replacement": replacement},
        {"family-event:2026-11-01": {"status": "REPLACED"}},
        datetime(2026, 11, 1, tzinfo=timezone.utc),
        datetime(2026, 11, 2, tzinfo=timezone.utc),
    )
    assert len(rows) == 1 and rows[0].summary == "Later"


def test_dst_transition_keeps_local_start_time():
    item = event(
        start="2026-10-24T07:00:00+00:00",
        end="2026-10-24T08:00:00+00:00",
        timeZoneId="Europe/Prague",
        recurrence={"frequency": "DAILY"},
    )
    rows = expand(item, start="2026-10-24T00:00:00+00:00", end="2026-10-27T00:00:00+00:00")
    assert [value.start.hour for value in rows] == [9, 9, 9]
    assert (
        rows[1].start.astimezone(timezone.utc) - rows[0].start.astimezone(timezone.utc)
    ).total_seconds() == 25 * 3600


def test_spring_gap_matches_java_at_zone_forward_shift():
    item = event(
        start="2026-03-28T01:30:00+00:00",
        end="2026-03-28T02:30:00+00:00",
        timeZoneId="Europe/Prague",
        recurrence={"frequency": "DAILY"},
    )
    rows = expand(item, start="2026-03-28T00:00:00+00:00", end="2026-03-31T00:00:00+00:00")
    assert [value.start.hour for value in rows] == [2, 3, 2]


def test_custom_recurrence_units():
    assert is_occurrence(
        date(2026, 1, 1), date(2026, 1, 5), {"frequency": "CUSTOM", "customUnit": "DAYS", "interval": 2}
    )
    assert not is_occurrence(
        date(2026, 1, 1), date(2026, 1, 8), {"frequency": "CUSTOM", "customUnit": "WEEKS", "interval": 2}
    )
    assert is_occurrence(
        date(2026, 1, 31), date(2026, 3, 31), {"frequency": "CUSTOM", "customUnit": "MONTHS", "interval": 2}
    )


def test_overnight_event_overlapping_range_is_included():
    rows = expand(
        event(start="2026-10-31T23:30:00+00:00", end="2026-11-01T01:00:00+00:00"),
        start="2026-11-01T00:00:00+00:00",
        end="2026-11-02T00:00:00+00:00",
    )
    assert len(rows) == 1


def test_unknown_recurrence_and_unbounded_range_are_explicit_errors():
    with pytest.raises(CalendarModelError):
        expand(event(recurrence={"frequency": "UNSUPPORTED"}))
    with pytest.raises(CalendarModelError):
        expand(event(), start="2026-01-01T00:00:00+00:00", end="2040-01-01T00:00:00+00:00")
