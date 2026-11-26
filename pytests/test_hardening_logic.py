"""Schedules, holidays and prices: results that were wrong for particular days, places or sessions."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from grizzle_local import holiday_calendar as hc
from grizzle_local.schedules import charging_allowed, next_change, price_now, zone_active

from .support import make_controller

SERIAL = "GRD-L0000HARD4"
DENVER = ZoneInfo("America/Denver")
SPRING_FORWARD = date(2027, 3, 14)  # 02:00 -> 03:00 in America/Denver
FALL_BACK = date(2027, 11, 7)  # 02:00 -> 01:00


def window(start: str, end: str, **extra) -> dict:
    (sh, sm), (eh, em) = (map(int, value.split(":")) for value in (start, end))
    zone = {"name": f"{start}-{end}", "startHours": sh, "startMinutes": sm, "endHours": eh, "endMinutes": em}
    return {**zone, "days": [], "allDay": False, "isSchedule": True, "scheduleEnabled": True, **extra}


def utc(year, month, day, hour, minute=0) -> datetime:
    return datetime(year, month, day, hour, minute, tzinfo=UTC)


def first_flip_by_scanning(zones, now: datetime, limit_minutes: int = 3 * 24 * 60) -> datetime | None:
    """Ground truth for next_change(): walk real time a minute at a time and watch the state."""
    current = charging_allowed(zones, now, 1) is not None
    instant = now.astimezone(UTC).replace(second=0, microsecond=0)
    for _ in range(limit_minutes):
        instant += timedelta(minutes=1)
        if (charging_allowed(zones, instant.astimezone(now.tzinfo), 1) is not None) != current:
            return instant
    return None


# --- the nights the clocks change ------------------------------------------------------------------


def test_next_change_in_the_hour_that_does_not_exist():
    """02:30 never happens on the spring-forward night; the window really opens at the jump (03:00).
    Wall-clock arithmetic put it at "02:30" in the old offset: half an hour late."""
    zones = [window("02:30", "06:00")]
    now = utc(2027, 3, 14, 8).astimezone(DENVER)  # 01:00 MST
    assert next_change(zones, now, 1).astimezone(UTC) == utc(2027, 3, 14, 9)  # 03:00 MDT, the instant of the jump
    assert next_change([window("02:00", "06:00")], now, 1).astimezone(UTC) == utc(2027, 3, 14, 9)
    assert next_change([window("03:30", "06:00")], now, 1).astimezone(UTC) == utc(2027, 3, 14, 9, 30)


def test_a_window_does_not_pause_when_the_clocks_go_back():
    """01:00-02:00 happens twice. A window from 01:30 switched on, then off for the second
    01:00-01:30, then on again: a RemoteStop and, half an hour later, a RemoteStart."""
    zone = window("01:30", "05:00")
    states = []
    instant = utc(2027, 11, 7, 6)  # 00:00 MDT
    while instant < utc(2027, 11, 7, 13):  # 06:00 MST
        states.append(zone_active(zone, instant.astimezone(DENVER)))
        instant += timedelta(minutes=1)
    flips = [(i, state) for i, state in enumerate(states) if i and state != states[i - 1]]
    assert flips == [(90, True), (360, False)]  # on at the first 01:30 (07:30Z), off at 05:00 MST (12:00Z)

    second_pass = utc(2027, 11, 7, 8, 10).astimezone(DENVER)  # 01:10 for the second time
    assert second_pass.fold == 1 and zone_active(zone, second_pass) is True
    assert next_change([zone], second_pass, 1).astimezone(UTC) == utc(2027, 11, 7, 12)
    # A window that ended during the first pass stays ended.
    assert zone_active(window("20:00", "01:30"), second_pass) is False
    # Prices follow the same reading of the clock.
    rate = {**window("01:30", "05:00"), "isSchedule": False, "priceKW": 0.30}
    assert price_now([rate], second_pass, 0.10) == 0.30


@pytest.mark.parametrize("night", [SPRING_FORWARD, FALL_BACK], ids=["spring-forward", "fall-back"])
@pytest.mark.parametrize(
    "zones",
    [
        [window("02:30", "06:00")],
        [window("01:30", "05:00")],
        [window("01:15", "01:45")],
        [window("23:00", "02:30")],
        [window("00:00", "01:30"), window("03:00", "04:15")],
        [window("02:00", "03:00")],
        [window("22:00", "07:00", days=[0, 6])],
    ],
    ids=lambda zones: "+".join(zone["name"] for zone in zones),
)
def test_next_change_agrees_with_a_minute_by_minute_scan(night, zones):
    start = datetime(night.year, night.month, night.day, tzinfo=UTC) - timedelta(hours=6)
    for step in range(0, 36 * 60, 17):  # a day and a half around the change, at awkward minutes
        now = (start + timedelta(minutes=step)).astimezone(DENVER)
        expected = first_flip_by_scanning(zones, now)
        found = next_change(zones, now, 1)
        assert (found.astimezone(UTC) if found else None) == expected, now.isoformat()


def test_ordinary_days_are_unchanged():
    zone = window("23:00", "07:00")
    now = datetime(2026, 11, 8, 12, tzinfo=DENVER)
    assert next_change([zone], now, 1) == datetime(2026, 11, 8, 23, tzinfo=DENVER)
    assert next_change([zone], datetime(2026, 11, 8, 12), 1) == datetime(2026, 11, 8, 23)  # naive times still work


# --- holidays ----------------------------------------------------------------------------------------


def test_a_moved_holiday_is_not_also_kept_on_its_original_date():
    """Colombia moves Epiphany to the following Monday. With "observed days" on, both the Monday
    and the 6th counted as holidays: nine ordinary working days a year were holidays there."""
    observed = hc.normalize({"enabled": True, "country": "CO", "observed": True})
    assert hc.holiday_name(observed, date(2026, 1, 6)) is None
    assert hc.holiday_name(observed, date(2026, 1, 12)) == "Epiphany (observed)"
    plain = hc.normalize({"enabled": True, "country": "CO", "observed": False})
    assert hc.holiday_name(plain, date(2026, 1, 6)) == "Epiphany"
    assert hc.holiday_name(plain, date(2026, 1, 12)) is None

    import holidays

    library = holidays.country_holidays("CO", years=2026, observed=True)
    ours = {row["date"] for row in hc.upcoming(observed, date(2026, 1, 1), 364)}
    assert ours == {day.isoformat() for day in library}

    # Excluding the holiday by its name still drops the day it is observed on.
    without = hc.normalize({"enabled": True, "country": "CO", "observed": True, "excludedNames": ["Epiphany"]})
    assert hc.holiday_name(without, date(2026, 1, 12)) is None


def test_observed_days_that_are_additions_still_work():
    us = hc.normalize({"enabled": True, "country": "US", "observed": True})
    assert hc.holiday_name(us, date(2026, 7, 4)) == "Independence Day"  # a Saturday...
    assert hc.holiday_name(us, date(2026, 7, 3)) == "Independence Day (observed)"  # ...observed on the Friday too


@pytest.mark.parametrize("key", ["enabled", "observed"])
@pytest.mark.parametrize("value", ["false", "true", "no", [], {}, 2, 0.5])
def test_holiday_switches_must_be_booleans(key, value):
    """bool("false") is True: the string switched the option on."""
    with pytest.raises(ValueError):
        hc.normalize({"country": "US", key: value})


def test_holiday_switches_accept_booleans_and_defaults():
    assert hc.normalize({"enabled": True, "observed": False})["observed"] is False
    assert hc.normalize({"enabled": 1, "observed": 0}) == {**hc.DEFAULTS, "enabled": True, "observed": False}
    assert hc.normalize({})["observed"] is True and hc.normalize({"observed": None})["observed"] is True


def test_next_change_looks_far_enough_ahead_for_holiday_rules():
    """The search stopped after 8 days (120 for holidays-only windows): with the next holiday
    further off than that, the page said no window was coming at all."""
    settings = hc.normalize({"enabled": True, "country": "NL"})

    def is_holiday(day):
        return hc.holiday_name(settings, day) is not None

    upcoming = [row["date"] for row in hc.upcoming(settings, date(2026, 5, 26), 300)]
    assert upcoming[0] == "2026-12-25"  # seven months without a holiday
    amsterdam = ZoneInfo("Europe/Amsterdam")
    only = [{**window("00:00", "00:00"), "allDay": True, "holidays": "only"}]
    now = datetime(2026, 5, 26, 12, tzinfo=amsterdam)
    assert next_change(only, now, 1, is_holiday) == datetime(2026, 12, 25, tzinfo=amsterdam)

    # A Friday-only window that skips holidays, asked on a Good Friday (a public holiday in Great Britain):
    # the window next applies a week later. That was already within reach; it must stay right.
    gb = hc.normalize({"enabled": True, "country": "GB", "subdivision": "ENG"})
    assert hc.holiday_name(gb, date(2026, 4, 3)) is not None
    fridays = [{**window("00:00", "00:00"), "allDay": True, "days": [5], "holidays": "skip"}]
    london = ZoneInfo("Europe/London")
    good_friday_noon = datetime(2026, 4, 3, 12, tzinfo=london)
    found = next_change(fridays, good_friday_noon, 1, lambda d: hc.holiday_name(gb, d) is not None)
    assert found == datetime(2026, 4, 10, tzinfo=london)


# --- current limits across connectors ----------------------------------------------------------------


def test_the_lowest_window_limit_in_force_is_the_one_applied(tmp_path):
    """One profile goes to the whole station. With connector 1 in a 16 A window and connector 2 in
    a 32 A one, whichever connector came last won: 32 A for both."""
    controller = make_controller(tmp_path)
    station = controller._ensure_station(SERIAL)
    station["connectorCount"] = 2
    all_day = {"allDay": True, "days": [], "isSchedule": True, "scheduleEnabled": True}
    station["pricesByZone"] = [
        {**all_day, "_id": "a", "connectorId": 1, "currentLimit": 16},
        {**all_day, "_id": "b", "connectorId": 2, "currentLimit": 32},
    ]
    assert controller.effective_limit(station) == 16
    station["pricesByZone"].reverse()
    assert controller.effective_limit(station) == 16
    # A window's limit still overrides the station's own, in either direction...
    station["currentLimit"] = 8
    assert controller.effective_limit(station) == 16
    # ...and without a window in force the station's limit applies.
    station["pricesByZone"] = []
    assert controller.effective_limit(station) == 8


# --- what a session costs ------------------------------------------------------------------------------


def _reading(wh: float) -> dict:
    sampled = [{"value": str(wh), "measurand": "Energy.Active.Import.Register", "unit": "Wh"}]
    return {"connectorId": 1, "transactionId": 1, "meterValue": [{"sampledValue": sampled}]}


async def test_energy_after_the_last_reading_is_paid_for(tmp_path):
    """Cost only built up with each MeterValues reading. The last stretch of every session, and the
    whole of a session without readings, was recorded with its energy and without its cost; pressing
    "Recalculate" then changed totals although no price had changed."""
    controller = make_controller(tmp_path)
    station = controller._ensure_station(SERIAL)
    await controller.set_base_rate(SERIAL, 0.10)

    await controller._on_StartTransaction(station, {"connectorId": 1, "idTag": "t", "meterStart": 100_000})
    for wh in (100_000, 102_000, 105_000):
        await controller._on_MeterValues(station, _reading(wh))
    await controller._on_StopTransaction(station, {"transactionId": 1, "meterStop": 106_000})
    recorded = controller.store.sessions(SERIAL)[0]
    assert recorded["energy_wh"] == 6000 and recorded["cost"] == pytest.approx(0.60)
    assert recorded["price_kwh"] == pytest.approx(0.10)  # the average the session was charged at
    assert station["connectors"]["1"]["lastSession"]["priceTotal"] == pytest.approx(0.60)

    # No readings at all: the whole session is priced when it ends.
    await controller._on_StartTransaction(station, {"connectorId": 1, "idTag": "t", "meterStart": 106_000})
    await controller._on_StopTransaction(station, {"transactionId": 2, "meterStop": 116_000})
    assert controller.store.sessions(SERIAL)[0]["cost"] == pytest.approx(1.00)

    # ...so recalculating with unchanged prices changes nothing.
    result = await controller.recalculate_costs(SERIAL)
    assert result["cost_before"] == pytest.approx(result["cost_after"]) == pytest.approx(1.60)


async def test_final_readings_in_stop_transaction_belong_to_the_session(tmp_path):
    """transactionData was stored without the session's id, so repricing never saw it. It is still
    kept out of the live total: its begin/end readings may be lifetime values even where the
    session's own readings count from zero."""
    controller = make_controller(tmp_path)
    station = controller._ensure_station(SERIAL)
    await controller.set_base_rate(SERIAL, 0.10)
    await controller._on_StartTransaction(station, {"connectorId": 1, "idTag": "t", "meterStart": 819_392})
    await controller._on_MeterValues(station, _reading(0))
    await controller._on_MeterValues(station, _reading(1500))  # session-relative, like the Duo
    lifetime_end = {"sampledValue": [{"value": "821392", "measurand": "Energy.Active.Import.Register"}]}
    await controller._on_StopTransaction(
        station, {"transactionId": 1, "meterStop": 2000, "transactionData": [lifetime_end]}
    )
    recorded = controller.store.sessions(SERIAL)[0]
    assert recorded["energy_wh"] == 2000 and recorded["cost"] == pytest.approx(0.20)  # not 821 kWh
    rows = controller.store._db.execute("SELECT transaction_id, energy_wh FROM samples ORDER BY rowid").fetchall()
    assert [row[0] for row in rows] == [1, 1, 1]
    result = await controller.recalculate_costs(SERIAL)
    assert result["cost_after"] == pytest.approx(0.20)
