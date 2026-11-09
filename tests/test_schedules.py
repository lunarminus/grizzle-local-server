from datetime import datetime
from zoneinfo import ZoneInfo

from grizzle_local.schedules import charging_allowed, next_change, price_now, zone_active

TZ = ZoneInfo("America/Denver")


def at(y, m, d, hh, mm=0):
    return datetime(y, m, d, hh, mm, tzinfo=TZ)


OFF_PEAK = {
    "_id": "a",
    "name": "Off-peak",
    "startHours": 23,
    "startMinutes": 0,
    "endHours": 7,
    "endMinutes": 0,
    "allDay": False,
    "days": [0, 1, 2, 3, 4, 5, 6],
    "isSchedule": True,
    "scheduleEnabled": True,
    "connectorId": 0,
}
# 2026-11-08 is a Sunday (day 0)
WEEKDAY_MIDDAY = {
    "_id": "b",
    "name": "Midday",
    "startHours": 9,
    "startMinutes": 0,
    "endHours": 17,
    "endMinutes": 0,
    "allDay": False,
    "days": [1, 2, 3, 4, 5],
    "isSchedule": True,
    "scheduleEnabled": True,
    "connectorId": 2,
}


def test_window_crossing_midnight():
    assert zone_active(OFF_PEAK, at(2026, 11, 8, 23, 30))
    assert zone_active(OFF_PEAK, at(2026, 11, 9, 3))
    assert not zone_active(OFF_PEAK, at(2026, 11, 9, 7))
    assert not zone_active(OFF_PEAK, at(2026, 11, 9, 12))


def test_days_and_connector():
    sunday_noon = at(2026, 11, 8, 12)
    monday_noon = at(2026, 11, 9, 12)
    assert charging_allowed([WEEKDAY_MIDDAY], sunday_noon, 2) is None
    assert charging_allowed([WEEKDAY_MIDDAY], monday_noon, 2) is WEEKDAY_MIDDAY
    assert charging_allowed([WEEKDAY_MIDDAY], monday_noon, 1) is None  # zone is for connector 2 only
    disabled = {**WEEKDAY_MIDDAY, "scheduleEnabled": False}
    assert charging_allowed([disabled], monday_noon, 2) is None


def test_next_change():
    assert next_change([OFF_PEAK], at(2026, 11, 8, 12), 1) == at(2026, 11, 8, 23)
    assert next_change([OFF_PEAK], at(2026, 11, 9, 1), 1) == at(2026, 11, 9, 7)
    # Friday 18:00 for a weekday-only window -> Monday 09:00
    assert next_change([WEEKDAY_MIDDAY], at(2026, 11, 13, 18), 2) == at(2026, 11, 16, 9)
    assert next_change([], at(2026, 11, 8, 12), 1) is None


def test_all_day_and_second_range():
    all_day = {
        "startHours": 0,
        "startMinutes": 0,
        "endHours": 0,
        "endMinutes": 0,
        "allDay": True,
        "days": [0],
        "scheduleEnabled": True,
    }
    assert zone_active(all_day, at(2026, 11, 8, 15))
    assert not zone_active(all_day, at(2026, 11, 9, 15))
    winter = {
        "startHours": 9,
        "startMinutes": 0,
        "endHours": 17,
        "endMinutes": 0,
        "startHours2": 20,
        "startMinutes2": 0,
        "endHours2": 6,
        "endMinutes2": 0,
        "priceKW": 0.0923,
        "days": [1, 2, 3, 4, 5, 6],
        "allDay": False,
    }
    assert zone_active(winter, at(2026, 11, 9, 10))
    assert zone_active(winter, at(2026, 11, 9, 22))
    assert zone_active(winter, at(2026, 11, 10, 3))
    assert not zone_active(winter, at(2026, 11, 9, 18))


def test_price_now():
    rate = {
        "startHours": 9,
        "startMinutes": 0,
        "endHours": 17,
        "endMinutes": 0,
        "priceKW": 0.30,
        "days": [1],
        "allDay": False,
    }
    assert price_now([rate, OFF_PEAK], at(2026, 11, 9, 10), 0.10) == 0.30
    assert price_now([rate, OFF_PEAK], at(2026, 11, 9, 20), 0.10) == 0.10


def test_overnight_range_is_judged_per_calendar_day():
    """Reported on a real setup: weekdays 09-17, weekdays 20-06 and Sunday all day.

    "Weekdays 20:00-06:00" means that on a weekday the hours 00:00-06:00 and 20:00-24:00 are in the
    zone, not "starts Monday 20:00 and runs into Tuesday". So Sunday (all day) runs straight on into
    Monday's 00:00-06:00, and Saturday morning is outside every window.
    """

    def z(start, end, days, all_day=False):
        return {
            "startHours": start,
            "startMinutes": 0,
            "endHours": end,
            "endMinutes": 0,
            "allDay": all_day,
            "days": days,
            "scheduleEnabled": True,
            "priceKW": 0.0923,
        }

    weekdays = [1, 2, 3, 4, 5]
    zones = [z(9, 17, weekdays), z(20, 6, weekdays), z(0, 0, [0], all_day=True)]
    # 2026-11-08 is a Sunday
    assert next_change(zones, at(2026, 11, 8, 19, 53), 1) == at(2026, 11, 9, 6)
    assert charging_allowed(zones, at(2026, 11, 9, 3), 1) is zones[1]  # Monday 03:00
    assert charging_allowed(zones, at(2026, 11, 9, 7), 1) is None  # Monday 07:00, between windows
    assert charging_allowed(zones, at(2026, 11, 13, 21), 1) is zones[1]  # Friday 21:00
    assert charging_allowed(zones, at(2026, 11, 14, 3), 1) is None  # Saturday 03:00: Saturday isn't listed
    assert next_change(zones, at(2026, 11, 13, 21), 1) == at(2026, 11, 14, 0)  # Friday evening ends at midnight
    assert next_change(zones, at(2026, 11, 14, 12), 1) == at(2026, 11, 15, 0)  # Saturday -> Sunday 00:00
