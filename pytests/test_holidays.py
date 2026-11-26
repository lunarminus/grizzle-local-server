"""Statutory holidays: the calendar, the per-zone holiday modes, and the API."""

from __future__ import annotations

from datetime import date, datetime
from zoneinfo import ZoneInfo

import pytest
from aiohttp.test_utils import TestClient, TestServer

from grizzle_local import holiday_calendar as hc
from grizzle_local.config import Settings
from grizzle_local.main import create_app
from grizzle_local.schedules import charging_allowed, next_change, price_now, zone_active
from grizzle_local.store import Store

TZ = ZoneInfo("America/Denver")
US = hc.normalize({"enabled": True, "country": "us", "subdivision": "id"})
XMAS = date(2026, 12, 25)  # a Friday


def at(y, m, d, hh, mm=0):
    return datetime(y, m, d, hh, mm, tzinfo=TZ)


def is_holiday(day):
    return hc.holiday_name(US, day) is not None


def zone(**extra):
    base = {
        "startHours": 9,
        "startMinutes": 0,
        "endHours": 17,
        "endMinutes": 0,
        "allDay": False,
        "days": [1, 2, 3, 4, 5],
        "scheduleEnabled": True,
        "isSchedule": True,
        "connectorId": 0,
    }
    return {**base, **extra}


def test_calendar_and_observed_days():
    assert US["country"] == "US" and US["subdivision"] == "ID"
    assert hc.holiday_name(US, XMAS) == "Christmas Day"
    assert hc.holiday_name(US, date(2026, 12, 24)) is None
    # 4 July 2026 is a Saturday: observed on Friday the 3rd
    assert hc.holiday_name(US, date(2026, 7, 3)) == "Independence Day (observed)"
    not_observed = hc.normalize({**US, "observed": False})
    assert hc.holiday_name(not_observed, date(2026, 7, 3)) is None
    assert hc.holiday_name(not_observed, date(2026, 7, 4)) == "Independence Day"


def test_excluding_a_holiday_also_drops_its_observed_day_and_extra_dates_add():
    settings = hc.normalize(
        {**US, "excludedNames": ["Independence Day"], "extraDates": [{"date": "2026-12-24", "name": "Eve"}]}
    )
    assert hc.holiday_name(settings, date(2026, 7, 3)) is None
    assert hc.holiday_name(settings, date(2026, 7, 4)) is None
    assert hc.holiday_name(settings, date(2026, 12, 24)) == "Eve"
    rows = {r["date"]: r for r in hc.upcoming(settings, date(2026, 6, 1), 250)}
    assert rows["2026-07-03"]["included"] is False and rows["2026-07-03"]["key"] == "Independence Day"
    assert rows["2026-12-24"]["custom"] is True and rows["2026-12-25"]["included"] is True


def test_normalize_rejects_bad_input():
    for bad in (
        {"country": "ZZ"},
        {"country": "US", "subdivision": "Narnia"},
        {"priceKW": -1},
        {"extraDates": [{"date": "25/12/2026"}]},
    ):
        with pytest.raises(ValueError):
            hc.normalize(bad)
    assert hc.normalize({"subdivision": "ID"})["subdivision"] is None  # a region needs a country
    codes = {c["code"] for c in hc.countries()}
    assert {"US", "CA", "GB", "DE"} <= codes
    idaho = next(s for c in hc.countries() if c["code"] == "US" for s in c["subdivisions"] if s["code"] == "ID")
    assert idaho["name"] == "Idaho"


def test_holiday_modes():
    noon_xmas, noon_thu = at(2026, 12, 25, 12), at(2026, 12, 24, 12)
    assert zone_active(zone(), noon_xmas, is_holiday)  # default: a holiday is just a Friday
    assert zone_active(zone(holidays="same"), noon_xmas, is_holiday)
    assert not zone_active(zone(holidays="skip"), noon_xmas, is_holiday)
    assert zone_active(zone(holidays="skip"), noon_thu, is_holiday)
    weekend = zone(days=[0, 6], holidays="also")
    assert zone_active(weekend, noon_xmas, is_holiday) and not zone_active(weekend, noon_thu, is_holiday)
    only = zone(days=[], holidays="only", allDay=True)
    assert zone_active(only, noon_xmas, is_holiday) and not zone_active(only, noon_thu, is_holiday)
    # with holidays switched off (no checker) the modes fall back to plain weekdays
    assert zone_active(zone(holidays="skip"), noon_xmas, None)
    assert not zone_active(only, noon_xmas, None)


def test_overnight_window_skips_the_holiday_as_a_calendar_day():
    night = zone(startHours=22, endHours=6, days=[0, 1, 2, 3, 4, 5, 6], holidays="skip")
    assert zone_active(night, at(2026, 12, 24, 23), is_holiday)  # Christmas Eve evening
    assert not zone_active(night, at(2026, 12, 25, 2), is_holiday)  # nothing on the holiday itself…
    assert not zone_active(night, at(2026, 12, 25, 23), is_holiday)
    assert zone_active(night, at(2026, 12, 26, 2), is_holiday)  # …and back to normal the next morning
    only = zone(startHours=22, endHours=6, days=[], holidays="only")
    assert zone_active(only, at(2026, 12, 25, 2), is_holiday) and zone_active(only, at(2026, 12, 25, 23), is_holiday)
    assert not zone_active(only, at(2026, 12, 26, 2), is_holiday)


def test_next_change_and_window_lookup_with_holidays():
    weekday = zone(holidays="skip")
    # Thursday 18:00: tomorrow is Christmas, so the next window opens Monday 09:00
    assert next_change([weekday], at(2026, 12, 24, 18), 1, is_holiday) == at(2026, 12, 28, 9)
    assert next_change([weekday], at(2026, 12, 24, 18), 1, None) == at(2026, 12, 25, 9)
    only = zone(days=[], holidays="only", allDay=True)
    assert charging_allowed([weekday, only], at(2026, 12, 25, 12), 1, is_holiday) is only
    # holidays-only windows are found even when the next holiday is weeks away (Thanksgiving, 26 Nov)
    assert next_change([only], at(2026, 11, 12, 12), 1, is_holiday) == at(2026, 11, 26, 0)


def test_holiday_price_and_rate_zone_modes():
    peak = {
        "priceKW": 0.30,
        "startHours": 9,
        "startMinutes": 0,
        "endHours": 17,
        "endMinutes": 0,
        "days": [1, 2, 3, 4, 5],
        "allDay": False,
        "holidays": "skip",
    }
    assert price_now([peak], at(2026, 12, 24, 12), 0.10, is_holiday) == 0.30
    assert price_now([peak], at(2026, 12, 25, 12), 0.10, is_holiday) == 0.10  # peak skipped on the holiday
    assert (
        price_now([{**peak, "holidays": "same"}], at(2026, 12, 25, 12), 0.10, is_holiday, 0.07) == 0.07
    )  # flat price wins
    assert price_now([peak], at(2026, 12, 24, 12), 0.10, is_holiday, 0.07) == 0.30


async def test_holiday_api(tmp_path):
    settings = Settings(data_dir=tmp_path / "data", api_email="a@b", api_password="x", timezone="America/Denver")
    app = create_app(settings, Store(settings.data_dir))
    app["controller"]._ensure_station("GRD-TEST")
    async with TestServer(app) as server, TestClient(server) as client:
        token = (await (await client.post("/client/auth/login", json={"emailOrPhone": "a@b", "password": "x"})).json())[
            "token"
        ]
        auth = {"Authorization": f"Bearer {token}"}
        assert (await client.get("/local/holidays/countries")).status == 401
        countries = (await (await client.get("/local/holidays/countries", headers=auth)).json())["countries"]
        assert any(c["code"] == "CA" for c in countries)

        data = await (await client.get("/local/stations/GRD-TEST/holidays", headers=auth)).json()
        assert data["settings"]["enabled"] is False and data["upcoming"] == []

        body = {
            "enabled": True,
            "country": "US",
            "subdivision": "ID",
            "excludedNames": ["Columbus Day"],
            "priceKW": 0.07,
        }
        preview = await (await client.post("/local/stations/GRD-TEST/holidays/preview", json=body, headers=auth)).json()
        assert any(r["name"] == "Christmas Day" for r in preview["upcoming"])
        station = await (await client.get("/client/stations/GRD-TEST", headers=auth)).json()
        assert station["holidaysSettings"]["enabled"] is False and station["holidays"] == []  # preview saves nothing

        saved = await (await client.put("/local/stations/GRD-TEST/holidays", json=body, headers=auth)).json()
        assert saved["settings"]["priceKW"] == 0.07
        assert all(r["included"] is False for r in saved["upcoming"] if r["key"] == "Columbus Day")
        station = await (await client.get("/client/stations/GRD-TEST", headers=auth)).json()
        names = [h["name"] for h in station["holidays"]]
        assert "Christmas Day" in names and "Columbus Day" not in names
        assert station["holidaysSettings"]["country"] == "US" and "holidayToday" in station

        bad = await client.put("/local/stations/GRD-TEST/holidays", json={"country": "ZZ"}, headers=auth)
        assert bad.status == 400
        zone_bad = await client.post(
            "/client/stations/GRD-TEST/scheduleUpdate",
            headers=auth,
            json={"price": {"name": "x", "days": [1], "holidays": "sometimes"}},
        )
        assert zone_bad.status == 400
        zone_ok = await client.post(
            "/client/stations/GRD-TEST/scheduleUpdate",
            headers=auth,
            json={"price": {"name": "Holiday", "allDay": True, "days": [], "holidays": "only"}},
        )
        assert zone_ok.status == 200
        station = await (await client.get("/client/stations/GRD-TEST", headers=auth)).json()
        assert station["pricesByZone"][0]["holidays"] == "only"
