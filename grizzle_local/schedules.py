"""Charging windows and rate zones, in the cloud's ``pricesByZone`` format.

Each zone is a dict with ``startHours``/``startMinutes``/``endHours``/``endMinutes``
(optionally a second range ``startHours2``…), ``allDay``, ``days`` (0=Sunday … 6=Saturday)
and ``connectorId`` (0 = every connector). A zone with ``isSchedule`` is a plain charging
window; one with ``priceKW`` is a rate zone. Either acts as a charging window when
``scheduleEnabled`` is true. Times are in the station's local timezone.

Our own extension, ``holidays``, says how a zone treats statutory holidays: ``"same"``
(default: a holiday is just its weekday), ``"skip"`` (never on a holiday), ``"also"`` (its
days plus every holiday) or ``"only"`` (holidays only; ``days`` is ignored).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import date, datetime, time, timedelta
from typing import Any

MINUTES_PER_DAY = 24 * 60

HolidayCheck = Callable[[date], bool]


def _ranges(zone: dict[str, Any]) -> list[tuple[int, int]]:
    """Minute-of-day ranges. ``start == end`` (and allDay) mean the whole day."""
    if zone.get("allDay"):
        return [(0, MINUTES_PER_DAY)]
    ranges = []
    for suffix in ("", "2"):
        keys = [f"startHours{suffix}", f"startMinutes{suffix}", f"endHours{suffix}", f"endMinutes{suffix}"]
        if suffix and not any(zone.get(k) for k in keys):
            continue
        sh, sm, eh, em = (int(zone.get(k) or 0) for k in keys)
        start, end = sh * 60 + sm, eh * 60 + em
        if start == end:
            start, end = 0, MINUTES_PER_DAY
        ranges.append((start, end))
    return ranges


def _weekday(day: date) -> int:
    """0=Sunday … 6=Saturday, matching the app."""
    return (day.weekday() + 1) % 7


def _eligible(zone: dict[str, Any], day: date, is_holiday: HolidayCheck | None) -> bool:
    """Does the zone apply on this calendar day (before looking at the time of day)?"""
    mode = zone.get("holidays") or "same"
    holiday = bool(is_holiday and mode != "same" and is_holiday(day))
    if mode == "only":
        return holiday
    regular = _weekday(day) in set(zone.get("days") or range(7))
    if mode == "skip":
        return regular and not holiday
    if mode == "also":
        return regular or holiday
    return regular


def applies_to(zone: dict[str, Any], connector_id: int) -> bool:
    zone_connector = int(zone.get("connectorId") or 0)
    return zone_connector == 0 or connector_id == 0 or zone_connector == connector_id


def zone_active(zone: dict[str, Any], now: datetime, is_holiday: HolidayCheck | None = None) -> bool:
    """Is ``now`` (timezone-aware, in the station's zone) inside this zone's time ranges?"""
    today = now.date()
    on_today = _eligible(zone, today, is_holiday)
    on_yesterday = _eligible(zone, today - timedelta(days=1), is_holiday)
    minute = now.hour * 60 + now.minute + now.second / 60
    for start, end in _ranges(zone):
        if start < end:
            if on_today and start <= minute < end:
                return True
        else:  # crosses midnight: belongs to the day it starts on
            if on_today and minute >= start:
                return True
            if on_yesterday and minute < end:
                return True
    return False


def charging_allowed(
    zones: list[dict[str, Any]], now: datetime, connector_id: int, is_holiday: HolidayCheck | None = None
) -> dict[str, Any] | None:
    """The enabled charging window the connector is inside right now, if any."""
    for zone in zones:
        if zone.get("scheduleEnabled") and applies_to(zone, connector_id) and zone_active(zone, now, is_holiday):
            return zone
    return None


def price_now(
    zones: list[dict[str, Any]],
    now: datetime,
    base_price: float | None,
    is_holiday: HolidayCheck | None = None,
    holiday_price: float | None = None,
) -> float | None:
    """Electricity price per kWh: the flat holiday price, else the matching rate zone, else the base rate."""
    if holiday_price is not None and is_holiday is not None and is_holiday(now.date()):
        return float(holiday_price)
    for zone in zones:
        if zone.get("isSchedule") or not isinstance(zone.get("priceKW"), (int, float)):
            continue
        if zone_active(zone, now, is_holiday):
            return float(zone["priceKW"])
    return base_price


def _boundaries(zone: dict[str, Any], day: datetime) -> list[datetime]:
    """Instants on ``day`` (a local midnight) where this zone may switch state."""
    tz = day.tzinfo
    out = []
    for start, end in _ranges(zone):
        out.append(datetime.combine(day.date(), time(0), tz) + timedelta(minutes=start))
        end_day = day.date() if start < end else day.date() + timedelta(days=1)
        out.append(datetime.combine(end_day, time(0), tz) + timedelta(minutes=end))
    return out


def next_change(
    zones: list[dict[str, Any]],
    now: datetime,
    connector_id: int,
    is_holiday: HolidayCheck | None = None,
    horizon_days: int = 8,
) -> datetime | None:
    """When the connector's "allowed by schedule" state next flips, or None if it never does."""
    enabled = [z for z in zones if z.get("scheduleEnabled") and applies_to(z, connector_id)]
    if not enabled:
        return None
    if any((z.get("holidays") or "same") == "only" for z in enabled):
        horizon_days = max(horizon_days, 120)  # a holidays-only window may be months away
    current = charging_allowed(enabled, now, connector_id, is_holiday) is not None
    midnight = datetime.combine(now.date(), time(0), now.tzinfo)
    candidates: set[datetime] = set()
    for offset in range(-1, horizon_days + 1):
        day = midnight + timedelta(days=offset)
        for zone in enabled:
            candidates.update(_boundaries(zone, day))
    for moment in sorted(c for c in candidates if c > now):
        if (charging_allowed(enabled, moment, connector_id, is_holiday) is not None) != current:
            return moment
    return None
