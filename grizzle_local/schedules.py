"""Charging windows and rate zones, in the cloud's ``pricesByZone`` format.

Each zone is a dict with ``startHours``/``startMinutes``/``endHours``/``endMinutes``
(optionally a second range ``startHours2``…), ``allDay``, ``days`` (0=Sunday … 6=Saturday)
and ``connectorId`` (0 = every connector). A zone with ``isSchedule`` is a plain charging
window; one with ``priceKW`` is a rate zone. Either acts as a charging window when
``scheduleEnabled`` is true. Times are in the station's local timezone.
"""

from __future__ import annotations

from datetime import datetime, time, timedelta
from typing import Any

MINUTES_PER_DAY = 24 * 60


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


def _weekday(moment: datetime) -> int:
    """0=Sunday … 6=Saturday, matching the app."""
    return (moment.weekday() + 1) % 7


def applies_to(zone: dict[str, Any], connector_id: int) -> bool:
    zone_connector = int(zone.get("connectorId") or 0)
    return zone_connector == 0 or connector_id == 0 or zone_connector == connector_id


def zone_active(zone: dict[str, Any], now: datetime) -> bool:
    """Is ``now`` (timezone-aware, in the station's zone) inside this zone's time ranges?"""
    days = set(zone.get("days") or range(7))
    today, yesterday = _weekday(now), (_weekday(now) - 1) % 7
    minute = now.hour * 60 + now.minute + now.second / 60
    for start, end in _ranges(zone):
        if start < end:
            if today in days and start <= minute < end:
                return True
        else:  # crosses midnight
            if today in days and minute >= start:
                return True
            if yesterday in days and minute < end:
                return True
    return False


def charging_allowed(zones: list[dict[str, Any]], now: datetime, connector_id: int) -> dict[str, Any] | None:
    """The enabled charging window the connector is inside right now, if any."""
    for zone in zones:
        if zone.get("scheduleEnabled") and applies_to(zone, connector_id) and zone_active(zone, now):
            return zone
    return None


def price_now(zones: list[dict[str, Any]], now: datetime, base_price: float | None) -> float | None:
    """Electricity price per kWh: the matching rate zone, else the base rate."""
    for zone in zones:
        if zone.get("isSchedule") or not isinstance(zone.get("priceKW"), (int, float)):
            continue
        if zone_active(zone, now):
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
    zones: list[dict[str, Any]], now: datetime, connector_id: int, horizon_days: int = 8
) -> datetime | None:
    """When the connector's "allowed by schedule" state next flips, or None if it never does."""
    enabled = [z for z in zones if z.get("scheduleEnabled") and applies_to(z, connector_id)]
    if not enabled:
        return None
    current = charging_allowed(enabled, now, connector_id) is not None
    midnight = datetime.combine(now.date(), time(0), now.tzinfo)
    candidates: set[datetime] = set()
    for offset in range(-1, horizon_days + 1):
        day = midnight + timedelta(days=offset)
        for zone in enabled:
            candidates.update(_boundaries(zone, day))
    for moment in sorted(c for c in candidates if c > now):
        if (charging_allowed(enabled, moment, connector_id) is not None) != current:
            return moment
    return None
