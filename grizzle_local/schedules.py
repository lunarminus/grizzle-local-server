"""Charging windows and rate zones, in the cloud's ``pricesByZone`` format.

Each zone is a dict with ``startHours``/``startMinutes``/``endHours``/``endMinutes``
(optionally a second range ``startHours2``…), ``allDay``, ``days`` (0=Sunday … 6=Saturday)
and ``connectorId`` (0 = every connector). A zone with ``isSchedule`` is a plain charging
window; one with ``priceKW`` is a rate zone. Either acts as a charging window when
``scheduleEnabled`` is true. Times are in the station's local timezone.

``days`` are calendar days. A range that wraps past midnight (20:00-06:00) covers the small hours
and the late evening of each of those days; it does not run from a listed day into the next.

Our own extension, ``holidays``, says how a zone treats statutory holidays: ``"same"``
(default: a holiday is just its weekday), ``"skip"`` (never on a holiday), ``"also"`` (its
days plus every holiday) or ``"only"`` (holidays only; ``days`` is ignored).
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable
from datetime import date, datetime, time, timedelta, timezone
from typing import Any

MINUTES_PER_DAY = 24 * 60
HOLIDAY_MODES = ("same", "skip", "also", "only")

HolidayCheck = Callable[[date], bool]

# --- validation -----------------------------------------------------------------------------
#
# Zones arrive from the REST API and are evaluated on every controller tick, forever. Anything
# stored here must therefore be something the functions below can evaluate: one zone with
# ``"startHours": "soon"`` would otherwise raise on every tick after it was saved.

_TIME_KEYS = tuple(
    f"{edge}{unit}{suffix}" for suffix in ("", "2") for edge in ("start", "end") for unit in ("Hours", "Minutes")
)
_FLAG_KEYS = ("allDay", "isSchedule", "scheduleEnabled", "useSeason")
_PRICE_KEYS = ("priceKW", "priceKWSummer")
_ZONE_ID_RE = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
MAX_NAME_LENGTH = 100
MAX_EXTRA_KEYS = 32  # fields of the cloud's format we don't interpret but hand back unchanged


def zone_id(value: Any) -> str:
    """A zone's ``_id`` as text. Raises ValueError for anything that can't be one."""
    if isinstance(value, int) and not isinstance(value, bool):
        value = str(value)
    if not isinstance(value, str) or not _ZONE_ID_RE.fullmatch(value):
        raise ValueError("_id must be 1-64 letters, digits or _ . : -")
    return value


def _whole(key: str, value: Any, lo: int, hi: int) -> int:
    """An integer in ``lo..hi``; None means 0. Integral floats and digit strings are accepted."""
    if value is None:
        return 0
    number: int | None = None
    if isinstance(value, bool):
        pass
    elif isinstance(value, int):
        number = value
    elif isinstance(value, float) and value.is_integer():
        number = int(value)
    elif isinstance(value, str) and value.strip().isascii() and value.strip().isdigit() and len(value.strip()) <= 4:
        number = int(value.strip())
    if number is None or not lo <= number <= hi:
        raise ValueError(f"{key} must be a whole number from {lo} to {hi}")
    return number


def _amount(key: str, value: Any) -> float | int | None:
    """A finite number (numeric text is accepted), or None. Raises ValueError otherwise."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ValueError(f"{key} must be a number")
    if isinstance(value, str):
        if len(value) > 32:
            raise ValueError(f"{key} must be a number")
        try:
            value = float(value)
        except ValueError:
            raise ValueError(f"{key} must be a number") from None
    if not isinstance(value, (int, float)):
        raise ValueError(f"{key} must be a number")
    try:
        finite = math.isfinite(value)
    except OverflowError:  # an integer too large for a float
        finite = False
    if not finite:
        raise ValueError(f"{key} must be a finite number")
    return int(value) if isinstance(value, float) and value.is_integer() and abs(value) < 1e15 else value


def _passthrough(value: Any) -> bool:
    """Is this small enough, and plain enough, to store as a field we don't interpret?"""
    if value is None or isinstance(value, bool):
        return True
    if isinstance(value, str):
        return len(value) <= 200
    try:
        return len(json.dumps(value, allow_nan=False)) <= 256
    except (TypeError, ValueError, RecursionError, OverflowError):
        return False


def normalize_zone(raw: Any, *, max_connector: int = 8, max_current: int = 100) -> dict[str, Any]:
    """Validate a zone from the API (or from an old state file). Raises ValueError with a readable message.

    Only the keys present are returned, typed the way the evaluation below expects; ``_id`` is left to
    the caller. Fields of the cloud's format that we don't interpret survive if they are small.
    """
    if not isinstance(raw, dict):
        raise ValueError("price object required")
    zone: dict[str, Any] = {}
    extras = 0
    for key, value in raw.items():
        if key == "_id":
            continue
        if key == "name":
            if value is None:
                value = ""
            if not isinstance(value, str):
                raise ValueError("name must be text")
            value = value.strip()
            if len(value) > MAX_NAME_LENGTH:
                raise ValueError(f"name can't be longer than {MAX_NAME_LENGTH} characters")
        elif key in _FLAG_KEYS:
            if value is not None and not isinstance(value, bool) and value not in (0, 1):
                raise ValueError(f"{key} must be true or false")
            value = bool(value)
        elif key in _TIME_KEYS:
            value = _whole(key, value, 0, 24 if "Hours" in key else 59)
        elif key == "days":
            if value is None:
                value = []
            if not isinstance(value, list) or len(value) > 64 or any(day is None for day in value):
                raise ValueError("days must be a list of numbers, 0 (Sunday) to 6 (Saturday)")
            value = sorted({_whole("days", day, 0, 6) for day in value})
        elif key == "connectorId":
            value = _whole(key, value, 0, max_connector)
        elif key == "currentLimit":
            value = _amount(key, value)
            if value == 0:
                value = None  # "no limit of its own"
            if value is not None and not 1 <= value <= max_current:
                raise ValueError(f"currentLimit must be between 1 and {max_current} A")
        elif key in _PRICE_KEYS:
            value = _amount(key, value)
            if value is not None and value < 0:
                raise ValueError(f"{key} can't be negative")
        elif key == "holidays":
            if value is not None and not (isinstance(value, str) and value in HOLIDAY_MODES):
                raise ValueError(f"holidays must be one of {HOLIDAY_MODES}")
        else:
            if not isinstance(key, str) or len(key) > 40 or extras >= MAX_EXTRA_KEYS or not _passthrough(value):
                continue
            extras += 1
        zone[key] = value
    for suffix in ("", "2"):
        for edge in ("start", "end"):
            if zone.get(f"{edge}Hours{suffix}") == 24 and zone.get(f"{edge}Minutes{suffix}"):
                raise ValueError("a time can't be later than 24:00")
    return zone


# --- evaluation -----------------------------------------------------------------------------


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


def _wall_clock(now: datetime) -> datetime:
    """The moment whose wall-clock reading decides what applies at ``now``: normally ``now`` itself.

    On the night the clocks go back, an hour of wall-clock time happens twice. Read naively, a
    window that starts at 01:30 would switch on, off again for the second 01:00-01:30, and back
    on: a charger told to stop and to start again half an hour later. So the second time round is
    read as the moment the repeat ends, and whatever the first pass ended with carries through.
    """
    if not now.fold or now.tzinfo is None or now.replace(fold=0).utcoffset() == now.utcoffset():
        return now
    instant = now.astimezone(timezone.utc).replace(second=0, microsecond=0)
    for _ in range(3 * 60):
        instant += timedelta(minutes=1)
        local = instant.astimezone(now.tzinfo)
        if local.replace(fold=0).utcoffset() == local.replace(fold=1).utcoffset():
            return local
    return now


def zone_active(zone: dict[str, Any], now: datetime, is_holiday: HolidayCheck | None = None) -> bool:
    """Is ``now`` (timezone-aware, in the station's zone) inside this zone?

    Days are calendar days: a range that wraps past midnight, say 20:00-06:00, covers 00:00-06:00
    and 20:00-24:00 of every day the zone applies to. It does not start on a listed day and spill
    into the next one, so "weekdays 20:00-06:00" includes Monday's small hours and stops at
    midnight on Friday. That is how utility rate plans (and the Grizzl-E app) read it.
    """
    now = _wall_clock(now)
    if not _eligible(zone, now.date(), is_holiday):
        return False
    minute = now.hour * 60 + now.minute + now.second / 60
    for start, end in _ranges(zone):
        if start < end:
            if start <= minute < end:
                return True
        elif minute >= start or minute < end:  # wraps past midnight
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
    midnight = datetime.combine(day.date(), time(0), tz)
    out = [midnight]  # a new calendar day can change whether the zone applies at all
    for start, end in _ranges(zone):
        out.append(midnight + timedelta(minutes=start))
        out.append(midnight + timedelta(minutes=end))
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
    if is_holiday is not None and any((z.get("holidays") or "same") != "same" for z in enabled):
        # The next day a holiday rule lets a window apply (or stops it applying) can be most of a
        # year away: a holidays-only window in a country with one holiday left this year, a weekly
        # window whose next few days all fall on holidays.
        horizon_days = max(horizon_days, 370)
    current = charging_allowed(enabled, now, connector_id, is_holiday) is not None
    tz = now.tzinfo
    midnight = datetime.combine(now.date(), time(0), tz)
    walls: set[datetime] = set()
    for offset in range(-1, horizon_days + 1):
        day = midnight + timedelta(days=offset)
        for zone in enabled:
            walls.update(_boundaries(zone, day))
        if tz is not None and day.utcoffset() != (day + timedelta(days=1)).utcoffset():
            # The clocks change today, so the wall clock skips or repeats part of an hour and the
            # state can flip at the change itself, not only at a boundary someone typed in.
            walls.update(day + timedelta(minutes=30 * step) for step in range(49))
    if tz is None:  # naive datetimes: nothing to convert, and no clock changes to worry about
        candidates = sorted(wall for wall in walls if wall > now)
    else:
        # Compare as instants. Two datetimes in the same zone compare by their wall-clock reading,
        # which is wrong twice a year: a time that occurs twice is two instants (both are
        # candidates), and one that never occurs still stands for a real instant.
        now_utc = now.astimezone(timezone.utc)
        instants = {wall.replace(fold=fold).astimezone(timezone.utc) for wall in walls for fold in (0, 1)}
        candidates = [instant.astimezone(tz) for instant in sorted(i for i in instants if i > now_utc)]
    for moment in candidates:
        if (charging_allowed(enabled, moment, connector_id, is_holiday) is not None) != current:
            return moment
    return None
