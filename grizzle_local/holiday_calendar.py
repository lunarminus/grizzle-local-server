"""Statutory holidays for schedules and rates.

Holiday dates come from the ``holidays`` package, computed offline for a country and an
optional subdivision (state, province, …). A station keeps its own settings:

    {"enabled": bool, "country": "US", "subdivision": "ID", "observed": bool,
     "priceKW": float | None, "excludedNames": [...], "extraDates": [{"date", "name"}]}

``excludedNames`` drops holidays by name (so it holds across years, and also drops the
observed day of that holiday); ``extraDates`` adds one-off dates. ``priceKW`` is an optional
flat price that replaces every rate zone on a holiday.
"""

from __future__ import annotations

from datetime import date, timedelta
from functools import lru_cache
from typing import Any

import holidays as _holidays

DEFAULTS: dict[str, Any] = {
    "enabled": False,
    "country": None,
    "subdivision": None,
    "observed": True,
    "priceKW": None,
    "excludedNames": [],
    "extraDates": [],
}
HOLIDAY_MODES = ("same", "skip", "also", "only")


@lru_cache(maxsize=1)
def countries() -> list[dict[str, Any]]:
    """Every supported country with its subdivisions, for the settings form."""
    out = []
    for code, subdivisions in sorted(_holidays.list_supported_countries(include_aliases=False).items()):
        names: dict[str, str] = {}
        cls = getattr(_holidays, code, None)
        for name, sub in (getattr(cls, "subdivisions_aliases", None) or {}).items():
            names.setdefault(sub, name)
        out.append({"code": code, "subdivisions": [{"code": s, "name": names.get(s, s)} for s in subdivisions]})
    return out


def _supported() -> dict[str, list[str]]:
    return {c["code"]: [s["code"] for s in c["subdivisions"]] for c in countries()}


def normalize(raw: dict[str, Any] | None) -> dict[str, Any]:
    """Validate settings coming from the API. Raises ValueError with a readable message."""
    raw = raw or {}
    out = dict(DEFAULTS)
    out["enabled"] = bool(raw.get("enabled"))
    out["observed"] = bool(raw.get("observed", True))
    country = (raw.get("country") or "").strip().upper() or None
    subdivision = (raw.get("subdivision") or "").strip() or None
    if country is not None:
        supported = _supported()
        if country not in supported:
            raise ValueError(f"unsupported country {country!r}")
        if subdivision is not None and subdivision not in supported[country]:
            match = next((s for s in supported[country] if s.upper() == subdivision.upper()), None)
            if match is None:
                raise ValueError(f"unknown region {subdivision!r} for {country}")
            subdivision = match
    else:
        subdivision = None
    out["country"], out["subdivision"] = country, subdivision
    price = raw.get("priceKW")
    if price in (None, ""):
        out["priceKW"] = None
    else:
        price = float(price)
        if price < 0:
            raise ValueError("holiday price can't be negative")
        out["priceKW"] = price
    out["excludedNames"] = sorted({str(n).strip() for n in raw.get("excludedNames") or [] if str(n).strip()})
    extra: dict[str, str] = {}
    for item in raw.get("extraDates") or []:
        if isinstance(item, str):
            item = {"date": item}
        try:
            day = date.fromisoformat(str(item.get("date")))
        except (ValueError, AttributeError):
            raise ValueError(f"invalid date {item!r}; use YYYY-MM-DD") from None
        extra[day.isoformat()] = str(item.get("name") or "").strip()[:60] or "Holiday"
    out["extraDates"] = [{"date": d, "name": n} for d, n in sorted(extra.items())]
    return out


@lru_cache(maxsize=512)
def _year(country: str, subdivision: str | None, observed: bool, year: int) -> tuple[tuple[date, str, str], ...]:
    """(date, name, key) for one year. ``key`` is the holiday's own name, shared with its observed day."""
    base = _holidays.country_holidays(country, subdiv=subdivision, years=year, observed=False, language="en_US")
    entries = {day: (name, name) for day, name in base.items()}
    if observed:
        full = _holidays.country_holidays(country, subdiv=subdivision, years=year, observed=True, language="en_US")
        base_names = sorted(set(base.values()), key=len, reverse=True)
        for day, name in full.items():
            if day not in entries:
                key = next((b for b in base_names if name.startswith(b)), name)
                entries[day] = (name, key)
    return tuple(sorted((day, name, key) for day, (name, key) in entries.items()))


def _calendar(settings: dict[str, Any], years: range) -> list[tuple[date, str, str]]:
    country = settings.get("country")
    if not country:
        return []
    out: list[tuple[date, str, str]] = []
    for year in years:
        try:
            out.extend(_year(country, settings.get("subdivision"), bool(settings.get("observed", True)), year))
        except (NotImplementedError, KeyError, ValueError):  # country/region the library dropped
            return []
    return out


def holiday_name(settings: dict[str, Any] | None, day: date) -> str | None:
    """The holiday on ``day`` under these settings, or None. Ignores ``enabled``; callers check it."""
    if not settings:
        return None
    for item in settings.get("extraDates") or []:
        if item.get("date") == day.isoformat():
            return item.get("name") or "Holiday"
    excluded = set(settings.get("excludedNames") or [])
    for entry_day, name, key in _calendar(settings, range(day.year, day.year + 1)):
        if entry_day == day and key not in excluded:
            return name
    return None


def upcoming(settings: dict[str, Any] | None, start: date, days: int = 400) -> list[dict[str, Any]]:
    """Holidays from ``start`` on, including excluded ones (``included: false``) so the form can list them."""
    settings = settings or {}
    end = start + timedelta(days=days)
    excluded = set(settings.get("excludedNames") or [])
    rows: dict[str, dict[str, Any]] = {}
    for day, name, key in _calendar(settings, range(start.year, end.year + 1)):
        if start <= day <= end:
            rows[day.isoformat()] = {
                "date": day.isoformat(),
                "name": name,
                "key": key,
                "included": key not in excluded,
                "custom": False,
            }
    for item in settings.get("extraDates") or []:
        try:
            day = date.fromisoformat(item["date"])
        except (KeyError, ValueError):
            continue
        if start <= day <= end:
            rows[item["date"]] = {
                "date": item["date"],
                "name": item.get("name") or "Holiday",
                "key": None,
                "included": True,
                "custom": True,
            }
    return [rows[k] for k in sorted(rows)]
