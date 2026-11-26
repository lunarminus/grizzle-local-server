#!/usr/bin/env python3
"""Compile the statutory holidays the server knows into ``src/holidays.bin``.

The server is a single Rust binary and computes nothing about holidays itself: every date it
knows was worked out here, by the ``holidays`` package (the version pinned in requirements.txt),
for every country and subdivision the package supports, with and without observed days, for the
years FIRST_YEAR..LAST_YEAR. The table is built into the binary, so the server still needs no
network and no Python to answer "is this day a holiday".

    python tools/gen_holidays.py            # rewrite src/holidays.bin
    python tools/gen_holidays.py --check    # exit 1 if the file is not what this would write
    python tools/gen_holidays.py --dump out.jsonl   # every calendar as JSON lines (to compare decoders)

Run it again after updating ``holidays`` in requirements.txt (CI's --check says when), and
before LAST_YEAR comes within a few years.

File layout (integers are unsigned LEB128 unless noted; strings are length-prefixed UTF-8):

    "GZH1"  u16le first_year  u16le last_year  string holidays_version
    n_countries, then per country (sorted by code):
        string code
        n_subdivisions, then per subdivision: string code, string display_name
        blob_length                      # bytes of this country's blob in the data section
    data section: the countries' blobs one after another, each zlib-compressed

    A country's blob, decompressed:
        n_names, then each name as a string
        n_sets, then each set as ceil(n_calendars / 8) bytes: bit (subdivision_index * 2 + observed)
            says the calendar is in the set. subdivision_index 0 is the country as a whole, the
            subdivisions follow in the order listed above; n_calendars = (1 + n_subdivisions) * 2.
        per year, first_year..last_year:
            n_entries, then per entry, sorted by day:
                day_delta      # days since the previous entry's day (the first: since 1 January)
                name_index
                key_index + 1  # 0: the key is the name
                set_index

An entry is one row of what the Python server's ``holiday_calendar._year`` returned: the day, the
name shown for it, and the "key": the holiday's own name, which an observed day ("Christmas Day
(observed)") shares with the holiday it belongs to, so that leaving a holiday out by name leaves
its observed day out too.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
import warnings
import zlib
from datetime import date
from pathlib import Path

import holidays

FIRST_YEAR = 2000
LAST_YEAR = 2100
OUTPUT = Path(__file__).resolve().parents[1] / "src" / "holidays.bin"


def countries() -> list[tuple[str, list[tuple[str, str]]]]:
    """Every supported country with its subdivisions as (code, display name)."""
    out = []
    for code, subdivisions in sorted(holidays.list_supported_countries(include_aliases=False).items()):
        names: dict[str, str] = {}
        cls = getattr(holidays, code, None)
        for name, sub in (getattr(cls, "subdivisions_aliases", None) or {}).items():
            names.setdefault(sub, name)
        out.append((code, [(sub, names.get(sub, sub)) for sub in subdivisions]))
    return out


def calendar(country: str, subdivision: str | None, observed: bool) -> dict[int, list[tuple[date, str, str]]]:
    """year -> sorted (day, name, key) rows, as the Python server computed them one year at a time."""
    years = range(FIRST_YEAR, LAST_YEAR + 1)
    out: dict[int, list[tuple[date, str, str]]] = {year: [] for year in years}
    for year in years:
        # One year at a time: asked for a range, the package lets a holiday observed on 1 January
        # of the next year, or on 31 December of the last, leak in or out at the edges.
        try:
            base = holidays.country_holidays(country, subdiv=subdivision, years=year, observed=False, language="en_US")
            if not observed:
                out[year] = sorted((day, name, name) for day, name in base.items())
                continue
            full = holidays.country_holidays(country, subdiv=subdivision, years=year, observed=True, language="en_US")
        except (NotImplementedError, KeyError, ValueError):
            continue
        base_names = sorted(set(base.values()), key=len, reverse=True)
        out[year] = sorted(
            (day, name, next((b for b in base_names if name.startswith(b)), name)) for day, name in full.items()
        )
    return out


def varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def string(text: str) -> bytes:
    raw = text.encode("utf-8")
    return varint(len(raw)) + raw


def country_blob(code: str, subdivisions: list[tuple[str, str]], dump=None) -> bytes:
    calendars = [(sub, observed) for sub in [None, *(s for s, _ in subdivisions)] for observed in (False, True)]
    # (year, day, name, key) -> the calendars that have it
    members: dict[tuple[int, date, str, str], int] = {}
    for index, (sub, observed) in enumerate(calendars):
        for year, rows in calendar(code, sub, observed).items():
            if dump is not None:
                record = {"country": code, "subdivision": sub, "observed": observed, "year": year}
                record["rows"] = [[day.isoformat(), name, key] for day, name, key in rows]
                dump.write(json.dumps(record, ensure_ascii=False) + "\n")
            for day, name, key in rows:
                if day.year != year:
                    continue  # the package files such a day under its own year too
                members[(year, day, name, key)] = members.get((year, day, name, key), 0) | (1 << index)
    names: dict[str, int] = {}
    sets: dict[int, int] = {}
    for (_, _, name, key), mask in sorted(members.items()):
        for text in (name, key):
            names.setdefault(text, len(names))
        sets.setdefault(mask, len(sets))
    set_bytes = (len(calendars) + 7) // 8
    out = bytearray(varint(len(names)))
    for name in names:
        out += string(name)
    out += varint(len(sets))
    for mask in sets:
        out += mask.to_bytes(set_bytes, "little")
    by_year: dict[int, list[tuple[date, str, str, int]]] = {}
    for (year, day, name, key), mask in members.items():
        by_year.setdefault(year, []).append((day, name, key, mask))
    for year in range(FIRST_YEAR, LAST_YEAR + 1):
        rows = sorted(by_year.get(year, []))
        out += varint(len(rows))
        previous = 0
        for day, name, key, mask in rows:
            ordinal = day.timetuple().tm_yday - 1
            out += varint(ordinal - previous)
            previous = ordinal
            out += varint(names[name])
            out += varint(0 if key == name else names[key] + 1)
            out += varint(sets[mask])
    return bytes(out)


def build(dump=None) -> bytes:
    index = bytearray()
    data = bytearray()
    listing = countries()
    index += varint(len(listing))
    for code, subdivisions in listing:
        blob = zlib.compress(country_blob(code, subdivisions, dump), 9)
        index += string(code)
        index += varint(len(subdivisions))
        for sub, name in subdivisions:
            index += string(sub) + string(name)
        index += varint(len(blob))
        data += blob
    header = b"GZH1" + struct.pack("<HH", FIRST_YEAR, LAST_YEAR) + string(holidays.__version__)
    return bytes(header + index + data)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--check", action="store_true", help="compare with the file instead of writing it")
    parser.add_argument("--dump", metavar="FILE", help="also write every calendar as JSON lines")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    warnings.simplefilter("ignore")
    if args.dump:
        with open(args.dump, "w", encoding="utf-8") as dump:
            built = build(dump)
    else:
        built = build()
    if args.check:
        if not args.output.is_file() or args.output.read_bytes() != built:
            print(
                f"{args.output} is not what holidays {holidays.__version__} gives for {FIRST_YEAR}-{LAST_YEAR}: "
                "run tools/gen_holidays.py and commit the result",
                file=sys.stderr,
            )
            return 1
        print(f"{args.output} is up to date (holidays {holidays.__version__}, {FIRST_YEAR}-{LAST_YEAR})")
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(built)
    print(f"wrote {args.output}: {len(built)} bytes, holidays {holidays.__version__}, {FIRST_YEAR}-{LAST_YEAR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
