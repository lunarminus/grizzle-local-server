"""Persistence: a JSON document for live state, SQLite for history."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any

_LOGGER = logging.getLogger(__name__)


class Store:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        data_dir.mkdir(parents=True, exist_ok=True)
        self._state_path = data_dir / "state.json"
        self.state: dict[str, Any] = self._load()
        self.state.setdefault("stations", {})
        self.state.setdefault("tokens", {})
        self.state.setdefault("next_transaction_id", 1)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(data_dir / "history.sqlite", check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._init_db()

    # --- JSON state ---------------------------------------------------------

    def _load(self) -> dict[str, Any]:
        if not self._state_path.exists():
            return {}
        try:
            return json.loads(self._state_path.read_text())
        except ValueError:
            backup = self._state_path.with_suffix(".corrupt.json")
            _LOGGER.error("state.json is corrupt, moving it to %s", backup)
            os.replace(self._state_path, backup)
            return {}

    def save(self) -> None:
        tmp = self._state_path.with_suffix(".tmp")
        with self._lock:
            tmp.write_text(json.dumps(self.state, indent=1, sort_keys=True))
            os.replace(tmp, self._state_path)

    def next_transaction_id(self) -> int:
        tid = int(self.state.get("next_transaction_id", 1))
        self.state["next_transaction_id"] = tid + 1
        return tid

    # --- SQLite history -----------------------------------------------------

    def _init_db(self) -> None:
        with self._db:
            self._db.executescript(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY,
                    station TEXT NOT NULL,
                    connector INTEGER NOT NULL,
                    id_tag TEXT,
                    start_at TEXT NOT NULL,
                    stop_at TEXT,
                    meter_start INTEGER,
                    meter_stop INTEGER,
                    energy_wh REAL,
                    duration_s INTEGER,
                    price_kwh REAL,
                    cost REAL,
                    reason TEXT
                );
                CREATE TABLE IF NOT EXISTS samples (
                    station TEXT NOT NULL,
                    connector INTEGER NOT NULL,
                    transaction_id INTEGER,
                    at TEXT NOT NULL,
                    energy_wh REAL,
                    power_w REAL,
                    current_a REAL,
                    voltage_v REAL,
                    temperature_c REAL,
                    soc REAL
                );
                CREATE INDEX IF NOT EXISTS samples_station_at ON samples(station, at);
                CREATE INDEX IF NOT EXISTS sessions_station_start ON sessions(station, start_at);
                """
            )

    def start_session(
        self,
        tid: int,
        station: str,
        connector: int,
        id_tag: str | None,
        start_at: str,
        meter_start: int | None,
        price_kwh: float | None,
    ) -> None:
        with self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO sessions(id, station, connector, id_tag, start_at, meter_start, price_kwh)"
                " VALUES (?,?,?,?,?,?,?)",
                (tid, station, connector, id_tag, start_at, meter_start, price_kwh),
            )

    def finish_session(
        self,
        tid: int,
        stop_at: str,
        meter_stop: int | None,
        energy_wh: float | None,
        duration_s: int | None,
        cost: float | None,
        reason: str | None,
    ) -> None:
        with self._db:
            self._db.execute(
                "UPDATE sessions SET stop_at=?, meter_stop=?, energy_wh=?, duration_s=?, cost=?, reason=? WHERE id=?",
                (stop_at, meter_stop, energy_wh, duration_s, cost, reason, tid),
            )

    def add_sample(self, station: str, connector: int, tid: int | None, at: str, values: dict[str, Any]) -> None:
        with self._db:
            self._db.execute(
                "INSERT INTO samples(station, connector, transaction_id, at, energy_wh, power_w, current_a,"
                " voltage_v, temperature_c, soc) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    station,
                    connector,
                    tid,
                    at,
                    values.get("energy_wh"),
                    values.get("power_w"),
                    values.get("current_a"),
                    values.get("voltage_v"),
                    values.get("temperature_c"),
                    values.get("soc"),
                ),
            )

    def sessions(self, station: str, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._db.execute(
            "SELECT * FROM sessions WHERE station=? ORDER BY start_at DESC LIMIT ?", (station, limit)
        ).fetchall()
        return [dict(r) for r in rows]

    def samples(
        self, station: str, since: str, connector: int | None = None, limit: int = 2000
    ) -> list[dict[str, Any]]:
        if connector is None:
            rows = self._db.execute(
                "SELECT * FROM samples WHERE station=? AND at>=? ORDER BY at LIMIT ?", (station, since, limit)
            ).fetchall()
        else:
            rows = self._db.execute(
                "SELECT * FROM samples WHERE station=? AND connector=? AND at>=? ORDER BY at LIMIT ?",
                (station, connector, since, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def energy_samples(self, station: str, tid: int) -> list[dict[str, Any]]:
        """A transaction's energy readings in time order, for repricing."""
        rows = self._db.execute(
            "SELECT at, energy_wh FROM samples WHERE station=? AND transaction_id=? AND energy_wh IS NOT NULL"
            " ORDER BY at",
            (station, tid),
        ).fetchall()
        return [dict(r) for r in rows]

    def set_session_cost(self, tid: int, cost: float, price_kwh: float | None) -> None:
        with self._db:
            self._db.execute("UPDATE sessions SET cost=?, price_kwh=? WHERE id=?", (cost, price_kwh, tid))

    def prune_samples(self, keep_days: int = 90) -> None:
        with self._db:
            self._db.execute("DELETE FROM samples WHERE at < datetime('now', ?)", (f"-{keep_days} days",))

    def close(self) -> None:
        self._db.close()
