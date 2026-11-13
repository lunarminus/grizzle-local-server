"""Persistence: a JSON document for live state, SQLite for history."""

from __future__ import annotations

import contextlib
import json
import logging
import math
import os
import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

_LOGGER = logging.getLogger(__name__)

# state.json holds the API's bearer tokens and the charger's cloud Auth key: owner-only.
PRIVATE_FILE = 0o600


def _finite(value: Any) -> Any:
    """The same structure with NaN/Infinity replaced by None (JSON proper has no spelling for them)."""
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, dict):
        return {key: _finite(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_finite(item) for item in value]
    return value


def _restrict(path: Path) -> None:
    with contextlib.suppress(OSError):  # a filesystem without Unix permissions (SMB, some NAS datasets)
        os.chmod(path, PRIVATE_FILE)


class Store:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        data_dir.mkdir(parents=True, exist_ok=True)
        self._state_path = data_dir / "state.json"
        self.state: dict[str, Any] = self._load()
        if not isinstance(self.state.get("stations"), dict):
            self.state["stations"] = {}
        tokens = self.state.get("tokens")
        self.state["tokens"] = {
            token: info
            for token, info in (tokens.items() if isinstance(tokens, dict) else ())
            if isinstance(info, dict)
            and isinstance(info.get("refresh"), str)
            and isinstance(info.get("expires"), (int, float))
            and not isinstance(info.get("expires"), bool)
        }
        self._lock = threading.Lock()
        db_path = data_dir / "history.sqlite"
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._init_db()
        for path in (self._state_path, db_path):
            if path.exists():
                _restrict(path)
        # Never hand out an id history already uses: after a lost or reset state.json the counter
        # would restart at 1 and the next sessions would overwrite the recorded ones.
        counter = self.state.get("next_transaction_id")
        counter = counter if isinstance(counter, int) and not isinstance(counter, bool) and counter >= 1 else 1
        newest = self._db.execute("SELECT MAX(id) FROM sessions").fetchone()[0]
        self.state["next_transaction_id"] = max(counter, (newest or 0) + 1)

    # --- JSON state ---------------------------------------------------------

    def _load(self) -> dict[str, Any]:
        if not self._state_path.exists():
            return {}
        try:
            data = json.loads(self._state_path.read_text())
            if not isinstance(data, dict):
                raise ValueError("not a JSON object")
            return _finite(data)
        except (ValueError, RecursionError):
            backup = self._state_path.with_suffix(".corrupt.json")
            _LOGGER.error("state.json is corrupt, moving it to %s", backup)
            os.replace(self._state_path, backup)
            return {}

    def save(self) -> None:
        tmp = self._state_path.with_suffix(".tmp")
        payload = json.dumps(self.state, indent=1, sort_keys=True)
        with self._lock:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, PRIVATE_FILE)
            with os.fdopen(fd, "w") as handle:
                _restrict(tmp)  # the mode above only applies when the file is new
                handle.write(payload)
                handle.flush()
                # Without this a power cut can leave the renamed file empty, and an empty state
                # means every station (and every pinned Auth key) is forgotten.
                with contextlib.suppress(OSError):
                    os.fsync(handle.fileno())
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
                CREATE INDEX IF NOT EXISTS samples_station_tx ON samples(station, transaction_id, at);
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
        self.add_samples([(station, connector, tid, at, values)])

    def add_samples(self, rows: list[tuple[str, int, int | None, str, dict[str, Any]]]) -> None:
        """Insert several samples in one transaction (one commit, however many readings a message carries)."""
        if not rows:
            return
        with self._db:
            self._db.executemany(
                "INSERT INTO samples(station, connector, transaction_id, at, energy_wh, power_w, current_a,"
                " voltage_v, temperature_c, soc) VALUES (?,?,?,?,?,?,?,?,?,?)",
                [
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
                    )
                    for station, connector, tid, at, values in rows
                ],
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
        self.set_session_costs([(tid, cost, price_kwh)])

    def set_session_costs(self, rows: list[tuple[int, float, float | None]]) -> None:
        """Update many sessions' costs in one transaction: ``(id, cost, price per kWh)`` each."""
        if not rows:
            return
        with self._db:
            self._db.executemany(
                "UPDATE sessions SET cost=?, price_kwh=? WHERE id=?",
                [(cost, price_kwh, tid) for tid, cost, price_kwh in rows],
            )

    def prune_samples(self, keep_days: int = 90) -> None:
        # Sample times are ISO 8601 with a "T"; compare against the same spelling.
        cutoff = (datetime.now(UTC) - timedelta(days=keep_days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        with self._db:
            self._db.execute("DELETE FROM samples WHERE at < ?", (cutoff,))

    def close(self) -> None:
        self._db.close()
