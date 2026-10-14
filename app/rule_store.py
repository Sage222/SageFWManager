"""
core/rule_store.py

Local persistence for everything the native Windows Firewall API *doesn't*
track: friendly app metadata (icon path, display name, publisher), wildcard
groups, notification decisions ("always allow this app"), and point-in-time
snapshots used for rollback/undo.

Storage: a single SQLite file (portable, no server, ships as one file next
to the app). No UI or COM dependency -- fully unit-testable in isolation.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
import sqlite3
from pathlib import Path
from typing import Optional

# sagefw-portable-db-v1
import sys as _sys
_APP_DIR = (Path(_sys.executable).resolve().parent if getattr(_sys, "frozen", False)
            else Path(__file__).resolve().parent)
DEFAULT_DB_PATH = _APP_DIR / "data" / "nicerfirewall.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS app_metadata (
    app_path        TEXT PRIMARY KEY,
    display_name    TEXT,
    publisher       TEXT,
    icon_cache_path TEXT,
    is_uwp          INTEGER DEFAULT 0,
    package_family  TEXT,
    first_seen      TEXT,
    last_seen       TEXT,
    notes           TEXT
);

CREATE TABLE IF NOT EXISTS decisions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    app_path        TEXT NOT NULL,
    remote_address  TEXT,
    remote_port     TEXT,
    direction       TEXT NOT NULL,      -- 'in' or 'out'
    action          TEXT NOT NULL,      -- 'allow' or 'block'
    scope           TEXT NOT NULL,      -- 'once', 'always_app', 'always_app_dest'
    created_at      TEXT NOT NULL,
    rule_name        TEXT              -- native firewall rule name this created, if any
);

CREATE TABLE IF NOT EXISTS wildcard_groups (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    group_name      TEXT NOT NULL,
    path_pattern    TEXT NOT NULL,      -- e.g. C:\\Games\\*\\*.exe
    action          TEXT NOT NULL,
    direction       TEXT NOT NULL,
    enabled         INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS snapshots (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    label           TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    rules_json      TEXT NOT NULL       -- serialized list[FirewallRule]-as-dict
);

CREATE TABLE IF NOT EXISTS settings (
    key             TEXT PRIMARY KEY,
    value           TEXT
);
"""


class RuleStore:
    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self):
        self._conn.close()

    # ---------- app metadata ----------

    def upsert_app_metadata(self, app_path: str, display_name: str = "",
                             publisher: str = "", icon_cache_path: str = "",
                             is_uwp: bool = False, package_family: str = "") -> None:
        now = dt.datetime.utcnow().isoformat()
        cur = self._conn.execute(
            "SELECT first_seen FROM app_metadata WHERE app_path = ?", (app_path,)
        )
        row = cur.fetchone()
        first_seen = row["first_seen"] if row else now
        self._conn.execute(
            """
            INSERT INTO app_metadata
                (app_path, display_name, publisher, icon_cache_path, is_uwp,
                 package_family, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(app_path) DO UPDATE SET
                display_name=excluded.display_name,
                publisher=excluded.publisher,
                icon_cache_path=excluded.icon_cache_path,
                is_uwp=excluded.is_uwp,
                package_family=excluded.package_family,
                last_seen=excluded.last_seen
            """,
            (app_path, display_name, publisher, icon_cache_path, int(is_uwp),
             package_family, first_seen, now),
        )
        self._conn.commit()

    def get_app_metadata(self, app_path: str) -> Optional[dict]:
        cur = self._conn.execute(
            "SELECT * FROM app_metadata WHERE app_path = ?", (app_path,)
        )
        row = cur.fetchone()
        return dict(row) if row else None

    def is_known_app(self, app_path: str) -> bool:
        return self.get_app_metadata(app_path) is not None

    # ---------- decisions (drives notification suppression) ----------

    def record_decision(self, app_path: str, direction: str, action: str,
                         scope: str, remote_address: str = "*",
                         remote_port: str = "*", rule_name: str = "") -> int:
        now = dt.datetime.utcnow().isoformat()
        cur = self._conn.execute(
            """
            INSERT INTO decisions
                (app_path, remote_address, remote_port, direction, action,
                 scope, created_at, rule_name)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (app_path, remote_address, remote_port, direction, action,
             scope, now, rule_name),
        )
        self._conn.commit()
        return cur.lastrowid

    def find_existing_decision(self, app_path: str, direction: str,
                                remote_address: str = "*") -> Optional[dict]:
        """
        Used by the notification manager to decide whether a new connection
        needs a prompt at all, or whether the user already answered for
        this app (scope='always_app') or this app+destination pair.
        """
        cur = self._conn.execute(
            """
            SELECT * FROM decisions
            WHERE app_path = ? AND direction = ?
              AND scope IN ('always_app', 'always_app_dest')
              AND (scope = 'always_app' OR remote_address = ?)
            ORDER BY created_at DESC LIMIT 1
            """,
            (app_path, direction, remote_address),
        )
        row = cur.fetchone()
        return dict(row) if row else None

    # ---------- snapshots (undo / rollback) ----------

    def save_snapshot(self, label: str, rules: list) -> int:
        """`rules` is a list of FirewallRule dataclass instances or dicts."""
        serializable = [
            dataclasses.asdict(r) if dataclasses.is_dataclass(r) else r
            for r in rules
        ]
        now = dt.datetime.utcnow().isoformat()
        cur = self._conn.execute(
            "INSERT INTO snapshots (label, created_at, rules_json) VALUES (?, ?, ?)",
            (label, now, json.dumps(serializable)),
        )
        self._conn.commit()
        return cur.lastrowid

    def list_snapshots(self) -> list[dict]:
        cur = self._conn.execute(
            "SELECT id, label, created_at FROM snapshots ORDER BY created_at DESC"
        )
        return [dict(r) for r in cur.fetchall()]

    def load_snapshot(self, snapshot_id: int) -> list[dict]:
        cur = self._conn.execute(
            "SELECT rules_json FROM snapshots WHERE id = ?", (snapshot_id,)
        )
        row = cur.fetchone()
        if not row:
            raise KeyError(f"No snapshot with id {snapshot_id}")
        return json.loads(row["rules_json"])

    def delete_snapshot(self, snapshot_id: int) -> None:
        self._conn.execute("DELETE FROM snapshots WHERE id = ?", (snapshot_id,))
        self._conn.commit()

    # ---------- settings (small key/value store) ----------

    def get_setting(self, key: str, default=None):
        cur = self._conn.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = cur.fetchone()
        if row is None:
            return default
        try:
            return json.loads(row["value"])
        except (json.JSONDecodeError, TypeError):
            return row["value"]

    def set_setting(self, key: str, value) -> None:
        serialized = json.dumps(value)
        self._conn.execute(
            """
            INSERT INTO settings (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, serialized),
        )
        self._conn.commit()


if __name__ == "__main__":
    store = RuleStore(Path("data/test_nicerfirewall.db"))
    store.upsert_app_metadata(r"C:\Program Files\Example\example.exe",
                               display_name="Example App", publisher="Example Inc.")
    print(store.get_app_metadata(r"C:\Program Files\Example\example.exe"))
    store.set_setting("first_run_mode", "import_existing")
    print("first_run_mode =", store.get_setting("first_run_mode"))
    store.close()
