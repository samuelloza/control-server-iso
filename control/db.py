"""SQLite: esquema, conexion compartida y helpers de fecha."""
import os
import sqlite3
import threading
from datetime import datetime, timezone

from control.settings import DB_PATH


# Un lock global para la DB; alcanza para unos cientos de maquinas.
DB_LOCK = threading.RLock()


CMD_COND = threading.Condition()


_conn = None


def db():
    global _conn
    if _conn is None:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
        _conn.row_factory = sqlite3.Row
        try:
            _conn.execute("ALTER TABLE roster RENAME TO teams")   # nombre viejo de la tabla
        except sqlite3.OperationalError:
            pass
        _conn.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS machines (
                machine_id  TEXT PRIMARY KEY,
                group_id    TEXT NOT NULL,
                bearer      TEXT NOT NULL,
                hostname    TEXT,
                ip          TEXT,
                enrolled_at TEXT NOT NULL,
                last_seen   TEXT,
                lock_state  INTEGER NOT NULL DEFAULT 0,
                frozen      INTEGER NOT NULL DEFAULT 0,
                status_json TEXT,
                status_at   TEXT,
                binding_json TEXT
            );
            CREATE TABLE IF NOT EXISTS commands (
                nonce      TEXT PRIMARY KEY,
                group_id   TEXT NOT NULL,
                machine_id TEXT NOT NULL,          -- '*' = whole group
                action     TEXT NOT NULL,
                args_json  TEXT NOT NULL,
                payload    BLOB NOT NULL,
                signature  TEXT NOT NULL,
                issued_at  TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                status     TEXT NOT NULL DEFAULT 'pending'
            );
            CREATE TABLE IF NOT EXISTS deliveries (
                nonce        TEXT NOT NULL,
                machine_id   TEXT NOT NULL,
                delivered_at TEXT,
                acked_at     TEXT,
                status       TEXT,
                detail       TEXT,
                PRIMARY KEY (nonce, machine_id)
            );
            CREATE TABLE IF NOT EXISTS samples (
                machine_id TEXT NOT NULL,
                t          INTEGER NOT NULL,
                mem        REAL, ld REAL, sw REAL, hd REAL
            );
            CREATE INDEX IF NOT EXISTS samples_m ON samples(machine_id, t);
            -- owner = user_id del equipo logueado (sobrevive al reinicio: el
            -- machine_id de la ISO live cambia en cada arranque); machine_id si no hay login.
            CREATE TABLE IF NOT EXISTS app_usage (
                group_id TEXT NOT NULL,
                owner    TEXT NOT NULL,
                app      TEXT NOT NULL,
                secs     INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (group_id, owner, app)
            );
            CREATE TABLE IF NOT EXISTS app_sessions (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                machine_id TEXT NOT NULL,
                app        TEXT NOT NULL,
                started_at INTEGER NOT NULL,
                last_at    INTEGER NOT NULL,
                open       INTEGER NOT NULL DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS app_sessions_m ON app_sessions (machine_id, id);
            CREATE TABLE IF NOT EXISTS journal (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                machine_id TEXT NOT NULL,
                at         TEXT NOT NULL,
                nbytes     INTEGER NOT NULL,
                text       TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS journal_m ON journal(machine_id, id);
            CREATE TABLE IF NOT EXISTS alerts (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id     TEXT NOT NULL,
                machine_id   TEXT NOT NULL,
                kind         TEXT NOT NULL,
                detail       TEXT,
                raised_at    TEXT NOT NULL,
                dismissed_at TEXT,
                dismissed_by TEXT
            );
            CREATE INDEX IF NOT EXISTS alerts_open ON alerts(group_id, dismissed_at);
            CREATE TABLE IF NOT EXISTS teams (
                group_id TEXT NOT NULL,
                user_id  TEXT NOT NULL,
                name     TEXT NOT NULL,
                org      TEXT, seat TEXT, country TEXT,
                PRIMARY KEY (group_id, user_id)
            );
            CREATE TABLE IF NOT EXISTS group_config (
                group_id       TEXT PRIMARY KEY,
                allowlist_json TEXT NOT NULL DEFAULT '[]',
                updated_at     TEXT
            );
            """
        )
        for table, col in (("group_config", "phase TEXT NOT NULL DEFAULT 'idle'"),
                           ("group_config", "homepage TEXT"),
                           ("group_config", "homepage_updated_at TEXT"),
                           ("group_config", "logo_url TEXT"),
                           ("group_config", "logo_updated_at TEXT"),
                           ("machines", "location TEXT"),
                           ("machines", "hidden_at TEXT")):
            try:
                _conn.execute(f"ALTER TABLE {table} ADD COLUMN {col}")
            except sqlite3.OperationalError:
                pass  # ya existe
    return _conn


def now():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def since_seconds(ts):
    if not ts:
        return None
    try:
        return int((now() - datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
                    .replace(tzinfo=timezone.utc)).total_seconds())
    except ValueError:
        return None


def stored_phase(conn, group_id):
    row = conn.execute("SELECT phase FROM group_config WHERE group_id=?", (group_id,)).fetchone()
    return row["phase"] if row else "idle"
