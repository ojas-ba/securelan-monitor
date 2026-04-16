import json
import sqlite3
import time
from typing import Any, Dict, List, Optional


RETRYABLE_ERRORS = ("database is locked", "database table is locked")


def _execute_with_retry(conn: sqlite3.Connection, query: str, params: tuple = ()) -> sqlite3.Cursor:
    attempts = 5
    delay = 0.15

    for idx in range(attempts):
        try:
            cur = conn.execute(query, params)
            conn.commit()
            return cur
        except sqlite3.OperationalError as exc:
            message = str(exc).lower()
            if any(token in message for token in RETRYABLE_ERRORS) and idx < attempts - 1:
                time.sleep(delay)
                continue
            raise

    raise RuntimeError("Unexpected retry loop exit")


def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            details_json TEXT NOT NULL
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS mac_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            mac_count INTEGER NOT NULL,
            delta INTEGER NOT NULL
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action_type TEXT NOT NULL,
            description TEXT NOT NULL,
            encrypted_blob TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL,
            hmac_sig TEXT NOT NULL
        )
        """
    )

    conn.commit()
    return conn


def insert_event(conn: sqlite3.Connection, event: Dict[str, Any]) -> int:
    details_json = json.dumps(event.get("details", {}), sort_keys=True)
    cur = _execute_with_retry(
        conn,
        """
        INSERT INTO events (timestamp, attack_type, severity, details_json)
        VALUES (?, ?, ?, ?)
        """,
        (
            event["timestamp"],
            event["attack_type"],
            event.get("severity", "INFO"),
            details_json,
        ),
    )
    return int(cur.lastrowid)


def insert_mac_snapshot(conn: sqlite3.Connection, timestamp: str, mac_count: int, delta: int) -> int:
    cur = _execute_with_retry(
        conn,
        """
        INSERT INTO mac_snapshots (timestamp, mac_count, delta)
        VALUES (?, ?, ?)
        """,
        (timestamp, int(mac_count), int(delta)),
    )
    return int(cur.lastrowid)


def insert_audit_log(
    conn: sqlite3.Connection,
    timestamp: str,
    action_type: str,
    description: str,
    encrypted_blob: str,
    prev_hash: str,
    entry_hash: str,
    hmac_sig: str,
) -> int:
    cur = _execute_with_retry(
        conn,
        """
        INSERT INTO audit_log (
            timestamp, action_type, description, encrypted_blob, prev_hash, entry_hash, hmac_sig
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (timestamp, action_type, description, encrypted_blob, prev_hash, entry_hash, hmac_sig),
    )
    return int(cur.lastrowid)


def get_recent_events(conn: sqlite3.Connection, limit: int = 10) -> List[Dict[str, Any]]:
    cur = conn.execute(
        """
        SELECT id, timestamp, attack_type, severity, details_json
        FROM events
        ORDER BY id DESC
        LIMIT ?
        """,
        (int(limit),),
    )
    rows = [dict(row) for row in cur.fetchall()]
    rows.reverse()
    return rows


def get_recent_mac_snapshots(conn: sqlite3.Connection, limit: int = 200) -> List[Dict[str, Any]]:
    cur = conn.execute(
        """
        SELECT id, timestamp, mac_count, delta
        FROM mac_snapshots
        ORDER BY id DESC
        LIMIT ?
        """,
        (int(limit),),
    )
    rows = [dict(row) for row in cur.fetchall()]
    rows.reverse()
    return rows


def get_audit_rows(
    conn: sqlite3.Connection,
    limit: Optional[int] = 300,
    ascending: bool = True,
) -> List[Dict[str, Any]]:
    order = "ASC" if ascending else "DESC"
    if limit is None:
        cur = conn.execute(
            f"""
            SELECT id, timestamp, action_type, description, encrypted_blob, prev_hash, entry_hash, hmac_sig
            FROM audit_log
            ORDER BY id {order}
            """
        )
    else:
        cur = conn.execute(
            f"""
            SELECT id, timestamp, action_type, description, encrypted_blob, prev_hash, entry_hash, hmac_sig
            FROM audit_log
            ORDER BY id {order}
            LIMIT ?
            """,
            (int(limit),),
        )
    return [dict(row) for row in cur.fetchall()]


def get_last_audit_hash(conn: sqlite3.Connection) -> str:
    cur = conn.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1")
    row: Optional[sqlite3.Row] = cur.fetchone()
    if not row:
        return "GENESIS"
    return str(row["entry_hash"])
