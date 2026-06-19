import sqlite3
import json
import time
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "playbook_store.db"


def _get_conn():
    conn = sqlite3.connect(str(DB_PATH), timeout=5, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = _get_conn()
    try:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS tickets (
            alert_id TEXT PRIMARY KEY,
            ticket_json TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
        """)
        conn.commit()
    finally:
        conn.close()


def get_ticket(alert_id: str):
    conn = _get_conn()
    try:
        cur = conn.execute(
            "SELECT ticket_json FROM tickets WHERE alert_id = ?", (alert_id,))
        row = cur.fetchone()
        if not row:
            return None
        return json.loads(row["ticket_json"])
    finally:
        conn.close()


def save_ticket(alert_id: str, ticket: dict):
    conn = _get_conn()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO tickets (alert_id, ticket_json, created_at) VALUES (?, ?, ?)",
            (alert_id, json.dumps(ticket), int(time.time()))
        )
        conn.commit()
    finally:
        conn.close()
