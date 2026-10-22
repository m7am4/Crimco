"""Saves every action to a local SQLite database so you can look back at it later."""

import json
import os
import sqlite3
from datetime import datetime

# Stored in the user's home folder, e.g. ~/.kiber/history.db
DB_PATH = os.path.join(os.path.expanduser("~"), ".kiber", "history.db")


def _connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS history (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            time      TEXT,
            command   TEXT,
            target    TEXT,
            flags     TEXT,
            details   TEXT
        )"""
    )
    return conn


def save(command, target, flags=None, details=None):
    """Record one action."""
    with _connect() as conn:
        conn.execute(
            "INSERT INTO history (time, command, target, flags, details) VALUES (?, ?, ?, ?, ?)",
            (
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                command,
                target,
                json.dumps(flags or []),
                json.dumps(details or {}),
            ),
        )


def load(limit=20, search=None):
    """Return the most recent entries, optionally filtered by a search word."""
    query = "SELECT id, time, command, target, flags FROM history"
    params = []
    if search:
        query += " WHERE target LIKE ? OR flags LIKE ? OR command LIKE ?"
        params = [f"%{search}%"] * 3
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with _connect() as conn:
        rows = conn.execute(query, params).fetchall()
    return [
        {"id": r[0], "time": r[1], "command": r[2], "target": r[3], "flags": json.loads(r[4])}
        for r in rows
    ]


def clear():
    """Delete all history."""
    with _connect() as conn:
        conn.execute("DELETE FROM history")
