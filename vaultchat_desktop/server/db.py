from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

DB_DIR = Path.home() / '.vaultchat_desktop_server'
DB_FILE = DB_DIR / 'server.sqlite3'


class Database:
    def __init__(self) -> None:
        DB_DIR.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._migrate()

    def _migrate(self) -> None:
        cur = self.conn.cursor()
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS groups (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                secret_hash TEXT NOT NULL,
                admin_user_id TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                enc_public TEXT NOT NULL,
                sign_public TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                group_id TEXT NOT NULL,
                token TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                FOREIGN KEY(group_id) REFERENCES groups(id)
            );

            CREATE TABLE IF NOT EXISTS group_messages (
                id TEXT PRIMARY KEY,
                group_id TEXT NOT NULL,
                sender_user_id TEXT NOT NULL,
                envelope_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(group_id) REFERENCES groups(id),
                FOREIGN KEY(sender_user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS dm_messages (
                id TEXT PRIMARY KEY,
                sender_user_id TEXT NOT NULL,
                recipient_user_id TEXT NOT NULL,
                envelope_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(sender_user_id) REFERENCES users(id),
                FOREIGN KEY(recipient_user_id) REFERENCES users(id)
            );
            """
        )
        self.conn.commit()

    def group_exists(self) -> bool:
        row = self.conn.execute('SELECT COUNT(*) AS c FROM groups').fetchone()
        return bool(row['c'])

    def create_group(self, *, group_id: str, name: str, secret_hash: str, admin_user_id: str, created_at: str) -> None:
        self.conn.execute(
            'INSERT INTO groups (id, name, secret_hash, admin_user_id, created_at) VALUES (?, ?, ?, ?, ?)',
            (group_id, name, secret_hash, admin_user_id, created_at),
        )
        self.conn.commit()

    def create_user(self, *, user_id: str, display_name: str, enc_public: str, sign_public: str, is_admin: bool, group_id: str, token: str, created_at: str) -> None:
        self.conn.execute(
            'INSERT INTO users (id, display_name, enc_public, sign_public, is_admin, group_id, token, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            (user_id, display_name, enc_public, sign_public, 1 if is_admin else 0, group_id, token, created_at),
        )
        self.conn.commit()

    def find_group_by_secret_hash(self, secret_hash: str) -> Optional[Dict[str, Any]]:
        row = self.conn.execute('SELECT * FROM groups WHERE secret_hash = ?', (secret_hash,)).fetchone()
        return dict(row) if row else None

    def get_user_by_token(self, token: str) -> Optional[Dict[str, Any]]:
        row = self.conn.execute('SELECT * FROM users WHERE token = ?', (token,)).fetchone()
        return dict(row) if row else None

    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        row = self.conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        return dict(row) if row else None

    def list_members(self, group_id: str) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            'SELECT id, display_name, enc_public, sign_public, is_admin, created_at FROM users WHERE group_id = ? ORDER BY display_name COLLATE NOCASE',
            (group_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def create_group_message(self, *, message_id: str, group_id: str, sender_user_id: str, envelope: Dict[str, Any], created_at: str) -> None:
        self.conn.execute(
            'INSERT INTO group_messages (id, group_id, sender_user_id, envelope_json, created_at) VALUES (?, ?, ?, ?, ?)',
            (message_id, group_id, sender_user_id, json.dumps(envelope, ensure_ascii=False), created_at),
        )
        self.conn.commit()

    def list_group_messages(self, group_id: str) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            'SELECT * FROM group_messages WHERE group_id = ? ORDER BY created_at ASC',
            (group_id,),
        ).fetchall()
        return [
            {
                'id': row['id'],
                'group_id': row['group_id'],
                'sender_user_id': row['sender_user_id'],
                'envelope': json.loads(row['envelope_json']),
                'created_at': row['created_at'],
            }
            for row in rows
        ]

    def create_dm_message(self, *, message_id: str, sender_user_id: str, recipient_user_id: str, envelope: Dict[str, Any], created_at: str) -> None:
        self.conn.execute(
            'INSERT INTO dm_messages (id, sender_user_id, recipient_user_id, envelope_json, created_at) VALUES (?, ?, ?, ?, ?)',
            (message_id, sender_user_id, recipient_user_id, json.dumps(envelope, ensure_ascii=False), created_at),
        )
        self.conn.commit()

    def list_dm_messages(self, user_a: str, user_b: str) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT * FROM dm_messages
            WHERE (sender_user_id = ? AND recipient_user_id = ?)
               OR (sender_user_id = ? AND recipient_user_id = ?)
            ORDER BY created_at ASC
            """,
            (user_a, user_b, user_b, user_a),
        ).fetchall()
        return [
            {
                'id': row['id'],
                'sender_user_id': row['sender_user_id'],
                'recipient_user_id': row['recipient_user_id'],
                'envelope': json.loads(row['envelope_json']),
                'created_at': row['created_at'],
            }
            for row in rows
        ]
