# -*- coding: utf-8 -*-
"""
Storage securizat - mesaje, pending și metadate sensibile criptate
"""

import sqlite3
import time
import json
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass

from client.crypto_engine import encrypt_bytes, decrypt_bytes


@dataclass
class Contact:
    device_id: str
    display_name: str
    public_key: str
    last_ip: Optional[str] = None
    last_port: Optional[int] = None
    session_key: Optional[bytes] = None
    fingerprint: Optional[str] = None  # TOFU
    trusted: bool = False
    created_at: float = 0.0
    last_seen: float = 0.0


@dataclass
class Message:
    id: Optional[int]
    contact_id: str
    direction: str
    msg_type: str
    content: str
    timestamp: float
    status: str = "sent"


class Storage:
    def __init__(self, data_dir: Path, master_key: bytes):
        self.data_dir = data_dir
        self.master_key = master_key
        self.db_path = data_dir / "chat.db"
        self._session_keys = {}
        self._init_db()

    def _enc(self, data: bytes) -> bytes:
        return encrypt_bytes(data, self.master_key)

    def _dec(self, data: bytes) -> bytes:
        return decrypt_bytes(data, self.master_key)

    def _enc_str(self, s: str) -> bytes:
        return self._enc(s.encode("utf-8"))

    def _dec_str(self, b: bytes) -> str:
        return self._dec(b).decode("utf-8")

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS contacts (
                device_id TEXT PRIMARY KEY,
                display_name BLOB NOT NULL,
                public_key BLOB NOT NULL,
                last_ip BLOB,
                last_port INTEGER,
                fingerprint TEXT,
                trusted INTEGER DEFAULT 0,
                created_at REAL,
                last_seen REAL
            )
        """)
        # migrare coloane noi dacă DB vechi
        try:
            cur.execute("ALTER TABLE contacts ADD COLUMN fingerprint TEXT")
        except Exception:
            pass
        try:
            cur.execute("ALTER TABLE contacts ADD COLUMN trusted INTEGER DEFAULT 0")
        except Exception:
            pass

        cur.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contact_id TEXT NOT NULL,
                direction TEXT NOT NULL,
                msg_type TEXT NOT NULL,
                content BLOB NOT NULL,
                timestamp REAL NOT NULL,
                status TEXT DEFAULT 'sent'
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS deleted_peers (
                device_id TEXT PRIMARY KEY,
                deleted_at REAL NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS pending (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contact_id TEXT NOT NULL,
                payload BLOB NOT NULL,
                created_at REAL NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS pending_group_frames (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id TEXT NOT NULL,
                contact_id TEXT NOT NULL,
                payload BLOB NOT NULL,
                packed INTEGER NOT NULL DEFAULT 0,
                created_at REAL NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS pending_group_inbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                epoch INTEGER NOT NULL,
                payload BLOB NOT NULL,
                created_at REAL NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS ratchet_state (
                contact_id TEXT PRIMARY KEY,
                state BLOB NOT NULL,
                updated_at REAL NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS group_crypto_state (
                state_key TEXT PRIMARY KEY,
                state BLOB NOT NULL,
                updated_at REAL NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS groups (
                group_id TEXT PRIMARY KEY,
                metadata BLOB NOT NULL,
                updated_at REAL NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    def set_session_key(self, device_id: str, key: bytes):
        self._session_keys[device_id] = key

    def get_session_key(self, device_id: str) -> Optional[bytes]:
        return self._session_keys.get(device_id)

    def save_ratchet_state(self, device_id: str, state: bytes) -> None:
        """Persist ratchet state encrypted with the local master key."""
        if not device_id or not isinstance(state, bytes):
            raise ValueError("ratchet state invalid")
        encrypted = encrypt_bytes(state, self.master_key, context=b"ratchet-state-v2")
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "INSERT OR REPLACE INTO ratchet_state(contact_id, state, updated_at) VALUES (?, ?, ?)",
                (device_id, encrypted, time.time()),
            )
            conn.commit()
        finally:
            conn.close()

    def load_ratchet_state(self, device_id: str) -> Optional[bytes]:
        conn = sqlite3.connect(self.db_path)
        try:
            row = conn.execute("SELECT state FROM ratchet_state WHERE contact_id=?", (device_id,)).fetchone()
        finally:
            conn.close()
        if not row:
            return None
        return decrypt_bytes(row[0], self.master_key, context=b"ratchet-state-v2")

    def delete_ratchet_state(self, device_id: str) -> None:
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("DELETE FROM ratchet_state WHERE contact_id=?", (device_id,))
            conn.commit()
        finally:
            conn.close()

    def save_group_crypto_state(self, state_key: str, state: bytes) -> None:
        if not state_key or len(state_key.encode("utf-8")) > 100 or not isinstance(state, bytes):
            raise ValueError("group crypto state invalid")
        context = b"group-state-v1|" + state_key.encode("utf-8")
        encrypted = encrypt_bytes(state, self.master_key, context=context)
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "INSERT OR REPLACE INTO group_crypto_state(state_key, state, updated_at) VALUES (?, ?, ?)",
                (state_key, encrypted, time.time()),
            )
            conn.commit()
        finally:
            conn.close()

    def load_group_crypto_state(self, state_key: str) -> Optional[bytes]:
        if not state_key or len(state_key.encode("utf-8")) > 100:
            raise ValueError("group crypto state key invalid")
        conn = sqlite3.connect(self.db_path)
        try:
            row = conn.execute(
                "SELECT state FROM group_crypto_state WHERE state_key=?", (state_key,)
            ).fetchone()
        finally:
            conn.close()
        if not row:
            return None
        context = b"group-state-v1|" + state_key.encode("utf-8")
        return decrypt_bytes(row[0], self.master_key, context=context)

    def delete_group_crypto_state(self, group_id: str) -> None:
        if not group_id:
            raise ValueError("group id invalid")
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "DELETE FROM group_crypto_state WHERE state_key LIKE ? OR state_key LIKE ?",
                (f"gk|{group_id}|%", f"gs|{group_id}|%"),
            )
            conn.execute("DELETE FROM pending_group_frames WHERE group_id=?", (group_id,))
            conn.execute("DELETE FROM pending_group_inbox WHERE group_id=?", (group_id,))
            conn.commit()
        finally:
            conn.close()

    def save_group(self, group_id: str, metadata: dict) -> None:
        if not group_id or not isinstance(metadata, dict):
            raise ValueError("group metadata invalid")
        context = b"group-metadata-v1|" + group_id.encode("utf-8")
        encrypted = encrypt_bytes(
            json.dumps(metadata, separators=(",", ":")).encode("utf-8"),
            self.master_key,
            context=context,
        )
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "INSERT OR REPLACE INTO groups(group_id, metadata, updated_at) VALUES (?, ?, ?)",
                (group_id, encrypted, time.time()),
            )
            conn.commit()
        finally:
            conn.close()

    def load_groups(self) -> List[dict]:
        conn = sqlite3.connect(self.db_path)
        try:
            rows = conn.execute("SELECT group_id, metadata FROM groups").fetchall()
        finally:
            conn.close()
        groups = []
        for group_id, encrypted in rows:
            context = b"group-metadata-v1|" + group_id.encode("utf-8")
            metadata = json.loads(decrypt_bytes(encrypted, self.master_key, context).decode("utf-8"))
            if not isinstance(metadata, dict):
                raise ValueError("stored group metadata invalid")
            metadata["group_id"] = group_id
            groups.append(metadata)
        return groups

    def delete_group(self, group_id: str) -> None:
        if not group_id:
            raise ValueError("group id invalid")
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("DELETE FROM groups WHERE group_id=?", (group_id,))
            conn.execute("DELETE FROM pending_group_frames WHERE group_id=?", (group_id,))
            conn.execute("DELETE FROM pending_group_inbox WHERE group_id=?", (group_id,))
            conn.commit()
        finally:
            conn.close()

    def clear_session_keys(self):
        # Încearcă zero pe valorile vechi
        try:
            from client.secure_memory import secure_zero
            for k, v in list(self._session_keys.items()):
                if isinstance(v, (bytes, bytearray)):
                    ba = bytearray(v)
                    secure_zero(ba)
        except Exception:
            pass
        self._session_keys.clear()

    def add_contact(self, contact: Contact, force: bool = False):
        if not force and self.is_deleted_peer(getattr(contact, "device_id", "")):
            return  # șters de user – nu re-salva automat
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        last_ip_enc = self._enc_str(contact.last_ip) if contact.last_ip else None
        cur.execute("""
            INSERT OR REPLACE INTO contacts
            (device_id, display_name, public_key, last_ip, last_port, fingerprint, trusted, created_at, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            contact.device_id,
            self._enc_str(contact.display_name),
            self._enc_str(contact.public_key or ""),
            last_ip_enc,
            contact.last_port,
            contact.fingerprint,
            1 if contact.trusted else 0,
            contact.created_at or time.time(),
            contact.last_seen or time.time(),
        ))
        conn.commit()
        conn.close()
        if contact.session_key:
            self.set_session_key(contact.device_id, contact.session_key)

    def _row_to_contact(self, r) -> Contact:
        def safe_dec(b):
            if b is None:
                return None
            try:
                return self._dec_str(b)
            except Exception:
                # fallback pentru DB vechi necriptat (str)
                if isinstance(b, str):
                    return b
                try:
                    return b.decode("utf-8")
                except Exception:
                    return ""

        return Contact(
            device_id=r[0],
            display_name=safe_dec(r[1]) or "",
            public_key=safe_dec(r[2]) or "",
            last_ip=safe_dec(r[3]),
            last_port=r[4],
            fingerprint=r[5] if len(r) > 5 else None,
            trusted=bool(r[6]) if len(r) > 6 else False,
            created_at=r[7] if len(r) > 7 else 0,
            last_seen=r[8] if len(r) > 8 else 0,
        )

    def get_contacts(self) -> List[Contact]:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT device_id, display_name, public_key, last_ip, last_port, fingerprint, trusted, created_at, last_seen FROM contacts ORDER BY last_seen DESC")
        rows = cur.fetchall()
        conn.close()
        out = []
        for r in rows:
            c = self._row_to_contact(r)
            c.session_key = self._session_keys.get(c.device_id)
            out.append(c)
        return out

    def get_contact(self, device_id: str) -> Optional[Contact]:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT device_id, display_name, public_key, last_ip, last_port, fingerprint, trusted, created_at, last_seen FROM contacts WHERE device_id=?", (device_id,))
        r = cur.fetchone()
        conn.close()
        if not r:
            return None
        c = self._row_to_contact(r)
        c.session_key = self._session_keys.get(c.device_id)
        return c

    def update_contact_endpoint(self, device_id: str, ip: str, port: int):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "UPDATE contacts SET last_ip=?, last_port=?, last_seen=? WHERE device_id=?",
            (self._enc_str(ip), port, time.time(), device_id)
        )
        conn.commit()
        conn.close()

    def set_trusted(self, device_id: str, fingerprint: str, trusted: bool = True):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "UPDATE contacts SET fingerprint=?, trusted=? WHERE device_id=?",
            (fingerprint, 1 if trusted else 0, device_id)
        )
        conn.commit()
        conn.close()

    def save_message(self, msg: Message) -> int:
        content_bytes = msg.content.encode("utf-8") if isinstance(msg.content, str) else msg.content
        encrypted_content = self._enc(content_bytes)
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO messages (contact_id, direction, msg_type, content, timestamp, status)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (msg.contact_id, msg.direction, msg.msg_type, encrypted_content, msg.timestamp, msg.status))
        msg_id = cur.lastrowid
        conn.commit()
        conn.close()
        return msg_id

    def delete_messages(self, contact_id: str) -> int:
        """Șterge toate mesajele unui contact/grup. Returnează câte au fost șterse."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM messages WHERE contact_id=?", (contact_id,))
        n = cur.fetchone()[0]
        cur.execute("DELETE FROM messages WHERE contact_id=?", (contact_id,))
        conn.commit()
        conn.close()
        return int(n or 0)

    def delete_contact(self, device_id: str) -> None:
        """Șterge contact + mesaje + session key + pending + marchează ca șters definitiv."""
        self.delete_messages(device_id)
        self._session_keys.pop(device_id, None)
        self.delete_ratchet_state(device_id)
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("DELETE FROM contacts WHERE device_id=?", (device_id,))
        try:
            cur.execute("DELETE FROM pending WHERE contact_id=?", (device_id,))
            cur.execute("DELETE FROM pending_group_frames WHERE contact_id=?", (device_id,))
        except Exception:
            pass
        # listă de exclus: nu se readaugă automat din HELLO/relay
        cur.execute(
            "INSERT OR REPLACE INTO deleted_peers (device_id, deleted_at) VALUES (?, ?)",
            (device_id, time.time()),
        )
        conn.commit()
        conn.close()

    def is_deleted_peer(self, device_id: str) -> bool:
        """True dacă userul a șters explicit contactul (până la add/pair manual)."""
        if not device_id:
            return False
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        try:
            cur.execute(
                "CREATE TABLE IF NOT EXISTS deleted_peers ("
                "device_id TEXT PRIMARY KEY, deleted_at REAL NOT NULL)"
            )
            cur.execute("SELECT 1 FROM deleted_peers WHERE device_id=?", (device_id,))
            return cur.fetchone() is not None
        except Exception:
            return False
        finally:
            conn.close()

    def clear_deleted_peer(self, device_id: str) -> None:
        """Permite din nou contactul (add manual / pair cu cod)."""
        if not device_id:
            return
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        try:
            cur.execute("DELETE FROM deleted_peers WHERE device_id=?", (device_id,))
            conn.commit()
        except Exception:
            pass
        finally:
            conn.close()

    def get_messages(self, contact_id: str, limit: int = 200) -> List[Message]:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("""
            SELECT id, contact_id, direction, msg_type, content, timestamp, status
            FROM messages WHERE contact_id=? ORDER BY timestamp DESC LIMIT ?
        """, (contact_id, limit))
        rows = list(reversed(cur.fetchall()))
        conn.close()
        messages = []
        for r in rows:
            try:
                content = self._dec(r[4]).decode("utf-8")
            except Exception:
                content = "[mesaj corupt / cheie greșită]"
            messages.append(Message(
                id=r[0], contact_id=r[1], direction=r[2],
                msg_type=r[3], content=content, timestamp=r[5], status=r[6]
            ))
        return messages

    def add_pending(self, contact_id: str, payload: bytes):
        """Pending CRIPTAT cu master_key."""
        enc = self._enc(payload)
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO pending (contact_id, payload, created_at) VALUES (?, ?, ?)",
            (contact_id, enc, time.time())
        )
        conn.commit()
        conn.close()

    def get_pending(self, contact_id: str) -> List[bytes]:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT payload FROM pending WHERE contact_id=? ORDER BY created_at", (contact_id,))
        rows = cur.fetchall()
        conn.close()
        out = []
        for r in rows:
            try:
                out.append(self._dec(r[0]))
            except Exception:
                pass
        return out

    def clear_pending(self, contact_id: str):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("DELETE FROM pending WHERE contact_id=?", (contact_id,))
        conn.commit()
        conn.close()

    @staticmethod
    def _pending_group_context(group_id: str, contact_id: str) -> bytes:
        return b"pending-group-frame-v1|" + group_id.encode("utf-8") + b"|" + contact_id.encode("utf-8")

    def add_pending_group_frame(
        self, group_id: str, contact_id: str, payload: bytes, packed: bool = False
    ) -> int:
        if not group_id or not contact_id or not isinstance(payload, bytes):
            raise ValueError("pending group frame invalid")
        encrypted = encrypt_bytes(
            payload, self.master_key,
            context=self._pending_group_context(group_id, contact_id),
        )
        conn = sqlite3.connect(self.db_path)
        try:
            count = conn.execute(
                "SELECT COUNT(*) FROM pending_group_frames WHERE contact_id=?",
                (contact_id,),
            ).fetchone()[0]
            if count >= 2000:
                raise ValueError("pending group frame queue is full")
            cur = conn.execute(
                "INSERT INTO pending_group_frames"
                "(group_id, contact_id, payload, packed, created_at) VALUES (?, ?, ?, ?, ?)",
                (group_id, contact_id, encrypted, int(packed), time.time()),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    def get_pending_group_frames(self, contact_id: str) -> List[dict]:
        conn = sqlite3.connect(self.db_path)
        try:
            rows = conn.execute(
                "SELECT id, group_id, payload, packed FROM pending_group_frames "
                "WHERE contact_id=? ORDER BY id",
                (contact_id,),
            ).fetchall()
        finally:
            conn.close()
        return [{
            "id": row[0],
            "group_id": row[1],
            "payload": decrypt_bytes(
                row[2], self.master_key,
                context=self._pending_group_context(row[1], contact_id),
            ),
            "packed": bool(row[3]),
        } for row in rows]

    def update_pending_group_frame(
        self, frame_id: int, group_id: str, contact_id: str,
        payload: bytes, packed: bool,
    ) -> None:
        if not isinstance(payload, bytes):
            raise ValueError("pending group frame invalid")
        encrypted = encrypt_bytes(
            payload, self.master_key,
            context=self._pending_group_context(group_id, contact_id),
        )
        conn = sqlite3.connect(self.db_path)
        try:
            cur = conn.execute(
                "UPDATE pending_group_frames SET payload=?, packed=? "
                "WHERE id=? AND group_id=? AND contact_id=?",
                (encrypted, int(packed), frame_id, group_id, contact_id),
            )
            if cur.rowcount != 1:
                raise ValueError("pending group frame not found")
            conn.commit()
        finally:
            conn.close()

    def delete_pending_group_frame(self, frame_id: int) -> None:
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("DELETE FROM pending_group_frames WHERE id=?", (frame_id,))
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def _pending_group_inbox_context(group_id: str, sender_id: str) -> bytes:
        return b"pending-group-inbox-v1|" + group_id.encode("utf-8") + b"|" + sender_id.encode("utf-8")

    def add_pending_group_inbox(
        self, group_id: str, sender_id: str, epoch: int, payload: bytes
    ) -> int:
        if (not group_id or not sender_id or epoch <= 0
                or not isinstance(payload, bytes)):
            raise ValueError("pending group inbox frame invalid")
        encrypted = encrypt_bytes(
            payload, self.master_key,
            context=self._pending_group_inbox_context(group_id, sender_id),
        )
        conn = sqlite3.connect(self.db_path)
        try:
            count = conn.execute(
                "SELECT COUNT(*) FROM pending_group_inbox WHERE group_id=?",
                (group_id,),
            ).fetchone()[0]
            if count >= 2000:
                raise ValueError("pending group inbox is full")
            cur = conn.execute(
                "INSERT INTO pending_group_inbox"
                "(group_id, sender_id, epoch, payload, created_at) VALUES (?, ?, ?, ?, ?)",
                (group_id, sender_id, epoch, encrypted, time.time()),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    def get_pending_group_inbox(self, group_id: str) -> List[dict]:
        conn = sqlite3.connect(self.db_path)
        try:
            rows = conn.execute(
                "SELECT id, sender_id, epoch, payload FROM pending_group_inbox "
                "WHERE group_id=? ORDER BY id",
                (group_id,),
            ).fetchall()
        finally:
            conn.close()
        return [{
            "id": row[0],
            "sender_id": row[1],
            "epoch": row[2],
            "payload": decrypt_bytes(
                row[3], self.master_key,
                context=self._pending_group_inbox_context(group_id, row[1]),
            ),
        } for row in rows]

    def delete_pending_group_inbox(self, frame_id: int) -> None:
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("DELETE FROM pending_group_inbox WHERE id=?", (frame_id,))
            conn.commit()
        finally:
            conn.close()
