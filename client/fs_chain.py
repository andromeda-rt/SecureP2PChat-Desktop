# -*- coding: utf-8 -*-
"""SPC2 message-key chain (symmetric ratchet, not a full Double Ratchet).

Wire: b'FS2' || session_id[16] || message_number[4, big endian] || AEAD envelope.
The complete header and the ordered participant identities are authenticated
through the AEAD context. State export is intended to be encrypted by Storage.
"""
from __future__ import annotations

import base64
import hashlib
import struct
from typing import Dict, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from client.crypto_engine import encrypt_bytes, decrypt_bytes

_MAGIC = b"FS2"
_STATE_VERSION = 2
_MAX_SKIP = 1024
_MAX_COUNTER = 0xFFFFFFFF


def _hkdf(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None,
                info=info, backend=default_backend()).derive(ikm)


def _kdf_ck(chain_key: bytes) -> Tuple[bytes, bytes]:
    out = _hkdf(chain_key, b"SecureP2PChat-FS2-CK-v2", 64)
    return out[:32], out[32:]


def _id_hash(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()[:12]


class FSChain:
    """Per-contact symmetric message-key chain with authenticated framing."""
    __slots__ = ("send_ck", "recv_ck", "send_n", "recv_n", "skipped",
                 "session_id", "my_id", "peer_id")

    def __init__(self, session_key: bytes, my_id: str, peer_id: str):
        if not isinstance(session_key, bytes) or len(session_key) != 32:
            raise ValueError("session_key must be exactly 32 bytes")
        if not my_id or not peer_id or my_id == peer_id:
            raise ValueError("participant identities are invalid")
        self.my_id, self.peer_id = str(my_id), str(peer_id)
        lo, hi = sorted((self.my_id.encode(), self.peer_id.encode()))
        self.session_id = _hkdf(session_key, b"SecureP2PChat-FS2-session|" + lo + b"|" + hi, 16)
        self.send_ck = _hkdf(session_key, b"SecureP2PChat-FS2|send|" + self.my_id.encode() + b"|" + self.peer_id.encode())
        self.recv_ck = _hkdf(session_key, b"SecureP2PChat-FS2|send|" + self.peer_id.encode() + b"|" + self.my_id.encode())
        self.send_n = 0
        self.recv_n = 0
        self.skipped: Dict[int, bytes] = {}

    def _context(self, header: bytes) -> bytes:
        # Short, fixed-size identity binding keeps crypto_engine's context bound.
        return b"p2p-message-fs2|" + header + _id_hash(self.my_id) + _id_hash(self.peer_id)

    def encrypt(self, plaintext: bytes) -> bytes:
        if self.send_n > _MAX_COUNTER:
            raise OverflowError("FS2 message counter exhausted; establish a new session")
        next_ck, mk = _kdf_ck(self.send_ck)
        header = _MAGIC + self.session_id + struct.pack(">I", self.send_n)
        ciphertext = encrypt_bytes(plaintext, mk, context=self._context(header))
        # Advance only after successful AEAD encryption.
        self.send_ck, self.send_n = next_ck, self.send_n + 1
        return header + ciphertext

    def decrypt(self, blob: bytes) -> bytes:
        if not isinstance(blob, bytes) or len(blob) < 3 + 16 + 4 + 5 + 24 + 16:
            raise ValueError("FS2 frame too short")
        if blob[:3] != _MAGIC:
            raise ValueError("unsupported secure protocol frame")
        header, ciphertext = blob[:23], blob[23:]
        if header[3:19] != self.session_id:
            raise ValueError("FS2 session mismatch; re-pair contact")
        n = struct.unpack(">I", header[19:23])[0]
        context = b"p2p-message-fs2|" + header + _id_hash(self.peer_id) + _id_hash(self.my_id)

        if n in self.skipped:
            plaintext = decrypt_bytes(ciphertext, self.skipped[n], context=context)
            self.skipped.pop(n, None)
            return plaintext
        if n < self.recv_n:
            raise ValueError("FS2 replay or already-consumed message")
        if n - self.recv_n > _MAX_SKIP:
            raise ValueError(
                f"FS2 skip window exceeded (received={n}, expected={self.recv_n}, max={_MAX_SKIP})"
            )

        candidate_ck, candidate_n = self.recv_ck, self.recv_n
        candidate_skipped = dict(self.skipped)
        while candidate_n < n:
            candidate_ck, skipped_mk = _kdf_ck(candidate_ck)
            candidate_skipped[candidate_n] = skipped_mk
            candidate_n += 1
        next_ck, mk = _kdf_ck(candidate_ck)
        plaintext = decrypt_bytes(ciphertext, mk, context=context)
        candidate_skipped.pop(n, None)
        if len(candidate_skipped) > _MAX_SKIP:
            for old in sorted(candidate_skipped)[:len(candidate_skipped) - _MAX_SKIP]:
                candidate_skipped.pop(old, None)
        # Transactional commit: authentication must succeed first.
        self.recv_ck, self.recv_n, self.skipped = next_ck, n + 1, candidate_skipped
        return plaintext

    def export_state(self) -> bytes:
        import json
        data = {
            "version": _STATE_VERSION, "my_id": self.my_id, "peer_id": self.peer_id,
            "session_id": base64.b64encode(self.session_id).decode("ascii"),
            "send_ck": base64.b64encode(self.send_ck).decode("ascii"),
            "recv_ck": base64.b64encode(self.recv_ck).decode("ascii"),
            "send_n": self.send_n, "recv_n": self.recv_n,
            "skipped": {str(k): base64.b64encode(v).decode("ascii") for k, v in self.skipped.items()},
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @classmethod
    def import_state(cls, session_key: bytes, my_id: str, peer_id: str, raw: bytes) -> "FSChain":
        import json
        data = json.loads(raw.decode("utf-8"))
        if data.get("version") != _STATE_VERSION or data.get("my_id") != my_id or data.get("peer_id") != peer_id:
            raise ValueError("FS2 state version or participant mismatch")
        obj = cls(session_key, my_id, peer_id)
        dec = lambda s: base64.b64decode(s, validate=True)
        if dec(data["session_id"]) != obj.session_id:
            raise ValueError("FS2 state belongs to another session")
        send_ck, recv_ck = dec(data["send_ck"]), dec(data["recv_ck"])
        send_n, recv_n = data["send_n"], data["recv_n"]
        if len(send_ck) != 32 or len(recv_ck) != 32 or not isinstance(send_n, int) or not isinstance(recv_n, int) or not (0 <= send_n <= _MAX_COUNTER + 1 and 0 <= recv_n <= _MAX_COUNTER + 1):
            raise ValueError("FS2 state fields invalid")
        skipped = {int(k): dec(v) for k, v in data.get("skipped", {}).items()}
        if len(skipped) > _MAX_SKIP or any(k < 0 or k > _MAX_COUNTER or len(v) != 32 for k, v in skipped.items()):
            raise ValueError("FS2 skipped-key state invalid")
        obj.send_ck, obj.recv_ck = send_ck, recv_ck
        obj.send_n, obj.recv_n, obj.skipped = send_n, recv_n, skipped
        return obj


def is_fs_payload(blob: bytes) -> bool:
    return isinstance(blob, (bytes, bytearray)) and bytes(blob[:3]) == _MAGIC
