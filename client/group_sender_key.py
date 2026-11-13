# -*- coding: utf-8 -*-
"""Sender-key chain wire-compatible with the Android GSK1 implementation."""
from __future__ import annotations

import base64
import json
import struct
from typing import Dict, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from client.crypto_engine import decrypt_bytes, encrypt_bytes

_MAGIC = b"GSK1"
_STATE_VERSION = 1
_MAX_SKIP = 1024
_MAX_COUNTER = 0xFFFFFFFF


def _hkdf(ikm: bytes, info: bytes, length: int) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=length, salt=None,
        info=info, backend=default_backend(),
    ).derive(ikm)


def _next_chain_key(chain_key: bytes) -> Tuple[bytes, bytes]:
    output = _hkdf(chain_key, b"SecureP2PChat-GSK-CK-v1", 64)
    return output[:32], output[32:]


class GroupSenderKeyChain:
    def __init__(self, epoch_secret: bytes, group_id: str, epoch: int, sender_id: str):
        if len(epoch_secret) != 32 or not group_id or not sender_id or epoch <= 0:
            raise ValueError("invalid group sender-key context")
        self.group_id, self.epoch, self.sender_id = group_id, epoch, sender_id
        self.chain_key = _hkdf(
            epoch_secret,
            f"SecureP2PChat-GSK-v1|{group_id}|{epoch}|{sender_id}".encode(),
            32,
        )
        self.next_number = 0
        self.skipped: Dict[int, bytes] = {}

    def _context(self, header: bytes) -> bytes:
        return b"group-message-v1|" + self.group_id.encode() + b"\x00" + self.sender_id.encode() + header

    def encrypt(self, plaintext: bytes) -> bytes:
        if self.next_number > _MAX_COUNTER:
            raise OverflowError("group sender counter exhausted")
        header = _MAGIC + struct.pack(">QI", self.epoch, self.next_number)
        next_key, message_key = _next_chain_key(self.chain_key)
        ciphertext = encrypt_bytes(plaintext, message_key, self._context(header))
        self.chain_key, self.next_number = next_key, self.next_number + 1
        return header + ciphertext

    def decrypt(self, frame: bytes) -> bytes:
        if len(frame) < 16 + 4 + 1 + 24 + 16 or frame[:4] != _MAGIC:
            raise ValueError("invalid group sender-key frame")
        header, ciphertext = frame[:16], frame[16:]
        epoch, number = struct.unpack(">QI", header[4:])
        if epoch != self.epoch:
            raise ValueError("group epoch mismatch")
        context = self._context(header)
        if number in self.skipped:
            plain = decrypt_bytes(ciphertext, self.skipped[number], context)
            del self.skipped[number]
            return plain
        if number < self.next_number:
            raise ValueError("group message replay")
        if number - self.next_number > _MAX_SKIP:
            raise ValueError("group message skip window exceeded")

        candidate = self.chain_key
        candidate_skipped = dict(self.skipped)
        for index in range(self.next_number, number):
            candidate, message_key = _next_chain_key(candidate)
            candidate_skipped[index] = message_key
        next_key, message_key = _next_chain_key(candidate)
        plain = decrypt_bytes(ciphertext, message_key, context)
        candidate_skipped.pop(number, None)
        while len(candidate_skipped) > _MAX_SKIP:
            del candidate_skipped[min(candidate_skipped)]
        self.chain_key = next_key
        self.next_number = number + 1
        self.skipped = candidate_skipped
        return plain

    def export_state(self) -> bytes:
        data = {
            "version": _STATE_VERSION,
            "group_id": self.group_id,
            "epoch": self.epoch,
            "sender_id": self.sender_id,
            "chain_key": base64.b64encode(self.chain_key).decode("ascii"),
            "next_number": self.next_number,
            "skipped": {str(k): base64.b64encode(v).decode("ascii") for k, v in self.skipped.items()},
        }
        return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")

    @classmethod
    def import_state(cls, epoch_secret: bytes, raw: bytes) -> "GroupSenderKeyChain":
        data = json.loads(raw.decode("utf-8"))
        if data.get("version") != _STATE_VERSION:
            raise ValueError("unsupported group sender state")
        chain = cls(epoch_secret, data["group_id"], int(data["epoch"]), data["sender_id"])
        key = base64.b64decode(data["chain_key"], validate=True)
        number = data["next_number"]
        skipped = {int(k): base64.b64decode(v, validate=True) for k, v in data["skipped"].items()}
        if len(key) != 32 or not isinstance(number, int) or not 0 <= number <= _MAX_COUNTER + 1:
            raise ValueError("invalid group sender state")
        if len(skipped) > _MAX_SKIP or any(k < 0 or k >= number or len(v) != 32 for k, v in skipped.items()):
            raise ValueError("invalid skipped group keys")
        chain.chain_key, chain.next_number, chain.skipped = key, number, skipped
        return chain

    @staticmethod
    def is_frame(frame: bytes) -> bool:
        return isinstance(frame, (bytes, bytearray)) and bytes(frame[:4]) == _MAGIC
