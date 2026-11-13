# -*- coding: utf-8 -*-
"""Logarithmic TreeKEM (RFC 9420 / MLS) ratchet tree wire-compatible with Android."""
from __future__ import annotations

import base64
import json
import os
import struct
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from client.crypto_engine import decrypt_bytes, encrypt_bytes

_MAGIC = b"TKEM"
_VERSION = 1


def _hkdf(ikm: bytes, info: bytes, length: int) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
        backend=default_backend(),
    ).derive(ikm)


def _derive_x25519_keypair(secret: bytes, info: bytes) -> Tuple[bytes, bytes]:
    priv_bytes = _hkdf(secret, info, 32)
    priv = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_bytes, pub_bytes


def _generate_x25519_keypair() -> Tuple[bytes, bytes]:
    priv = x25519.X25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_bytes, pub_bytes


def _raw_key_agreement(priv_bytes: bytes, pub_bytes: bytes) -> bytes:
    priv = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
    pub = x25519.X25519PublicKey.from_public_bytes(pub_bytes)
    return priv.exchange(pub)


def calculate_tree_height(n: int) -> int:
    if n <= 1:
        return 1
    h = 0
    temp = n - 1
    while temp > 0:
        h += 1
        temp >>= 1
    return max(1, h)


class EncryptedSecret:
    def __init__(self, target_level: int, target_index: int, eph_pub: bytes, ciphertext: bytes):
        self.target_level = target_level
        self.target_index = target_index
        self.eph_pub = eph_pub
        self.ciphertext = ciphertext


class PathNode:
    def __init__(self, level: int, node_pub: bytes, secrets: List[EncryptedSecret]):
        self.level = level
        self.node_pub = node_pub
        self.secrets = secrets


class TreeKEMGroup:
    def __init__(self, group_id: str, epoch: int, my_device_id: str, members: List[str]):
        if not group_id or not my_device_id or not members:
            raise ValueError("invalid TreeKEM context")
        self.group_id = group_id
        self.epoch = int(epoch)
        self.my_device_id = my_device_id
        self.roster = sorted(list(set(members)))
        if my_device_id not in self.roster:
            raise ValueError("local device not in group roster")
        self.my_leaf_index = self.roster.index(my_device_id)

        # Nodes: (level, index) -> 32-byte public key
        self.public_nodes: Dict[Tuple[int, int], bytes] = {}
        # Private keys: (level, index) -> 32-byte private key
        self.private_nodes: Dict[Tuple[int, int], bytes] = {}

    @property
    def member_count(self) -> int:
        return len(self.roster)

    def tree_height(self) -> int:
        return calculate_tree_height(self.member_count)

    def set_leaf_keypair(self, leaf_index: int, private_key: Optional[bytes], public_key: bytes):
        if not (0 <= leaf_index < self.member_count) or len(public_key) != 32:
            raise ValueError("invalid leaf keypair")
        self.public_nodes[(0, leaf_index)] = bytes(public_key)
        if private_key is not None and leaf_index == self.my_leaf_index:
            if len(private_key) != 32:
                raise ValueError("invalid leaf private key")
            self.private_nodes[(0, leaf_index)] = bytes(private_key)

    def resolution(self, level: int, index: int) -> List[Tuple[Tuple[int, int], bytes]]:
        key = (level, index)
        if key in self.public_nodes:
            return [(key, self.public_nodes[key])]
        if level == 0:
            return []
        left = self.resolution(level - 1, index * 2)
        right = self.resolution(level - 1, index * 2 + 1)
        return left + right

    def generate_commit(self) -> Tuple[bytes, bytes]:
        next_epoch = self.epoch + 1
        height = self.tree_height()
        path_nodes: List[PathNode] = []

        leaf_secret = os.urandom(32)
        current_secret = leaf_secret

        priv_leaf, pub_leaf = _derive_x25519_keypair(
            current_secret,
            f"MLS-TreeKEM-Leaf|{self.group_id}|{next_epoch}|{self.my_leaf_index}".encode("utf-8"),
        )
        self.public_nodes[(0, self.my_leaf_index)] = pub_leaf
        self.private_nodes[(0, self.my_leaf_index)] = priv_leaf

        for l in range(1, height + 1):
            sibling_idx = (self.my_leaf_index >> (l - 1)) ^ 1
            targets = self.resolution(l - 1, sibling_idx)

            current_secret = _hkdf(
                current_secret,
                f"MLS-TreeKEM-Path|{self.group_id}|{next_epoch}|{l}".encode("utf-8"),
                32,
            )
            priv_node, pub_node = _derive_x25519_keypair(
                current_secret,
                f"MLS-TreeKEM-Priv|{self.group_id}|{next_epoch}|{l}".encode("utf-8"),
            )
            ancestor_idx = self.my_leaf_index >> l
            self.public_nodes[(l, ancestor_idx)] = pub_node
            self.private_nodes[(l, ancestor_idx)] = priv_node

            encrypted_list: List[EncryptedSecret] = []
            for (t_level, t_idx), target_pub in targets:
                eph_priv, eph_pub = _generate_x25519_keypair()
                shared = _raw_key_agreement(eph_priv, target_pub)
                enc_key = _hkdf(
                    shared,
                    f"MLS-TreeKEM-EncKey|{self.group_id}|{next_epoch}|{l}|{t_level},{t_idx}".encode("utf-8"),
                    32,
                )
                aad = f"MLS-TreeKEM-AAD|{self.group_id}|{next_epoch}|{l}|{t_level},{t_idx}".encode("utf-8")
                ct = encrypt_bytes(current_secret, enc_key, aad)
                encrypted_list.append(EncryptedSecret(t_level, t_idx, eph_pub, ct))

            path_nodes.append(PathNode(l, pub_node, encrypted_list))

        epoch_secret = _hkdf(
            current_secret,
            f"MLS-TreeKEM-EpochSecret|{self.group_id}|{next_epoch}".encode("utf-8"),
            32,
        )
        self.epoch = next_epoch
        frame = self.serialize_commit(next_epoch, self.my_leaf_index, len(self.roster), path_nodes)
        return frame, epoch_secret

    def process_commit(self, frame: bytes) -> bytes:
        commit_epoch, committer_leaf, roster_count, path_nodes = self.parse_commit(frame)
        if roster_count != len(self.roster) or not (0 <= committer_leaf < self.member_count):
            raise ValueError("commit roster or committer mismatch")
        if commit_epoch != self.epoch + 1:
            raise ValueError(f"commit epoch mismatch (expected {self.epoch + 1}, got {commit_epoch})")

        if committer_leaf == self.my_leaf_index:
            return b""

        diff = self.my_leaf_index ^ committer_leaf
        intersect_level = diff.bit_length()
        height = self.tree_height()
        if not (1 <= intersect_level <= height):
            raise ValueError(f"invalid tree intersection level {intersect_level}")

        path_node = next((p for p in path_nodes if p.level == intersect_level), None)
        if path_node is None:
            raise ValueError(f"commit path missing intersection level {intersect_level}")

        decrypted_secret = None
        for s in path_node.secrets:
            priv = self.private_nodes.get((s.target_level, s.target_index))
            if priv is not None:
                shared = _raw_key_agreement(priv, s.eph_pub)
                enc_key = _hkdf(
                    shared,
                    f"MLS-TreeKEM-EncKey|{self.group_id}|{commit_epoch}|{intersect_level}|{s.target_level},{s.target_index}".encode("utf-8"),
                    32,
                )
                aad = f"MLS-TreeKEM-AAD|{self.group_id}|{commit_epoch}|{intersect_level}|{s.target_level},{s.target_index}".encode("utf-8")
                decrypted_secret = decrypt_bytes(s.ciphertext, enc_key, aad)
                break

        if decrypted_secret is None:
            raise ValueError(f"could not decrypt TreeKEM path at level {intersect_level}")

        current_secret = decrypted_secret
        ancestor_idx = committer_leaf >> intersect_level
        priv_node, pub_node = _derive_x25519_keypair(
            current_secret,
            f"MLS-TreeKEM-Priv|{self.group_id}|{commit_epoch}|{intersect_level}".encode("utf-8"),
        )
        self.public_nodes[(intersect_level, ancestor_idx)] = pub_node
        self.private_nodes[(intersect_level, ancestor_idx)] = priv_node

        for l in range(intersect_level + 1, height + 1):
            current_secret = _hkdf(
                current_secret,
                f"MLS-TreeKEM-Path|{self.group_id}|{commit_epoch}|{l}".encode("utf-8"),
                32,
            )
            priv_node, pub_node = _derive_x25519_keypair(
                current_secret,
                f"MLS-TreeKEM-Priv|{self.group_id}|{commit_epoch}|{l}".encode("utf-8"),
            )
            higher_idx = committer_leaf >> l
            self.public_nodes[(l, higher_idx)] = pub_node
            self.private_nodes[(l, higher_idx)] = priv_node

        for p in path_nodes:
            idx = committer_leaf >> p.level
            self.public_nodes[(p.level, idx)] = bytes(p.node_pub)

        epoch_secret = _hkdf(
            current_secret,
            f"MLS-TreeKEM-EpochSecret|{self.group_id}|{commit_epoch}".encode("utf-8"),
            32,
        )
        self.epoch = commit_epoch
        return epoch_secret

    def export_state(self) -> bytes:
        data = {
            "version": 1,
            "group_id": self.group_id,
            "epoch": self.epoch,
            "my_id": self.my_device_id,
            "roster": self.roster,
            "public_nodes": {
                f"{k[0]},{k[1]}": base64.b64encode(v).decode("ascii")
                for k, v in self.public_nodes.items()
            },
            "private_nodes": {
                f"{k[0]},{k[1]}": base64.b64encode(v).decode("ascii")
                for k, v in self.private_nodes.items()
            },
        }
        return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")

    @classmethod
    def import_state(cls, raw: bytes) -> "TreeKEMGroup":
        data = json.loads(raw.decode("utf-8"))
        if data.get("version") != 1:
            raise ValueError("unsupported TreeKEM state version")
        group = cls(data["group_id"], data["epoch"], data["my_id"], data["roster"])
        for k, v in data.get("public_nodes", {}).items():
            lvl, idx = map(int, k.split(","))
            group.public_nodes[(lvl, idx)] = base64.b64decode(v)
        for k, v in data.get("private_nodes", {}).items():
            lvl, idx = map(int, k.split(","))
            group.private_nodes[(lvl, idx)] = base64.b64decode(v)
        return group

    def destroy(self):
        self.private_nodes.clear()
        self.public_nodes.clear()

    @staticmethod
    def is_commit_frame(payload: bytes) -> bool:
        return (
            isinstance(payload, (bytes, bytearray))
            and len(payload) >= 19
            and bytes(payload[:4]) == _MAGIC
            and payload[4] == _VERSION
        )

    @classmethod
    def serialize_commit(
        cls, epoch: int, committer_leaf: int, roster_count: int, path_nodes: List[PathNode]
    ) -> bytes:
        header = _MAGIC + bytes([_VERSION]) + struct.pack(">QIH I", epoch, committer_leaf, roster_count, len(path_nodes))
        body = bytearray(header)
        for p in path_nodes:
            body.append(p.level)
            body.extend(p.node_pub)
            body.extend(struct.pack(">H", len(p.secrets)))
            for s in p.secrets:
                body.append(s.target_level)
                body.extend(struct.pack(">I", s.target_index))
                body.extend(s.eph_pub)
                body.extend(struct.pack(">H", len(s.ciphertext)))
                body.extend(s.ciphertext)
        return bytes(body)

    @classmethod
    def parse_commit(cls, frame: bytes) -> Tuple[int, int, int, List[PathNode]]:
        if not cls.is_commit_frame(frame):
            raise ValueError("invalid TreeKEM commit frame")
        epoch, committer_leaf, roster_count, path_count = struct.unpack(">QIH I", frame[5:23])
        offset = 23
        nodes: List[PathNode] = []
        for _ in range(path_count):
            level = frame[offset]
            offset += 1
            node_pub = frame[offset : offset + 32]
            offset += 32
            secrets_count = struct.unpack(">H", frame[offset : offset + 2])[0]
            offset += 2
            secrets: List[EncryptedSecret] = []
            for _ in range(secrets_count):
                target_level = frame[offset]
                offset += 1
                target_idx = struct.unpack(">I", frame[offset : offset + 4])[0]
                offset += 4
                eph_pub = frame[offset : offset + 32]
                offset += 32
                ct_len = struct.unpack(">H", frame[offset : offset + 2])[0]
                offset += 2
                ct = frame[offset : offset + ct_len]
                offset += ct_len
                secrets.append(EncryptedSecret(target_level, target_idx, eph_pub, ct))
            nodes.append(PathNode(level, node_pub, secrets))
        return epoch, committer_leaf, roster_count, nodes
