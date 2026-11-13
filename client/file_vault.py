# -*- coding: utf-8 -*-
"""
File vault - stocare fișiere criptată la rest
Format pe disc: [16 salt unused][SecretBox(master_key, plaintext)]
Numele fișierului real e în header criptat.
"""

import os
import struct
from pathlib import Path
from typing import Tuple

from client.crypto_engine import encrypt_bytes, decrypt_bytes


def save_encrypted_file(vault_dir: Path, master_key: bytes, filename: str, data: bytes) -> Path:
    """Salvează fișier criptat. Returnează path-ul pe disc."""
    vault_dir.mkdir(parents=True, exist_ok=True)
    # header: name_len(2) + name + data
    name_b = filename.encode("utf-8")
    payload = struct.pack(">H", len(name_b)) + name_b + data
    encrypted = encrypt_bytes(payload, master_key)
    # nume pe disc opac
    disk_name = os.urandom(16).hex() + ".vault"
    path = vault_dir / disk_name
    path.write_bytes(encrypted)
    return path


def load_encrypted_file(path: Path, master_key: bytes) -> Tuple[str, bytes]:
    """Returnează (filename, data)."""
    encrypted = path.read_bytes()
    payload = decrypt_bytes(encrypted, master_key)
    name_len = struct.unpack(">H", payload[:2])[0]
    filename = payload[2:2 + name_len].decode("utf-8")
    data = payload[2 + name_len:]
    return filename, data


def export_to_temp(path: Path, master_key: bytes, temp_dir: Path) -> Path:
    """Decriptează temporar pentru deschidere. Caller trebuie să șteargă după."""
    filename, data = load_encrypted_file(path, master_key)
    # sanitize name
    safe = "".join(c if c.isalnum() or c in "._- " else "_" for c in filename)[:120]
    temp_dir.mkdir(parents=True, exist_ok=True)
    out = temp_dir / safe
    out.write_bytes(data)
    try:
        os.chmod(out, 0o600)
    except Exception:
        pass
    return out
