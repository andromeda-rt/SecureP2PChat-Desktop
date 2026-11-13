# -*- coding: utf-8 -*-
"""
Identity Manager - chei protejate + LockedKey pentru master_key
"""

import os
import hashlib
import platform
import uuid
import json
from pathlib import Path
from typing import Optional

from nacl.public import PrivateKey, PublicKey
from nacl.encoding import RawEncoder
from nacl.signing import SigningKey

from client.secure_memory import LockedKey, secure_zero


def get_hardware_fingerprint() -> str:
    parts = []
    try:
        if platform.system() == "Windows":
            import subprocess
            result = subprocess.run(
                ["wmic", "csproduct", "get", "uuid"],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            lines = [l.strip() for l in result.stdout.splitlines() if l.strip() and "UUID" not in l.upper()]
            if lines:
                parts.append(lines[0])
        else:
            machine_id_path = Path("/etc/machine-id")
            if machine_id_path.exists():
                parts.append(machine_id_path.read_text().strip())
    except Exception:
        pass
    try:
        mac = uuid.getnode()
        parts.append(f"{mac:012x}")
    except Exception:
        pass
    parts.append(platform.node())
    parts.append(platform.system())
    parts.append(platform.machine())
    try:
        parts.append(platform.processor())
    except Exception:
        pass
    return hashlib.sha3_256("|".join(filter(None, parts)).encode("utf-8")).hexdigest()


class IdentityManager:
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.identity_file = self.data_dir / "identity.bin"
        self.private_key: Optional[PrivateKey] = None
        self.public_key: Optional[PublicKey] = None
        self.device_id: Optional[str] = None
        self.display_name: Optional[str] = None
        self.salt: Optional[bytes] = None
        self._master_key: Optional[LockedKey] = None
        self._signing_key: Optional[SigningKey] = None

    def exists(self) -> bool:
        return self.identity_file.exists()

    def create(self, display_name: str, password: str) -> None:
        from client.crypto_engine import derive_key_from_password, encrypt_bytes

        self.private_key = PrivateKey.generate()
        self.public_key = self.private_key.public_key
        self.salt = os.urandom(16)

        hw_fp = get_hardware_fingerprint()
        install_salt = os.urandom(16).hex()
        raw_id = f"{hw_fp}:{install_salt}:{display_name}"
        self.device_id = hashlib.sha3_256(raw_id.encode()).hexdigest()[:32]
        self.display_name = display_name

        mk = derive_key_from_password(password, self.salt)
        self._master_key = LockedKey(mk)
        # zero temp
        if isinstance(mk, bytearray):
            secure_zero(mk)

        self._init_signing_key()

        payload = {
            "device_id": self.device_id,
            "display_name": self.display_name,
            "public_key": self.public_key.encode(encoder=RawEncoder).hex(),
            "private_key": self.private_key.encode(encoder=RawEncoder).hex(),
            "version": 3,
        }
        raw = json.dumps(payload).encode("utf-8")
        encrypted = encrypt_bytes(raw, self._master_key.get())
        self.identity_file.write_bytes(self.salt + encrypted)
        # password e string Python – nu putem zero sigur, doar out of scope
        del password



    def unlock(self, password: str) -> bool:
        from client.crypto_engine import derive_key_from_password, decrypt_bytes
        if not self.exists():
            return False
        try:
            data = self.identity_file.read_bytes()
            if len(data) < 17:
                return False
            self.salt = data[:16]
            mk = derive_key_from_password(password, self.salt)
            self._master_key = LockedKey(mk)
            del password
            raw = decrypt_bytes(data[16:], self._master_key.get())
            payload = json.loads(raw.decode("utf-8"))
            self.device_id = payload["device_id"]
            self.display_name = payload["display_name"]
            self.public_key = PublicKey(bytes.fromhex(payload["public_key"]), encoder=RawEncoder)
            self.private_key = PrivateKey(bytes.fromhex(payload["private_key"]), encoder=RawEncoder)
            self._init_signing_key()
            return True
        except Exception:
            self.lock()
            return False

    def _init_signing_key(self):
        if not self.private_key:
            return
        from client.crypto_engine import signing_key_from_seed
        seed = hashlib.sha256(
            b"SecureP2PChat-SignSeed-v1" + self.private_key.encode(encoder=RawEncoder)
        ).digest()
        self._signing_key = signing_key_from_seed(seed)

    def get_signing_key(self) -> Optional[SigningKey]:
        return self._signing_key

    def get_verify_key_bytes(self) -> Optional[bytes]:
        if self._signing_key:
            return bytes(self._signing_key.verify_key)
        return None

    def get_master_key(self) -> Optional[bytes]:
        if self._master_key is None:
            return None
        try:
            return self._master_key.get()
        except RuntimeError:
            return None

    def get_fingerprint(self) -> str:
        from client.crypto_engine import public_key_fingerprint
        if not self.public_key:
            return ""
        return public_key_fingerprint(self.public_key.encode(encoder=RawEncoder))

    def get_public_info(self) -> dict:
        return {
            "device_id": self.device_id,
            "display_name": self.display_name,
            "public_key": self.public_key.encode(encoder=RawEncoder).hex() if self.public_key else None,
            "fingerprint": self.get_fingerprint(),
        }

    def lock(self):
        """Șterge din RAM: master key, private key, signing key."""
        if self._master_key:
            self._master_key.clear()
            self._master_key = None
        self.private_key = None
        self.public_key = None
        self._signing_key = None
        self.device_id = None
        self.display_name = None
        self.salt = None
