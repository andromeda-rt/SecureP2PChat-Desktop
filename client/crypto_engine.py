# -*- coding: utf-8 -*-
"""
Crypto Engine - Argon2id + X25519 + XSalsa20-Poly1305 + fingerprint
"""

import hashlib
from typing import Tuple

from argon2.low_level import hash_secret_raw, Type
from nacl.public import PrivateKey, PublicKey, Box
from nacl.secret import SecretBox
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
)
import os
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import RawEncoder
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from shared.constants import (
    ARGON2_TIME_COST,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_HASH_LEN,
)


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )


# Envelope versionat pentru criptarea locală și payload-uri. Prefixul permite
# migrarea transparentă a datelor istorice SecretBox. Datele noi folosesc
# XChaCha20-Poly1305 cu AAD (domain separation).
_ENVELOPE_MAGIC = b"SPC2"
_ENVELOPE_VERSION = 2
_DEFAULT_CONTEXT = b"storage"
_MAX_CONTEXT_LEN = 128


def _envelope_aad(context: bytes) -> bytes:
    if not isinstance(context, bytes) or not context or len(context) > _MAX_CONTEXT_LEN:
        raise ValueError("Context criptografic invalid")
    return b"SecureP2PChat\x00AEAD\x00v2\x00" + context


def encrypt_bytes(plaintext: bytes, key: bytes, context: bytes = _DEFAULT_CONTEXT) -> bytes:
    """Criptează cu XChaCha20-Poly1305; contextul este autentificat ca AAD."""
    if len(key) != 32:
        raise ValueError("Cheia trebuie să aibă 32 bytes")
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext trebuie să fie bytes")
    nonce = os.urandom(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
    aad = _envelope_aad(context)
    ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)
    return _ENVELOPE_MAGIC + bytes([_ENVELOPE_VERSION]) + nonce + ciphertext


def decrypt_bytes(ciphertext: bytes, key: bytes, context: bytes = _DEFAULT_CONTEXT) -> bytes:
    """Decriptează envelope v2; citește și formatul SecretBox istoric pentru migrare."""
    if len(key) != 32:
        raise ValueError("Cheia trebuie să aibă 32 bytes")
    if not isinstance(ciphertext, bytes):
        raise TypeError("ciphertext trebuie să fie bytes")
    if ciphertext.startswith(_ENVELOPE_MAGIC):
        min_len = len(_ENVELOPE_MAGIC) + 1 + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + 16
        if len(ciphertext) < min_len or ciphertext[len(_ENVELOPE_MAGIC)] != _ENVELOPE_VERSION:
            raise ValueError("Envelope criptografic invalid sau versiune nesuportată")
        pos = len(_ENVELOPE_MAGIC) + 1
        nonce = ciphertext[pos:pos + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES]
        encrypted = ciphertext[pos + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES:]
        return crypto_aead_xchacha20poly1305_ietf_decrypt(encrypted, _envelope_aad(context), nonce, key)
    # Compatibilitate numai la citire pentru mesajele/înregistrările create înainte de v2.
    return SecretBox(key).decrypt(ciphertext)


def generate_keypair() -> Tuple[PrivateKey, PublicKey]:
    private = PrivateKey.generate()
    return private, private.public_key


def perform_key_exchange(private_key: PrivateKey, peer_public_key: bytes) -> bytes:
    peer_pk = PublicKey(peer_public_key, encoder=RawEncoder)
    shared = Box(private_key, peer_pk).shared_key()
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"SecureP2PChat-SessionKey-v1",
        backend=default_backend(),
    )
    return hkdf.derive(shared)


def encrypt_message(session_key: bytes, plaintext: bytes) -> bytes:
    return encrypt_bytes(plaintext, session_key, context=b"p2p-message")


def decrypt_message(session_key: bytes, ciphertext: bytes) -> bytes:
    return decrypt_bytes(ciphertext, session_key, context=b"p2p-message")


def public_key_fingerprint(public_key_hex_or_bytes) -> str:
    """Fingerprint scurt pentru TOFU: SHA256, afișat ca grupuri de 4 hex."""
    if isinstance(public_key_hex_or_bytes, str):
        raw = bytes.fromhex(public_key_hex_or_bytes)
    else:
        raw = public_key_hex_or_bytes
    h = hashlib.sha256(raw).hexdigest().upper()
    # 12 grupuri de 4 = 48 caractere ușor de comparat
    return " ".join(h[i:i + 4] for i in range(0, 48, 4))


def secure_zero(data: bytearray) -> None:
    for i in range(len(data)):
        data[i] = 0


# --- Semnături pentru serverul de semnalizare (Ed25519 via PyNaCl SigningKey) ---

def signing_key_from_seed(seed32: bytes) -> SigningKey:
    """Derivă cheie de semnare din material existent (ex: hash al private X25519)."""
    # seed trebuie 32 bytes
    if len(seed32) != 32:
        seed32 = hashlib.sha256(seed32).digest()
    return SigningKey(seed32)


def sign_message(signing_key: SigningKey, message: bytes) -> bytes:
    return signing_key.sign(message).signature


def verify_signature(verify_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    try:
        vk = VerifyKey(verify_key_bytes)
        vk.verify(message, signature)
        return True
    except Exception:
        return False
