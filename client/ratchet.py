# -*- coding: utf-8 -*-
"""
EXPERIMENTAL — ratchet simplificat, neintegrat în fluxul aplicației.

ATENȚIE: această clasă NU este o implementare Signal Double Ratchet validată
și NU trebuie folosită în producție. În special, headerul nu este autentificat
ca associated data, iar gestionarea stării/skipped keys nu a fost verificată
formal. Fluxul principal folosește în prezent cheia de sesiune statică din
crypto_engine.py. Consultați SECURITY_AUDIT_0.9.11.md.
"""

import os
import struct
from typing import Optional, Tuple, Dict
from dataclasses import dataclass, field

from nacl.public import PrivateKey, PublicKey, Box
from nacl.secret import SecretBox
from nacl.encoding import RawEncoder
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def _kdf_rk(root_key: bytes, dh_out: bytes) -> Tuple[bytes, bytes]:
    """KDF pe root key → (new_root_key, chain_key)."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=root_key,
        info=b"SecureP2PChat-Ratchet-RK",
        backend=default_backend(),
    )
    out = hkdf.derive(dh_out)
    return out[:32], out[32:]


def _kdf_ck(chain_key: bytes) -> Tuple[bytes, bytes]:
    """KDF pe chain key → (new_chain_key, message_key)."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=b"\x00" * 32,
        info=b"SecureP2PChat-Ratchet-CK",
        backend=default_backend(),
    )
    out = hkdf.derive(chain_key)
    return out[:32], out[32:]


@dataclass
class RatchetState:
    root_key: bytes
    send_chain_key: Optional[bytes] = None
    recv_chain_key: Optional[bytes] = None
    send_n: int = 0
    recv_n: int = 0
    prev_send_n: int = 0
    dh_priv: Optional[PrivateKey] = None
    dh_pub: Optional[PublicKey] = None
    remote_dh_pub: Optional[PublicKey] = None
    # skipped message keys: (dh_pub_hex, n) -> msg_key
    skipped: Dict[Tuple[str, int], bytes] = field(default_factory=dict)
    MAX_SKIP = 100


class DoubleRatchet:
    def __init__(self, state: RatchetState):
        self.state = state

    @staticmethod
    def init_sender(shared_secret: bytes, remote_public: bytes) -> "DoubleRatchet":
        """Inițializare după X25519 handshake (partea care trimite prima)."""
        dh_priv = PrivateKey.generate()
        remote_pk = PublicKey(remote_public, encoder=RawEncoder)
        box = Box(dh_priv, remote_pk)
        rk, ck = _kdf_rk(shared_secret, box.shared_key())
        st = RatchetState(
            root_key=rk,
            send_chain_key=ck,
            dh_priv=dh_priv,
            dh_pub=dh_priv.public_key,
            remote_dh_pub=remote_pk,
        )
        return DoubleRatchet(st)

    @staticmethod
    def init_receiver(shared_secret: bytes, local_private: PrivateKey) -> "DoubleRatchet":
        """Inițializare receptor (așteaptă primul mesaj cu header DH)."""
        st = RatchetState(
            root_key=shared_secret,
            dh_priv=local_private,
            dh_pub=local_private.public_key,
        )
        return DoubleRatchet(st)

    def _dh(self, priv: PrivateKey, pub: PublicKey) -> bytes:
        return Box(priv, pub).shared_key()

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Returnează: header_len(2) + dh_pub(32) + n(4) + pn(4) + ciphertext
        """
        st = self.state
        if st.send_chain_key is None:
            # ratchet step dacă nu avem send chain
            if st.remote_dh_pub is None:
                raise RuntimeError("Ratchet: lipsește remote DH")
            st.dh_priv = PrivateKey.generate()
            st.dh_pub = st.dh_priv.public_key
            dh_out = self._dh(st.dh_priv, st.remote_dh_pub)
            st.root_key, st.send_chain_key = _kdf_rk(st.root_key, dh_out)
            st.prev_send_n = st.send_n
            st.send_n = 0

        st.send_chain_key, msg_key = _kdf_ck(st.send_chain_key)
        n = st.send_n
        pn = st.prev_send_n
        st.send_n += 1

        box = SecretBox(msg_key)
        ct = box.encrypt(plaintext)

        dh_raw = st.dh_pub.encode(encoder=RawEncoder)
        header = dh_raw + struct.pack(">II", n, pn)
        return struct.pack(">H", len(header)) + header + ct

    def decrypt(self, blob: bytes) -> bytes:
        st = self.state
        if len(blob) < 2:
            raise ValueError("Mesaj ratchet prea scurt")
        hlen = struct.unpack(">H", blob[:2])[0]
        header = blob[2:2 + hlen]
        ct = blob[2 + hlen:]
        if len(header) < 40:
            raise ValueError("Header invalid")

        dh_raw = header[:32]
        n, pn = struct.unpack(">II", header[32:40])
        remote_pk = PublicKey(dh_raw, encoder=RawEncoder)
        key_id = (dh_raw.hex(), n)

        # skipped keys
        if key_id in st.skipped:
            msg_key = st.skipped.pop(key_id)
            return SecretBox(msg_key).decrypt(ct)

        # DH ratchet dacă e cheie nouă
        if st.remote_dh_pub is None or remote_pk.encode(encoder=RawEncoder) != st.remote_dh_pub.encode(encoder=RawEncoder):
            self._skip_message_keys(pn)
            # recv chain din DH nou
            if st.dh_priv is None:
                st.dh_priv = PrivateKey.generate()
                st.dh_pub = st.dh_priv.public_key
            dh_out = self._dh(st.dh_priv, remote_pk)
            st.root_key, st.recv_chain_key = _kdf_rk(st.root_key, dh_out)
            st.remote_dh_pub = remote_pk
            st.recv_n = 0
            # send chain nouă
            st.dh_priv = PrivateKey.generate()
            st.dh_pub = st.dh_priv.public_key
            dh_out2 = self._dh(st.dh_priv, st.remote_dh_pub)
            st.root_key, st.send_chain_key = _kdf_rk(st.root_key, dh_out2)
            st.prev_send_n = st.send_n
            st.send_n = 0

        self._skip_message_keys(n)
        if st.recv_chain_key is None:
            raise ValueError("Lipsește recv chain")
        st.recv_chain_key, msg_key = _kdf_ck(st.recv_chain_key)
        st.recv_n += 1
        return SecretBox(msg_key).decrypt(ct)

    def _skip_message_keys(self, until: int):
        st = self.state
        if st.recv_chain_key is None:
            return
        if until - st.recv_n > st.MAX_SKIP:
            raise ValueError("Prea multe mesaje sărite")
        while st.recv_n < until:
            st.recv_chain_key, mk = _kdf_ck(st.recv_chain_key)
            if st.remote_dh_pub:
                kid = (st.remote_dh_pub.encode(encoder=RawEncoder).hex(), st.recv_n)
                st.skipped[kid] = mk
            st.recv_n += 1
