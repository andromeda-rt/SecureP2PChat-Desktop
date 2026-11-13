# -*- coding: utf-8 -*-
"""
Protocol Secure P2P Chat + transfer fișiere
Format: [4 bytes length BE][1 byte type][payload]
"""

import struct
from typing import Tuple
from shared.constants import PROTOCOL_VERSION


class ProtocolError(Exception):
    pass


def pack_message(msg_type: int, payload: bytes = b"") -> bytes:
    if not (0 <= msg_type <= 255):
        raise ProtocolError("msg_type invalid")
    length = 1 + len(payload)
    return struct.pack(">I", length) + bytes([msg_type]) + payload


def unpack_message(data: bytes) -> Tuple[int, bytes]:
    if len(data) < 5:
        raise ProtocolError("Mesaj prea scurt")
    length = struct.unpack(">I", data[:4])[0]
    if length < 1 or length > 20 * 1024 * 1024:
        raise ProtocolError("Lungime invalidă")
    if len(data) < 4 + length:
        raise ProtocolError("Date incomplete")
    msg_type = data[4]
    payload = data[5:4 + length]
    return msg_type, payload


def _key_exchange_transcript(public_key: bytes, device_id: str, display_name: str, verify_key: bytes) -> bytes:
    if len(public_key) != 32 or len(verify_key) != 32:
        raise ProtocolError("Cheie publică invalidă")
    id_bytes = device_id.encode("utf-8")
    name_bytes = display_name.encode("utf-8")
    if not id_bytes or len(id_bytes) > 256 or len(name_bytes) > 512:
        raise ProtocolError("ID/nume invalid")
    return (b"SecureP2PChat-key-exchange-v1\x00" + bytes([PROTOCOL_VERSION]) +
            public_key + struct.pack(">H", len(id_bytes)) + id_bytes +
            struct.pack(">H", len(name_bytes)) + name_bytes + verify_key)


def create_key_exchange(public_key: bytes, device_id: str, display_name: str,
                        signing_key=None, verify_key: bytes = b"") -> bytes:
    """Handshake semnat: X25519 + Ed25519. Numele NU se pune pe fir (anti-metadata)."""
    if signing_key is None:
        raise ProtocolError("Cheia de semnare este obligatorie")
    # Privacy: display_name pe wire mereu gol — numele vine din pair/signaling/local
    display_name = ""
    verify_key = verify_key or bytes(signing_key.verify_key)
    transcript = _key_exchange_transcript(public_key, device_id, display_name, verify_key)
    signature = signing_key.sign(transcript).signature
    id_bytes = device_id.encode("utf-8")
    name_bytes = display_name.encode("utf-8")
    return (bytes([PROTOCOL_VERSION]) + public_key + struct.pack(">H", len(id_bytes)) + id_bytes +
            struct.pack(">H", len(name_bytes)) + name_bytes + verify_key + signature)


def parse_key_exchange(payload: bytes):
    """Returnează (version, x25519_pub, device_id, name, verify_key, signature)."""
    if len(payload) < 1 + 32 + 2 + 1 + 2 + 32 + 64:
        raise ProtocolError("Key exchange prea scurt")
    version = payload[0]
    if version != PROTOCOL_VERSION:
        raise ProtocolError("Versiune de protocol incompatibilă")
    public_key = payload[1:33]
    pos = 33
    id_len = struct.unpack(">H", payload[pos:pos + 2])[0]; pos += 2
    if id_len < 1 or id_len > 256 or pos + id_len + 2 > len(payload):
        raise ProtocolError("Lungime ID invalidă")
    device_id = payload[pos:pos + id_len].decode("utf-8"); pos += id_len
    name_len = struct.unpack(">H", payload[pos:pos + 2])[0]; pos += 2
    if name_len > 512 or pos + name_len + 96 != len(payload):
        raise ProtocolError("Lungime nume/semnătură invalidă")
    display_name = payload[pos:pos + name_len].decode("utf-8"); pos += name_len
    verify_key = payload[pos:pos + 32]; pos += 32
    signature = payload[pos:pos + 64]
    return version, public_key, device_id, display_name, verify_key, signature


def verify_key_exchange(payload: bytes) -> bool:
    try:
        from nacl.signing import VerifyKey
        version, public_key, device_id, display_name, verify_key, signature = parse_key_exchange(payload)
        transcript = _key_exchange_transcript(public_key, device_id, display_name, verify_key)
        VerifyKey(verify_key).verify(transcript, signature)
        return True
    except Exception:
        return False


def create_file_start(transfer_id: str, filename: str, file_size: int, total_chunks: int) -> bytes:
    """transfer_id(16) + size(8) + chunks(4) + name_len(2) + name"""
    tid = transfer_id.encode("utf-8")[:16].ljust(16, b"\x00")
    name_b = filename.encode("utf-8")
    return tid + struct.pack(">Q", file_size) + struct.pack(">I", total_chunks) + struct.pack(">H", len(name_b)) + name_b


def parse_file_start(payload: bytes) -> Tuple[str, str, int, int]:
    if len(payload) < 30:
        raise ProtocolError("FILE_START prea scurt")
    tid = payload[:16].rstrip(b"\x00").decode("utf-8", errors="replace")
    file_size = struct.unpack(">Q", payload[16:24])[0]
    total_chunks = struct.unpack(">I", payload[24:28])[0]
    name_len = struct.unpack(">H", payload[28:30])[0]
    filename = payload[30:30 + name_len].decode("utf-8", errors="replace")
    return tid, filename, file_size, total_chunks


def create_file_chunk(transfer_id: str, chunk_index: int, encrypted_data: bytes) -> bytes:
    """transfer_id(16) + index(4) + data"""
    tid = transfer_id.encode("utf-8")[:16].ljust(16, b"\x00")
    return tid + struct.pack(">I", chunk_index) + encrypted_data


def parse_file_chunk(payload: bytes) -> Tuple[str, int, bytes]:
    if len(payload) < 20:
        raise ProtocolError("FILE_CHUNK prea scurt")
    tid = payload[:16].rstrip(b"\x00").decode("utf-8", errors="replace")
    idx = struct.unpack(">I", payload[16:20])[0]
    data = payload[20:]
    return tid, idx, data


def create_file_end(transfer_id: str) -> bytes:
    return transfer_id.encode("utf-8")[:16].ljust(16, b"\x00")


def parse_file_end(payload: bytes) -> str:
    return payload[:16].rstrip(b"\x00").decode("utf-8", errors="replace")
