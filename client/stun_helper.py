# -*- coding: utf-8 -*-
"""STUN (RFC 5389) – află IP public + port mapat pentru încercări P2P prin NAT."""
from __future__ import annotations

import asyncio
import os
import socket
import struct
from typing import Optional, Tuple, List

# Magic cookie RFC 5389
MAGIC = 0x2112A442
STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
]


def _xor_addr(family: int, xport: int, xip: bytes, tid: bytes) -> Tuple[str, int]:
    magic = MAGIC.to_bytes(4, "big")
    port = xport ^ (MAGIC >> 16)
    if family == 0x01:  # IPv4
        ip_int = int.from_bytes(xip, "big") ^ MAGIC
        ip = socket.inet_ntoa(ip_int.to_bytes(4, "big"))
        return ip, port
    # IPv6
    xor_key = magic + tid
    plain = bytes(a ^ b for a, b in zip(xip, xor_key))
    ip = socket.inet_ntop(socket.AF_INET6, plain)
    return ip, port


def _parse_stun(data: bytes, tid: bytes) -> Optional[Tuple[str, int]]:
    if len(data) < 20:
        return None
    msg_type, length, magic = struct.unpack("!HHI", data[:8])
    if magic != MAGIC or data[8:20] != tid:
        return None
    # Binding Success Response = 0x0101
    if msg_type != 0x0101:
        return None
    offset = 20
    end = 20 + length
    mapped = None
    xor_mapped = None
    while offset + 4 <= end and offset + 4 <= len(data):
        atype, alen = struct.unpack("!HH", data[offset:offset + 4])
        offset += 4
        val = data[offset:offset + alen]
        offset += alen
        # padding to 4
        offset += (4 - (alen % 4)) % 4
        if atype == 0x0020 and len(val) >= 8:  # XOR-MAPPED-ADDRESS
            family = val[1]
            xport = struct.unpack("!H", val[2:4])[0]
            if family == 0x01 and len(val) >= 8:
                xor_mapped = _xor_addr(family, xport, val[4:8], tid)
            elif family == 0x02 and len(val) >= 20:
                xor_mapped = _xor_addr(family, xport, val[4:20], tid)
        elif atype == 0x0001 and len(val) >= 8:  # MAPPED-ADDRESS
            family = val[1]
            port = struct.unpack("!H", val[2:4])[0]
            if family == 0x01 and len(val) >= 8:
                mapped = (socket.inet_ntoa(val[4:8]), port)
    return xor_mapped or mapped


async def stun_query(
    servers: Optional[List[Tuple[str, int]]] = None,
    timeout: float = 2.5,
) -> Optional[Tuple[str, int]]:
    """Returnează (ip_public, port_mapat) sau None."""
    servers = servers or STUN_SERVERS
    loop = asyncio.get_event_loop()
    for host, port in servers:
        try:
            # resolve
            infos = await loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
            if not infos:
                continue
            af, socktype, proto, _, sockaddr = infos[0]
            sock = socket.socket(af, socktype, proto)
            sock.setblocking(False)
            try:
                tid = os.urandom(12)
                # Binding Request
                header = struct.pack("!HHI", 0x0001, 0, MAGIC) + tid
                await loop.sock_sendto(sock, header, sockaddr)
                try:
                    data, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 2048), timeout=timeout)
                except asyncio.TimeoutError:
                    continue
                result = _parse_stun(data, tid)
                if result:
                    return result
            finally:
                sock.close()
        except Exception as e:
            print(f"[STUN] {host}: {e}")
            continue
    return None


async def discover_public_endpoint(local_port: int) -> Optional[Tuple[str, int]]:
    """
    Află IP public. Portul STUN e al socket-ului efemer de query,
    deci folosim local_port ca port de anunțat pentru TCP P2P (best-effort).
    """
    mapped = await stun_query()
    if not mapped:
        return None
    pub_ip, _stun_port = mapped
    # TCP listen e pe local_port – anunțăm acela (hole punch TCP e imperfect fără simultaneitate)
    return pub_ip, local_port
