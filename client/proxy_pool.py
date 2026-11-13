# -*- coding: utf-8 -*-
"""
Pool simplu de proxy SOCKS4/SOCKS5 – failover + rotație opțională.
Format linie: socks5://host:port  sau  socks4://host:port  sau  host:port (default socks5)
"""

from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class ProxyEntry:
    scheme: str  # socks5 | socks4
    host: str
    port: int
    fails: int = 0
    last_ok: float = 0.0
    last_fail: float = 0.0

    def url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    def label(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"


def parse_proxy_line(line: str) -> Optional[ProxyEntry]:
    line = (line or "").strip()
    if not line or line.startswith("#"):
        return None
    scheme = "socks5"
    rest = line
    if "://" in line:
        scheme, rest = line.split("://", 1)
        scheme = scheme.lower().strip()
        if scheme not in ("socks5", "socks4", "socks4a"):
            scheme = "socks5"
        if scheme == "socks4a":
            scheme = "socks4"
    if ":" not in rest:
        return None
    host, port_s = rest.rsplit(":", 1)
    host = host.strip().strip("[]")
    try:
        port = int(port_s.strip())
    except ValueError:
        return None
    if not host or port < 1 or port > 65535:
        return None
    return ProxyEntry(scheme=scheme, host=host, port=port)


def parse_proxy_list(text: str) -> List[ProxyEntry]:
    out: List[ProxyEntry] = []
    seen = set()
    for line in (text or "").splitlines():
        e = parse_proxy_line(line)
        if not e:
            continue
        key = e.url()
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out


class ProxyPool:
    """Selectează proxy: preferă cele sănătoase, rotește la interval, sare peste cele eșuate."""

    def __init__(self, proxies: Optional[List[ProxyEntry]] = None, rotate_seconds: int = 0):
        self.proxies: List[ProxyEntry] = list(proxies or [])
        self.rotate_seconds = max(0, int(rotate_seconds or 0))  # 0 = doar failover
        self._index = 0
        self._selected_at = 0.0
        self._current: Optional[ProxyEntry] = None

    def set_list(self, proxies: List[ProxyEntry], rotate_seconds: int = 0):
        self.proxies = list(proxies)
        self.rotate_seconds = max(0, int(rotate_seconds or 0))
        self._index = 0
        self._current = None
        self._selected_at = 0.0

    def empty(self) -> bool:
        return not self.proxies

    def current(self) -> Optional[ProxyEntry]:
        return self._current

    def mark_ok(self, entry: Optional[ProxyEntry] = None):
        e = entry or self._current
        if not e:
            return
        e.fails = 0
        e.last_ok = time.time()

    def mark_fail(self, entry: Optional[ProxyEntry] = None):
        e = entry or self._current
        if not e:
            return
        e.fails += 1
        e.last_fail = time.time()
        # forțează alt proxy la următorul pick
        if self._current is e:
            self._current = None

    def pick(self, force_next: bool = False) -> Optional[ProxyEntry]:
        if not self.proxies:
            return None
        now = time.time()
        if (
            not force_next
            and self._current is not None
            and self._current.fails < 3
            and (self.rotate_seconds <= 0 or now - self._selected_at < self.rotate_seconds)
        ):
            return self._current

        n = len(self.proxies)
        start = (self._index + (1 if force_next or self._current else 0)) % n
        # preferă fails mici
        candidates = sorted(
            range(n),
            key=lambda i: (self.proxies[(start + i) % n].fails, (start + i) % n)
        )
        for i in candidates:
            e = self.proxies[i]
            if e.fails >= 5 and now - e.last_fail < 300:
                continue  # cooldown 5 min după multe eșecuri
            self._index = i
            self._current = e
            self._selected_at = now
            return e

        # totul e în cooldown – ia pe cel cu cele mai puține fails
        i = min(range(n), key=lambda j: self.proxies[j].fails)
        self._index = i
        self._current = self.proxies[i]
        self._selected_at = now
        return self._current

    def to_text(self) -> str:
        return "\n".join(p.url() for p in self.proxies)
