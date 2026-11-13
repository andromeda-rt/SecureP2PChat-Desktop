# -*- coding: utf-8 -*-
"""
Protecții practice împotriva leak-ului de chei din RAM / pagefile.

Limită: pe un OS complet compromis, memoria poate fi citită oricum.
Reducem: swap/pagefile, timpul de viață al cheilor, urme după folosire.
"""

import sys
import ctypes


def lock_memory(buf: memoryview) -> bool:
    try:
        addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
        size = len(buf)
        if sys.platform.startswith("win"):
            return bool(ctypes.windll.kernel32.VirtualLock(
                ctypes.c_void_p(addr), ctypes.c_size_t(size)))
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        return libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(size)) == 0
    except Exception:
        return False


def unlock_memory(buf: memoryview) -> None:
    try:
        addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
        size = len(buf)
        if sys.platform.startswith("win"):
            ctypes.windll.kernel32.VirtualUnlock(
                ctypes.c_void_p(addr), ctypes.c_size_t(size))
        else:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            libc.munlock(ctypes.c_void_p(addr), ctypes.c_size_t(size))
    except Exception:
        pass


def secure_zero(data) -> None:
    try:
        if isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = 0
        elif isinstance(data, memoryview) and not data.readonly:
            for i in range(len(data)):
                data[i] = 0
    except Exception:
        pass


class LockedKey:
    """Cheie în bytearray, blocată în RAM (best-effort)."""

    def __init__(self, key: bytes):
        self._buf = bytearray(key)
        self._mv = memoryview(self._buf)
        self._locked = lock_memory(self._mv)

    @property
    def locked(self) -> bool:
        return bool(getattr(self, "_locked", False))

    def get(self) -> bytes:
        if self._buf is None:
            raise RuntimeError("Cheie ștearsă din memorie")
        return bytes(self._buf)

    def clear(self) -> None:
        if self._buf is None:
            return
        try:
            unlock_memory(self._mv)
        except Exception:
            pass
        secure_zero(self._buf)
        self._mv = None
        self._buf = None
        self._locked = False

    def __del__(self):
        try:
            self.clear()
        except Exception:
            pass
