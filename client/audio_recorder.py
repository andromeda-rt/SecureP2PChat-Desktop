import ctypes
import os
from pathlib import Path
from typing import Callable, Optional


class VoiceRecorder:
    def __init__(self, command_sender: Optional[Callable] = None):
        if command_sender is None:
            if os.name != "nt":
                raise OSError("Înregistrarea vocală este disponibilă pe Windows")
            command_sender = ctypes.windll.winmm.mciSendStringW
            command_sender.argtypes = [
                ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint, ctypes.c_void_p
            ]
            command_sender.restype = ctypes.c_uint
        self._command_sender = command_sender
        self._recording = False

    def _send(self, command: str) -> None:
        result = self._command_sender(command, None, 0, None)
        if result:
            raise RuntimeError(f"Comanda audio Windows a eșuat ({result})")

    def start(self, path: Path) -> None:
        if self._recording:
            raise RuntimeError("Există deja o înregistrare vocală activă")
        path.parent.mkdir(parents=True, exist_ok=True)
        self._send("open new type waveaudio alias securep2p_voice")
        try:
            self._send("set securep2p_voice time format ms")
            self._send("record securep2p_voice")
        except Exception:
            self._send("close securep2p_voice")
            raise
        self._path = path
        self._recording = True

    def stop(self) -> Path:
        if not self._recording:
            raise RuntimeError("Nu există o înregistrare vocală activă")
        try:
            self._send("stop securep2p_voice")
            self._send(f'save securep2p_voice "{self._path}"')
        finally:
            self._send("close securep2p_voice")
            self._recording = False
        if not self._path.is_file() or self._path.stat().st_size == 0:
            raise RuntimeError("Înregistrarea vocală este goală")
        return self._path

    def cancel(self) -> None:
        if not self._recording:
            return
        try:
            self._send("stop securep2p_voice")
        finally:
            self._send("close securep2p_voice")
            self._recording = False
