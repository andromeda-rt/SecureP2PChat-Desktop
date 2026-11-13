# -*- coding: utf-8 -*-
"""
Secure P2P Chat v0.7.4 – pairing migration fix
"""

import sys
import asyncio
import threading
import socket
import time
import random
import re
import json
import os
import uuid
import math
import struct
import base64
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Optional, Dict, Any
from collections import defaultdict, deque

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from client.identity import IdentityManager
from client.audio_recorder import VoiceRecorder
from client.crypto_engine import perform_key_exchange, public_key_fingerprint
from client.fs_chain import FSChain, is_fs_payload
from client.group_sender_key import GroupSenderKeyChain
from client.treekem_group import TreeKEMGroup
from client.trust import fingerprint_transition_allowed
from client.storage import Storage, Contact, Message
from client.stun_helper import discover_public_endpoint, stun_query
from client.gui import LoginWindow, MainWindow, TrustDialog
from client.network import NetworkManager, PeerConnection
from client.signaling import SignalingClient
from client.proxy_pool import ProxyPool, parse_proxy_list
from client.file_vault import save_encrypted_file, export_to_temp
from shared.protocol import (
    create_key_exchange, parse_key_exchange, verify_key_exchange,
    create_file_start, parse_file_start,
    create_file_chunk, parse_file_chunk,
    create_file_end, parse_file_end,
)
from shared.constants import (
    DEFAULT_PORT, DEFAULT_SIGNAL_PORT, MSG_KEY_EXCHANGE, MSG_TEXT, MSG_PING,
    MSG_FILE_START, MSG_FILE_CHUNK, MSG_FILE_END, MSG_TYPING,
    MSG_HELLO, MSG_HELLO_ACK, MSG_GROUP_TEXT, MSG_GROUP_META,
    APP_NAME, SIGNAL_HEARTBEAT, FILE_CHUNK_SIZE, MAX_FILE_SIZE,
    IMAGE_EXTENSIONS, RISKY_EXTENSIONS,
    RATE_LIMIT_MESSAGES_PER_SEC, IDLE_LOCK_SECONDS, RELAY_POLL_SECONDS, RELAY_POLL_JITTER_MIN, RELAY_POLL_JITTER_MAX,
)
from nacl.encoding import RawEncoder

GROUP_FILE_CHUNK_SIZE = 64 * 1024


def get_local_addresses():
    ipv4 = ipv6 = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.4)
        s.connect(("8.8.8.8", 80))
        ipv4 = s.getsockname()[0]
        s.close()
    except Exception:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6):
            addr = info[4][0]
            if addr and not addr.startswith("fe80") and addr != "::1":
                ipv6 = addr.split("%")[0]
                break
    except Exception:
        pass
    return ipv4, ipv6


def parse_connection_code(value: str):
    value = value.strip()
    port = DEFAULT_PORT
    ip = None
    if "@" not in value:
        return value, None, port
    device_id, addr = value.split("@", 1)
    device_id, addr = device_id.strip(), addr.strip()
    m = re.match(r"^\[([0-9a-fA-F:]+)\](?::(\d+))?$", addr)
    if m:
        ip = m.group(1)
        if m.group(2):
            port = int(m.group(2))
        return device_id, ip, port
    if addr.count(":") == 1 and "." in addr:
        ip, port_str = addr.rsplit(":", 1)
        port = int(port_str)
    elif addr.count(":") >= 2:
        ip = addr.strip("[]")
    else:
        ip = addr
    return device_id, ip, port


class RateLimiter:
    def __init__(self, max_per_sec: int):
        self.max = max_per_sec
        self.hits = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.time()
        q = self.hits[key]
        while q and now - q[0] > 1.0:
            q.popleft()
        if len(q) >= self.max:
            return False
        q.append(now)
        return True


class SecureChatApp:
    def __init__(self):
        self.data_dir = Path.home() / f".{APP_NAME.lower()}"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.files_dir = self.data_dir / "files"
        self.files_dir.mkdir(exist_ok=True)
        self.temp_dir = self.data_dir / "temp"
        self.temp_dir.mkdir(exist_ok=True)
        self.config_file = self.data_dir / "config.json"

        self.identity = IdentityManager(self.data_dir)
        self.storage = None
        self.network = NetworkManager(port=DEFAULT_PORT)
        self.signaling = None
        self.main_window = None
        self.current_contact_id = None
        self.loop = None
        self._login_window = None
        self._exchanged = set()
        self._heartbeat_task = None
        self._relay_task = None
        self._signal_watchdog_task = None
        self._peer_keep_task = None
        self._signal_stop = False
        self._secure_notified = set()
        self._p2p_maintenance_task = None
        self._p2p_connecting = set()
        self._incoming_files = {}
        self._voice_recorder = None
        self._voice_recording_path = None
        self._last_typing_sent = 0.0
        self._typing_clear_job = None
        self._rate = RateLimiter(RATE_LIMIT_MESSAGES_PER_SEC)
        self._pending_trust = {}
        self._hello_sent = set()
        self._recent_msg_ids = set()
        self._pending_relay_inbox = {}
        self._fs_chains = {}  # device_id -> FSChain  # device_id -> list[bytes] așteaptă HELLO/key  # dedup relay+p2p
        self.current_group_id = None
        self._groups = {}  # group_id -> {name, members}
        self._pending_group_texts = {}
        self._pending_group_flush_locks = {}
        self._group_send_locks = {}
        self._group_epoch_sent = set()
        self._group_epoch_request_at = {}

        cfg = self._load_signal_config()
        self.signal_host = cfg["host"]
        self.signal_port = cfg["port"]
        self.signal_tls = cfg["tls"]
        self.signal_ca = cfg["ca"]
        self.signal_tls_insecure = cfg["insecure"]
        self.socks_host = cfg["socks_host"]
        self.socks_port = cfg["socks_port"]
        self.proxy_list_text = cfg.get("proxy_list", "")
        self.proxy_rotate_sec = cfg.get("proxy_rotate", 0)
        self.proxy_pool = ProxyPool(parse_proxy_list(self.proxy_list_text), self.proxy_rotate_sec)
        self.local_ipv4 = self.local_ipv6 = None

    def _load_signal_config(self):
        try:
            if self.config_file.exists():
                data = json.loads(self.config_file.read_text(encoding="utf-8"))
                return {
                    "host": data.get("signal_host", ""),
                    "port": int(data.get("signal_port", DEFAULT_SIGNAL_PORT)),
                    "tls": bool(data.get("signal_tls", True)),
                    "ca": data.get("signal_ca", "") or None,
                    "insecure": bool(data.get("signal_tls_insecure", False)),
                    "socks_host": data.get("socks_host") or None,
                    "socks_port": int(data["socks_port"]) if data.get("socks_port") else None,
                    "proxy_list": data.get("proxy_list", "") or "",
                    "proxy_rotate": int(data.get("proxy_rotate_sec", 0) or 0),
                }
        except Exception:
            pass
        return {
            "host": "", "port": DEFAULT_SIGNAL_PORT, "tls": True, "ca": None,
            "insecure": False, "socks_host": None, "socks_port": None,
            "proxy_list": "", "proxy_rotate": 0,
        }

    def _save_signal_config(self, host, port, use_tls=True, ca_file="", insecure=False,
                             socks_host=None, socks_port=None,
                             proxy_list="", proxy_rotate=0):
        self.config_file.write_text(
            json.dumps({
                "signal_host": host,
                "signal_port": port,
                "signal_tls": use_tls,
                "signal_ca": ca_file or "",
                "signal_tls_insecure": insecure,
                "socks_host": socks_host or "",
                "socks_port": socks_port or "",
                "proxy_list": proxy_list or "",
                "proxy_rotate_sec": int(proxy_rotate or 0),
            }, indent=2), encoding="utf-8"
        )
        self.signal_host, self.signal_port = host, port
        self.signal_tls = use_tls
        self.signal_ca = ca_file or None
        self.signal_tls_insecure = insecure
        self.socks_host = socks_host or None
        self.socks_port = int(socks_port) if socks_port else None
        self.proxy_list_text = proxy_list or ""
        self.proxy_rotate_sec = int(proxy_rotate or 0)
        self.proxy_pool = ProxyPool(parse_proxy_list(self.proxy_list_text), self.proxy_rotate_sec)

    def run(self):
        self._login_window = LoginWindow(
            on_login=self._handle_login, on_create=self._handle_create,
            has_existing=self.identity.exists(),
        )
        self._login_window.mainloop()


    def _handle_create(self, display_name, password):
        try:
            self.identity.create(display_name, password)
            self._start_main()
        except Exception as e:
            if self._login_window:
                self._login_window.status_label.configure(text=f"Eroare: {e}")

    def _handle_login(self, password):
        ok = self.identity.unlock(password)
        if ok:
            self._start_main()
        return ok

    def _start_main(self):
        mk = self.identity.get_master_key()
        if not mk:
            return
        self.storage = Storage(self.data_dir, mk)
        self._groups = {
            entry["group_id"]: {k: v for k, v in entry.items() if k != "group_id"}
            for entry in self.storage.load_groups()
        }
        self.local_ipv4, self.local_ipv6 = get_local_addresses()
        self.public_ipv4 = None
        self.public_port = None
        # Coduri P2P cu IP local (LAN). Semnalizarea pe Tor rămâne .onion + SOCKS.
        code_ipv4 = f"{self.identity.device_id}@{self.local_ipv4}:{DEFAULT_PORT}" if self.local_ipv4 else (self.identity.device_id or "")
        code_ipv6 = f"{self.identity.device_id}@[{self.local_ipv6}]:{DEFAULT_PORT}" if self.local_ipv6 else ""

        if self._login_window:
            try:
                self._login_window.destroy()
            except Exception:
                pass
            self._login_window = None

        disp = self.identity.display_name or "User"
        self.main_window = MainWindow(disp, self.identity.device_id)
        self.main_window.set_codes(code_ipv4, code_ipv6)
        self.main_window.set_signal_config(
            self.signal_host, self.signal_port,
            use_tls=getattr(self, "signal_tls", True),
            ca_file=getattr(self, "signal_ca", "") or "",
            insecure=getattr(self, "signal_tls_insecure", False),
            proxy_list=getattr(self, "proxy_list_text", "") or "",
            proxy_rotate=getattr(self, "proxy_rotate_sec", 0) or 0,
            socks_host=getattr(self, "socks_host", "") or "",
            socks_port=str(getattr(self, "socks_port", "") or ""),
        )
        self.main_window.on_send_message = self._on_send_message
        self.main_window.on_send_file = self._on_send_file
        self.main_window.on_voice_record = self._toggle_voice_recording
        self.main_window.on_open_file = self._open_file_safe
        self.main_window.on_add_contact = self._on_add_contact
        self.main_window.on_logout = self._on_logout
        self.main_window.on_save_signal = self._on_save_signal
        self.main_window.on_typing = self._on_local_typing
        self.main_window.on_gen_pair = self._on_gen_pair
        self.main_window.on_join_pair = self._on_join_pair
        self.main_window.on_create_group = self._on_create_group
        self.main_window.on_join_group = self._on_join_group
        self.main_window.on_clear_chat = self._on_clear_chat
        self.main_window.on_delete_contact = self._on_delete_contact

        for c in self.storage.get_contacts():
            label = (c.display_name or "").strip() or f"Peer-{c.device_id[:8]}"
            self.main_window.add_contact_to_list(
                label, c.device_id,
                command=lambda cid=c.device_id: self._select_contact(cid)
            )
        for gid, group in self._groups.items():
            self.main_window.add_group_to_list(
                group.get("name") or "Grup", gid,
                command=lambda group_id=gid: self._select_group(group_id)
            )

        self.loop = asyncio.new_event_loop()
        threading.Thread(
            target=lambda: (asyncio.set_event_loop(self.loop), self.loop.run_forever()),
            daemon=True
        ).start()

        self.network.on_key_exchange = self._on_key_exchange
        self.network.on_message = self._on_network_message
        self.network.on_file_start = self._on_file_start
        self.network.on_file_chunk = self._on_file_chunk
        self.network.on_file_end = self._on_file_end
        self.network.on_typing = self._on_peer_typing
        self.network.on_disconnect = self._on_peer_disconnect

        fut = asyncio.run_coroutine_threadsafe(self.network.start_server(), self.loop)
        try:
            fut.result(timeout=10)
        except Exception:
            pass
        self._p2p_maintenance_task = asyncio.run_coroutine_threadsafe(
            self._p2p_maintenance_loop(), self.loop
        )
        asyncio.run_coroutine_threadsafe(self._p2p_keepalive_loop(), self.loop)

        if self.network.upnp_ok and self.network.external_ip:
            code_ipv4 = f"{self.identity.device_id}@{self.network.external_ip}:{DEFAULT_PORT}"
            self.main_window.set_codes(code_ipv4, code_ipv6)
            self.local_ipv4 = self.network.external_ip

        if self.signal_host:
            asyncio.run_coroutine_threadsafe(self._start_signaling(), self.loop)

        self.main_window.protocol("WM_DELETE_WINDOW", self._on_close)
        self._last_activity = time.time()
        self._bind_activity_tracking()
        self._arm_idle_lock()
        self.main_window.mainloop()

    # ── Signaling ──────────────────────────────────────────

    def _signal_endpoints(self):
        """IP local + (dacă STUN a reușit) IP public pentru P2P prin NAT."""
        try:
            self.local_ipv4, self.local_ipv6 = get_local_addresses()
        except Exception:
            pass
        ip4 = getattr(self, "public_ipv4", None) or self.local_ipv4
        port = getattr(self, "public_port", None) or DEFAULT_PORT
        return ip4, self.local_ipv6, port

    def _apply_onion_defaults(self):
        """Pe .onion: SOCKS 9150. TLS rămâne cum e în Setări (serverul tău are TLS)."""
        host = (getattr(self, "signal_host", None) or "").strip()
        if host.endswith(".onion"):
            if not getattr(self, "socks_port", None):
                self.socks_host = getattr(self, "socks_host", None) or "127.0.0.1"
                self.socks_port = 9150
            # Cert self-signed pe HS: fără insecure, TLS eșuează
            if getattr(self, "signal_tls", False):
                self.signal_tls_insecure = True

    async def _start_signaling(self):
        if not self.signal_host:
            return
        self._signal_stop = False
        self._apply_onion_defaults()
        # Tor: dacă host e .onion, SOCKS e obligatoriu
        sh = getattr(self, "socks_host", None)
        sp = getattr(self, "socks_port", None)
        if str(self.signal_host).endswith(".onion") and not sp:
            # Tor Browser = 9150 (implicit); sistem tor daemon = 9050
            sh, sp = sh or "127.0.0.1", sp or 9150
        pin_path = None
        try:
            if self.config_file:
                pin_path = self.config_file.parent / "tls_pin.sha256"
        except Exception:
            pin_path = None
        _onion = str(self.signal_host or "").endswith(".onion")
        _tls = getattr(self, "signal_tls", True)
        _insec = getattr(self, "signal_tls_insecure", False) or (_onion and _tls)
        self.signaling = SignalingClient(
            self.signal_host, self.signal_port,
            use_tls=_tls,
            ca_file=getattr(self, "signal_ca", None),
            insecure_skip_verify=_insec,
            socks_host=sh,
            socks_port=sp,
            proxy_pool=getattr(self, "proxy_pool", None),
            pin_file=pin_path,
        )
        sk = self.identity.get_signing_key()
        vk = self.identity.get_verify_key_bytes()
        pk_hex = self.identity.public_key.encode(encoder=RawEncoder).hex() if self.identity.public_key else ""
        if sk and vk:
            self.signaling.set_identity(
                self.identity.device_id, sk, vk,
                public_key_hex=pk_hex,
                display_name=self.identity.display_name or "",
            )
        # o singură instanță de bucle de mentenanță
        if not self._heartbeat_task or self._heartbeat_task.done():
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        if not self._relay_task or self._relay_task.done():
            self._relay_task = asyncio.create_task(self._relay_poll_loop())
        if not self._signal_watchdog_task or self._signal_watchdog_task.done():
            self._signal_watchdog_task = asyncio.create_task(self._signal_watchdog_loop())
        if not self._peer_keep_task or self._peer_keep_task.done():
            self._peer_keep_task = asyncio.create_task(self._peer_keepalive_loop())
        await self._signal_connect_and_register()


    async def _discover_nat_and_reregister(self):
        """STUN: află IP public, re-register pe semnalizare pentru P2P prin NAT."""
        try:
            ep = await discover_public_endpoint(DEFAULT_PORT)
            if ep:
                self.public_ipv4, self.public_port = ep
                print(f"[STUN] public endpoint {self.public_ipv4}:{self.public_port}")
                if self.signaling and self.signaling.connected:
                    ip4, ip6, port = self._signal_endpoints()
                    await self.signaling.register(self.identity.device_id, ip4, ip6, port)
            else:
                print("[STUN] eșuat – P2P doar LAN / IP cunoscut")
        except Exception as e:
            print(f"[STUN] {e}")

    async def _try_p2p_then_relay_ready(self, device_id: str, extra_endpoints=None):
        """Încearcă toate endpoint-urile (local peer, STUN, lookup), paralel, scurt timeout."""
        endpoints = list(extra_endpoints or [])
        try:
            lookup = await self.signaling.lookup(device_id) if self.signaling else None
        except Exception:
            lookup = None
        if lookup:
            port = int(lookup.get("port") or DEFAULT_PORT)
            for k in ("ipv6", "ipv4"):
                if lookup.get(k):
                    endpoints.append((lookup[k], port))
        # dedup
        seen = set()
        tasks = []
        for ip, p in endpoints:
            if not ip:
                continue
            key = f"{ip}:{p}"
            if key in seen:
                continue
            seen.add(key)
            tasks.append(self._try_connect_and_exchange(device_id, ip, int(p)))
        if not tasks:
            return False
        results = await asyncio.gather(*tasks, return_exceptions=True)
        ok = any(r is True or r is None for r in results if not isinstance(r, Exception))
        # connections dict is the real signal
        if device_id in self.network.connections:
            print(f"[P2P] connected to {device_id[:12]}…")
            return True
        print(f"[P2P] no direct path – remain on relay for {device_id[:12]}…")
        return False

    async def _signal_connect_and_register(self) -> bool:
        if not self.signaling or self._signal_stop:
            return False
        try:
            if not await self.signaling.ensure_connected():
                host = getattr(self, "signal_host", "") or ""
                err = (getattr(self.signaling, "last_error", None) or "")
                if "python-socks" in err.lower() or "no-python-socks" in err:
                    hint = "pip install python-socks[asyncio]"
                elif str(host).endswith(".onion"):
                    hint = err[:45] if err else "Tor Browser 9150 + TLS OFF"
                else:
                    hint = err[:45] if err else "host/port/TLS"
                self.main_window.after(0, lambda h=hint: self.main_window.set_signal_status(
                    f"Offline – {h}", ok=False
                ))
                return False
            ip4, ip6, port = self._signal_endpoints()
            ok = await self.signaling.register(
                self.identity.device_id, ip4, ip6, port
            )
            if ok:
                self.main_window.after(0, lambda: self.main_window.set_signal_status(
                    "Online (relay activ)", ok=True
                ))
                asyncio.create_task(self._rehello_all_contacts())
                asyncio.create_task(self._discover_nat_and_reregister())
                return True
            self.main_window.after(0, lambda: self.main_window.set_signal_status(
                "Semnalizare: auth eșuat", ok=False
            ))
            return False
        except Exception as e:
            print(f"[Signal] connect/register: {e}")
            self.main_window.after(0, lambda: self.main_window.set_signal_status(
                "Semnalizare: offline", ok=False
            ))
            return False

    async def _signal_watchdog_loop(self):
        """Reconectare automată cu backoff (Tor / Wi‑Fi instabil)."""
        delay = 2.0
        while not self._signal_stop and self.main_window is not None:
            try:
                await asyncio.sleep(3.0)
                if not self.signaling or self._signal_stop:
                    continue
                if self.signaling.connected:
                    delay = 2.0
                    continue
                self.main_window.after(0, lambda: self.main_window.set_signal_status(
                    f"Reconectare peste {int(delay)}s…", ok=False
                ))
                await asyncio.sleep(delay)
                if await self._signal_connect_and_register():
                    delay = 2.0
                    print("[Signal] watchdog: reonline")
                else:
                    delay = min(delay * 1.6, 30.0)
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[Signal] watchdog: {e}")
                await asyncio.sleep(5)

    async def _heartbeat_loop(self):
        fails = 0
        while not self._signal_stop and self.main_window is not None:
            await asyncio.sleep(SIGNAL_HEARTBEAT)
            if not self.signaling:
                continue
            try:
                if not self.signaling.connected:
                    fails += 1
                    if fails >= 1:
                        # lasă watchdog-ul să reconecteze
                        pass
                    continue
                ip4, ip6, port = self._signal_endpoints()
                ok = await self.signaling.heartbeat(
                    self.identity.device_id, ip4, ip6, port
                )
                if ok:
                    fails = 0
                    self.main_window.after(0, lambda: self.main_window.set_signal_status(
                        "Online (relay activ)", ok=True
                    ))
                else:
                    fails += 1
                    print("[Signal] heartbeat fail → forțez reconnect")
                    self.signaling.connected = False
                    # re-register imediat o dată
                    if await self._signal_connect_and_register():
                        fails = 0
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[Signal] heartbeat: {e}")
                if self.signaling:
                    self.signaling.connected = False
                fails = 0

    def _on_save_signal(self, host, port, use_tls=True, ca_file="", insecure=False,
                         socks_host="", socks_port="", proxy_list="", proxy_rotate=0):
        sp = None
        try:
            sp = int(socks_port) if socks_port not in (None, "") else None
        except (TypeError, ValueError):
            sp = None
        host = (host or "").strip()
        is_onion = host.endswith(".onion")
        is_local = host in ("127.0.0.1", "localhost", "::1")
        # Politica securitate: pe clearnet TLS recomandat; insecure doar explicit
        if not is_onion and not is_local and not use_tls:
            # nu forțăm hard (poate fi LAN), dar avertizam
            if self.main_window:
                self.main_window.show_info(
                    "Atenție: semnalizare fără TLS pe rețea publică – risc MITM. Preferă Tor sau TLS."
                )
        if insecure and not is_onion and not is_local:
            if self.main_window:
                self.main_window.show_info(
                    "„Acceptă self-signed” pe clearnet slăbește protecția MITM. Folosește doar la test."
                )
        # onion: SOCKS implicit
        if is_onion and not sp:
            socks_host = socks_host or "127.0.0.1"
            sp = 9150
        if is_onion and use_tls:
            insecure = True  # self-signed pe HS
        self._save_signal_config(
            host, port, use_tls=use_tls, ca_file=ca_file, insecure=insecure,
            socks_host=socks_host or None, socks_port=sp,
            proxy_list=proxy_list or "", proxy_rotate=proxy_rotate or 0,
        )
        if self.loop:
            asyncio.run_coroutine_threadsafe(self._restart_signaling(), self.loop)

    async def _restart_signaling(self):
        if self.signaling:
            try:
                await self.signaling.unregister(self.identity.device_id)
            except Exception:
                pass
            try:
                await self.signaling.close()
            except Exception:
                pass
            self.signaling.connected = False
        await self._start_signaling()

    # ── Direct P2P persistence ──────────────────────────────
    async def _p2p_keepalive_loop(self):
        """Keep established TCP peer links alive and notice stale connections."""
        while self.main_window is not None:
            try:
                await asyncio.sleep(12)
                dead = []
                for did, conn in list(self.network.connections.items()):
                    try:
                        await self.network.send_message(conn, MSG_PING, b"")
                    except Exception:
                        dead.append(did)
                for did in dead:
                    try:
                        c = self.network.connections.pop(did, None)
                        if c:
                            await self.network._close_conn(c)
                    except Exception:
                        pass
            except asyncio.CancelledError:
                break
            except Exception as exc:
                print(f"[P2P] keepalive: {exc}")

    async def _p2p_maintenance_loop(self):
        """Maintain direct peer sessions where a reachable endpoint is known.

        Signaling is used only to discover/refresh endpoints or as a message fallback;
        the actual TCP session is peer-to-peer whenever it can be established.
        """
        while self.main_window is not None:
            try:
                for contact in self.storage.get_contacts():
                    peer_id = contact.device_id
                    if peer_id == self.identity.device_id or peer_id in self.network.connections:
                        continue
                    if not self._peer_auto_allowed(peer_id):
                        continue
                    if peer_id in self._p2p_connecting:
                        continue
                    self._p2p_connecting.add(peer_id)
                    try:
                        endpoint = (contact.last_ip, contact.last_port or DEFAULT_PORT)
                        # Prefer a saved direct endpoint so manual IPv6 pairing works
                        # even when no signaling server is configured.
                        if endpoint[0]:
                            await self._try_connect_and_exchange(peer_id, endpoint[0], int(endpoint[1]))
                        elif self.signaling and self.signaling.connected:
                            await self._lookup_and_connect(peer_id, quiet=True)
                    except Exception as exc:
                        print(f"[P2P] reconectare {peer_id[:12]}: {exc}")
                    finally:
                        self._p2p_connecting.discard(peer_id)
                await asyncio.sleep(5)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                print(f"[P2P] mentenanță: {exc}")
                await asyncio.sleep(5)

    # ── Contacts / UI ──────────────────────────────────────
    def _select_contact(self, device_id):
        self.current_group_id = None
        self.current_contact_id = device_id
        contact = self.storage.get_contact(device_id)
        if not contact:
            return
        online = device_id in self.network.connections or bool(self.storage.get_session_key(device_id))
        title = (contact.display_name or "").strip() or f"Peer-{device_id[:8]}"
        if contact.trusted:
            title = f"✓ {title}"
        self.main_window.set_chat_title(title, online=online)
        self.main_window.clear_messages()
        for msg in self.storage.get_messages(device_id):
            if msg.msg_type == "file":
                parts = msg.content.split("|", 1)
                fname, fpath = parts[0], (parts[1] if len(parts) > 1 else "")
                is_img = Path(fname).suffix.lower() in IMAGE_EXTENSIONS
                self.main_window.add_file_bubble(fname, fpath, msg.direction == "out", is_img)
            else:
                self.main_window.add_message_bubble(msg.content, msg.direction == "out")



    def _set_session_key_fs(self, device_id: str, key: bytes) -> None:
        self.storage.set_session_key(device_id, key)
        self._reset_fs_chain(device_id, key)
        try:
            task = asyncio.get_running_loop().create_task(
                self._flush_pending_group_frames(device_id)
            )
            task.add_done_callback(self._log_group_flush_error)
        except RuntimeError:
            pass

    @staticmethod
    def _log_group_flush_error(task):
        if task.cancelled():
            return
        error = task.exception()
        if error:
            print(f"[Group] pending frame flush failed: {error}")

    def _reset_fs_chain(self, device_id: str, session_key: bytes) -> None:
        """Încarcă starea FS2 existentă sau inițializează una nouă; nu resetează implicit."""
        if not device_id or not session_key or not self.identity:
            return
        try:
            # Reuse authenticated, locally encrypted state after restart/HELLO.
            # A corrupt or mismatched state is never silently accepted.
            raw_state = self.storage.load_ratchet_state(device_id)
            if raw_state:
                chain = FSChain.import_state(
                    session_key, self.identity.device_id, device_id, raw_state
                )
            else:
                chain = FSChain(session_key, self.identity.device_id, device_id)
                self.storage.save_ratchet_state(device_id, chain.export_state())
            self._fs_chains[device_id] = chain
            print(f"[FS2] chain ready for {device_id[:12]}")
        except Exception as e:
            self._fs_chains.pop(device_id, None)
            print(f"[FS2] state restore/init failed: {e}")

    def _encrypt_direct(self, device_id: str, plaintext: bytes, session_key: bytes) -> bytes:
        """Criptează mesajele noi numai cu FS; nu face downgrade silențios."""
        ch = self._fs_chains.get(device_id)
        if ch is None and session_key:
            self._reset_fs_chain(device_id, session_key)
            ch = self._fs_chains.get(device_id)
        if ch is None:
            raise RuntimeError("FS2 indisponibil: lanțul de chei nu este inițializat sau starea nu este validă")
        # Dacă FS eșuează, mesajul nu este trimis cu cheia statică.
        blob = ch.encrypt(plaintext)
        self.storage.save_ratchet_state(device_id, ch.export_state())
        return blob

    def _decrypt_direct(self, device_id: str, blob: bytes, session_key: bytes) -> bytes:
        """Acceptă numai protocolul FS2 pentru mesajele directe noi; fără downgrade."""
        if not is_fs_payload(blob):
            raise ValueError("Protocol criptografic vechi/neacceptat; re-asociați contactul")
        ch = self._fs_chains.get(device_id)
        if ch is None and session_key:
            self._reset_fs_chain(device_id, session_key)
            ch = self._fs_chains.get(device_id)
        if ch is None:
            raise ValueError("FS2 payload but no valid chain")
        plaintext = ch.decrypt(blob)
        self.storage.save_ratchet_state(device_id, ch.export_state())
        return plaintext

    def _peer_auto_allowed(self, device_id: str) -> bool:
        """False dacă contactul a fost șters explicit – nu reapare din HELLO/relay."""
        if not device_id:
            return False
        try:
            return not self.storage.is_deleted_peer(device_id)
        except Exception:
            return True

    def _is_known_group_sender(self, device_id: str, raw: bytes) -> bool:
        if not device_id or not raw:
            return False
        if raw[0] == MSG_GROUP_TEXT:
            payload = raw[1:]
            if len(payload) < 3:
                return False
            group_id_len = struct.unpack(">H", payload[:2])[0]
            if not group_id_len or len(payload) <= 2 + group_id_len:
                return False
            try:
                group_id = payload[2:2 + group_id_len].decode("utf-8")
            except UnicodeDecodeError:
                return False
            group = self._groups.get(group_id) or {}
            return device_id in group.get("members", [])
        if raw[0] == MSG_GROUP_META:
            return any(
                device_id in (group.get("members") or [])
                for group in self._groups.values()
            )
        return False

    def _allow_contact_manual(self, device_id: str) -> None:
        """User a adăugat / pair manual → scoate din lista de șterși."""
        try:
            self.storage.clear_deleted_peer(device_id)
        except Exception:
            pass

    def _on_add_contact(self, value):
        try:
            device_id, ip, port = parse_connection_code(value)
            if device_id == self.identity.device_id:
                self.main_window.show_info("Nu te poți adăuga pe tine.")
                return
            self._allow_contact_manual(device_id)
            if not self.storage.get_contact(device_id):
                c = Contact(
                    device_id=device_id, display_name=f"Peer-{device_id[:8]}",
                    public_key="", last_ip=ip, last_port=port,
                    created_at=time.time(), last_seen=time.time(), trusted=False,
                )
                self.storage.add_contact(c, force=True)
                self.main_window.add_contact_to_list(
                    c.display_name, c.device_id,
                    command=lambda cid=c.device_id: self._select_contact(cid)
                )
            elif ip:
                self.storage.update_contact_endpoint(device_id, ip, port)
            self._select_contact(device_id)
            if ip:
                asyncio.run_coroutine_threadsafe(
                    self._try_connect_and_exchange(device_id, ip, port), self.loop
                )
            else:
                asyncio.run_coroutine_threadsafe(self._lookup_and_connect(device_id), self.loop)
        except Exception as e:
            self.main_window.show_info(f"Cod invalid: {e}")

    async def _lookup_and_connect(self, device_id, quiet: bool = False):
        """Lookup pe server pentru endpoint P2P. quiet=True: fără mesaje în chat (mentenanță)."""
        if not self.signaling or not self.signaling.connected:
            if not quiet and self.main_window:
                self.main_window.after(0, lambda: self.main_window.show_info("Semnalizare offline"))
            return
        # Deja împerecheat pe relay: lookup e doar bonus P2P – nu deranja UI
        has_local = bool(
            self.storage.get_session_key(device_id)
            or (self.storage.get_contact(device_id) and self.storage.get_contact(device_id).public_key)
        )
        info = await self.signaling.lookup(device_id)
        if not info:
            if has_local:
                print(f"[App] lookup empty for {device_id[:12]} – rămânem pe relay (OK)")
                await self._send_hello(device_id)
                return
            if not quiet and self.main_window:
                self.main_window.after(0, lambda: self.main_window.show_info(
                    "Contact offline pe server (mesajele pe relay pot merge după pair)"
                ))
            else:
                print(f"[App] lookup not_found {device_id[:12]}")
            return
        if info.get("public_key") and info.get("verify_key"):
            try:
                incoming_fp = public_key_fingerprint(bytes.fromhex(info["verify_key"]))
                c = self.storage.get_contact(device_id)
                if c and c.fingerprint and c.fingerprint != incoming_fp:
                    raise ValueError("Cheia de identitate din server diferă de cea memorată")
                if not c:
                    c = Contact(device_id=device_id,
                                display_name=info.get("display_name") or f"Peer-{device_id[:8]}",
                                public_key=info["public_key"], fingerprint=incoming_fp,
                                last_ip=info.get("ipv4") or info.get("ipv6"),
                                last_port=int(info.get("port", DEFAULT_PORT)),
                                created_at=time.time(), last_seen=time.time())
                else:
                    c.public_key = info["public_key"]
                    c.fingerprint = incoming_fp
                    if info.get("display_name"):
                        c.display_name = info["display_name"]
                self.storage.add_contact(c)
                shared = perform_key_exchange(self.identity.private_key, bytes.fromhex(info["public_key"]))
                self._set_session_key_fs(device_id, shared)
            except Exception as e:
                print(f"[App] lookup ecdh: {e}")
                self.main_window.after(0, lambda: self.main_window.show_info(f"Identitatea contactului nu a fost verificată: {e}"))
                return
        await self._send_hello(device_id)
        for k in ("ipv6", "ipv4"):
            if info.get(k):
                await self._try_connect_and_exchange(device_id, info[k], int(info.get("port", DEFAULT_PORT)))

    async def _try_connect_and_exchange(self, device_id, ip, port):
        conn = await self.network.connect_to_peer(ip, port)
        if not conn:
            return False
        conn.expected_device_id = device_id
        # placeholder până la KE complet
        if device_id not in self.network.connections:
            self.network.connections[device_id] = conn
        try:
            pubkey = self.identity.public_key.encode(encoder=RawEncoder)
            await self.network.send_message(
                conn, MSG_KEY_EXCHANGE,
                create_key_exchange(pubkey, self.identity.device_id, "",
                                           self.identity.get_signing_key())
            )
            return True
        except Exception as e:
            print(f"[App] KE send fail: {e}")
            try:
                await self.network._close_conn(conn)
            except Exception:
                pass
            return False

    # ── Pair codes ─────────────────────────────────────────

    async def _ensure_signal_ready_for_pair(self) -> bool:
        """Register + identity pe signaling înainte de pair (înainte de pair)."""
        if not self.signaling:
            return False
        # reatașează cheile (reconnect)
        try:
            from nacl.encoding import RawEncoder
            sk = self.identity.get_signing_key()
            vk = bytes(self.identity.get_signing_key().verify_key) if sk else None
            pk_hex = ""
            if self.identity.public_key:
                pk_hex = self.identity.public_key.encode(encoder=RawEncoder).hex()
            disp = self.identity.display_name or ""
            if not disp:
                disp = (self.identity.device_id or "user")[:8]
            if sk and vk:
                self.signaling.set_identity(
                    self.identity.device_id, sk, vk,
                    public_key_hex=pk_hex, display_name=disp,
                )
        except Exception as e:
            print(f"[App] ensure identity: {e}")
        if not await self.signaling.ensure_connected():
            return False
        # re-register mereu înainte de pair (token proaspăt)
        ip4, ip6, port = self._signal_endpoints()
        ok = await self.signaling.register(self.identity.device_id, ip4, ip6, port)
        if not ok:
            print("[App] register înainte de pair a eșuat")
        return bool(ok and self.signaling._session_token)


    def _on_gen_pair(self):
        if not self.signaling or not self.signaling.connected:
            self.main_window.show_info("Configurează serverul în ⚙ Setări (IP + port 37422)")
            return
        asyncio.run_coroutine_threadsafe(self._gen_pair_async(), self.loop)

    async def _gen_pair_async(self):
        if not await self._ensure_signal_ready_for_pair():
            self.main_window.after(0, lambda: self.main_window.show_info(
                "Nu ești Online – așteaptă „Online (relay activ)” apoi generează cod"
            ))
            return
        code = await self.signaling.pair_create()
        if not code:
            self.main_window.after(0, lambda: self.main_window.show_info(
                "Nu am putut genera codul – Online? Același server?"
            ))
            return
        self.main_window.after(0, lambda: self.main_window.show_pair_code(code))
        self.main_window.after(0, lambda: self.main_window.show_info(
            "Cod generat – aștept peer (max ~90s). Nu șterge nimic."
        ))
        # Poll pair_status – nu depinde doar de notify relay
        for _ in range(60):
            if self._signal_stop:
                return
            await asyncio.sleep(2.0)
            try:
                st = await self.signaling.pair_status(code)
            except Exception as e:
                print(f"[App] pair_status: {e}")
                continue
            if not st or not st.get("joined"):
                continue
            device_id = st.get("device_id") or ""
            pub = st.get("public_key") or ""
            name = (st.get("display_name") or "").strip() or f"Peer-{device_id[:8]}"
            verify_key_hex = st.get("verify_key") or ""
            if not device_id or not pub:
                print("[App] pair_status joined dar fără chei")
                continue
            self._allow_contact_manual(device_id)
            print(f"[App] pair_status JOINED {name} {device_id[:12]}")
            pairing_fp = ""
            if verify_key_hex:
                try:
                    pairing_fp = public_key_fingerprint(bytes.fromhex(verify_key_hex))
                except Exception:
                    pass
            c = self.storage.get_contact(device_id)
            if not c:
                c = Contact(
                    device_id=device_id, display_name=name, public_key=pub,
                    fingerprint=pairing_fp, created_at=time.time(), last_seen=time.time(),
                )
                self.storage.add_contact(c)
                self.main_window.after(
                    0, lambda n=name, did=device_id: self.main_window.add_contact_to_list(
                        n, did, command=lambda cid=did: self._select_contact(cid)
                    )
                )
            else:
                c.public_key = pub
                c.display_name = name
                if pairing_fp:
                    c.fingerprint = pairing_fp
                self.storage.add_contact(c)
            try:
                shared = perform_key_exchange(self.identity.private_key, bytes.fromhex(pub))
                self._set_session_key_fs(device_id, shared)
            except Exception as e:
                print(f"[App] pair_status ecdh: {e}")
            await self._send_hello(device_id)
            await self._flush_pending_relay(device_id)
            # P2P după pair_status
            try:
                lookup = await self.signaling.lookup(device_id)
                if lookup:
                    port = int(lookup.get("port") or DEFAULT_PORT)
                    tasks = []
                    for k in ("ipv6", "ipv4"):
                        if lookup.get(k):
                            tasks.append(self._try_connect_and_exchange(device_id, lookup[k], port))
                    if tasks:
                        await asyncio.gather(*tasks, return_exceptions=True)
            except Exception as e:
                print(f"[App] P2P after pair_status: {e}")
            self.main_window.after(0, lambda n=name: self.main_window.show_info(f"Conectat cu {n}"))
            self.main_window.after(0, lambda did=device_id: self._select_contact(did))
            return
        self.main_window.after(0, lambda: self.main_window.show_info(
            "Nimeni nu a intrat pe cod în 120s – ambele trebuie Online (același server/Tor). Regenerează cod."
        ))

    def _on_join_pair(self, code: str):
        if not self.signaling or not self.signaling.connected:
            self.main_window.show_info("Configurează serverul în ⚙ Setări")
            return
        asyncio.run_coroutine_threadsafe(self._join_pair_async(code), self.loop)

    async def _join_pair_async(self, code: str):
        if not await self._ensure_signal_ready_for_pair():
            self.main_window.after(0, lambda: self.main_window.show_info(
                "Nu ești Online – așteaptă Online, apoi intră cu cod"
            ))
            return
        code = (code or "").strip().upper()
        if len(code) < 4:
            self.main_window.after(0, lambda: self.main_window.show_info("Cod prea scurt"))
            return
        info = await self.signaling.pair_join(code)
        if not info:
            self.main_window.after(0, lambda: self.main_window.show_info(
                "Pair eșuat: cod invalid/expirat, sau celălalt nu e Online pe același server"
            ))
            return
        if not info.get("public_key"):
            # retry o dată după scurt delay (Tor lent)
            await asyncio.sleep(1.5)
            info = await self.signaling.pair_join(code)
        if not info or not info.get("public_key"):
            self.main_window.after(0, lambda: self.main_window.show_info(
                "Pair eșuat: peer fără cheie – celălalt să regenereze codul (Online)"
            ))
            return
        device_id = info["device_id"]
        name = info.get("display_name") or f"Peer-{device_id[:8]}"
        pub = info.get("public_key") or ""
        verify_key_hex = info.get("verify_key") or ""
        if not pub or not verify_key_hex:
            self.main_window.after(0, lambda: self.main_window.show_info("Peer fără chei publice complete"))
            return
        pairing_fp = public_key_fingerprint(bytes.fromhex(verify_key_hex))

        c = self.storage.get_contact(device_id)
        if not c:
            c = Contact(
                device_id=device_id, display_name=name, public_key=pub, fingerprint=pairing_fp,
                created_at=time.time(), last_seen=time.time(),
            )
            self.storage.add_contact(c)
            self.main_window.after(0, lambda: self.main_window.add_contact_to_list(
                name, device_id, command=lambda cid=device_id: self._select_contact(cid)
            ))
        else:
            if not fingerprint_transition_allowed(
                    c.fingerprint, c.public_key, pairing_fp, pub):
                self.main_window.after(0, lambda: self.main_window.show_info(
                    "Cheia de identitate a contactului s-a schimbat; împerechere refuzată. "
                    "Verifică fingerprint-ul printr-un canal separat."))
                return
            c.public_key = pub
            c.display_name = name
            c.fingerprint = pairing_fp
            self.storage.add_contact(c)

        try:
            shared = perform_key_exchange(self.identity.private_key, bytes.fromhex(pub))
            self._set_session_key_fs(device_id, shared)
            self._allow_contact_manual(device_id)
            print(f"[App] Session OK cu {name}")
        except Exception as e:
            self.main_window.after(0, lambda: self.main_window.show_info(f"Eroare chei: {e}"))
            return

        await self._send_hello(device_id)
        await asyncio.sleep(0.4)
        await self._send_hello(device_id)

        endpoints = []
        port = int(info.get("port") or DEFAULT_PORT)
        for k in ("ipv6", "ipv4"):
            if info.get(k):
                endpoints.append((info[k], port))
        await self._try_p2p_then_relay_ready(device_id, endpoints)

        await self._flush_pending_relay(device_id)
        self.main_window.after(0, lambda: self.main_window.show_info(
            f"✓ Conectat cu {name} – relay + P2P dacă e disponibil"
        ))
        self.main_window.after(0, lambda: self._select_contact(device_id))

    async def _send_hello(self, to_id: str):
        if not self.signaling or not self.signaling.connected:
            return
        pk = self.identity.public_key.encode(encoder=RawEncoder)
        payload = create_key_exchange(pk, self.identity.device_id, "",  # nume NU pe fir (anti-Wireshark)
                                      
                                      self.identity.get_signing_key())
        ok = await self.signaling.relay_send(to_id, bytes([MSG_HELLO]) + payload)
        print(f"[App] HELLO → {to_id[:12]} ok={ok}")

    # ── Relay ──────────────────────────────────────────────

    async def _rehello_all_contacts(self):
        """După reconnect: HELLO + flush pending pentru fiecare contact."""
        if not self.signaling or not self.signaling.connected:
            return
        try:
            contacts = list(self.storage.get_contacts() or [])
        except Exception:
            contacts = []
        for c in contacts:
            did = getattr(c, "device_id", None) or (c.get("device_id") if isinstance(c, dict) else None)
            if not did:
                continue
            try:
                # reconstruiește session din public_key dacă lipsește
                if not self.storage.get_session_key(did):
                    pub = getattr(c, "public_key", None) or (c.get("public_key") if isinstance(c, dict) else None)
                    if pub:
                        try:
                            shared = perform_key_exchange(self.identity.private_key, bytes.fromhex(pub))
                            self._set_session_key_fs(did, shared)
                        except Exception as e:
                            print(f"[Keep] ecdh {did[:8]}: {e}")
                await self._send_hello(did)
                await self._flush_pending_relay(did)
                await asyncio.sleep(0.15)
            except Exception as e:
                print(f"[Keep] rehello {did[:8] if did else '?'}: {e}")

    async def _peer_keepalive_loop(self):
        """Menține sesiunile peer prin HELLO periodic + flush cozi (chiar dacă Tor face figuri)."""
        while not self._signal_stop and self.main_window is not None:
            try:
                await asyncio.sleep(25.0)
                if not self.signaling or not self.signaling.connected:
                    continue
                try:
                    contacts = list(self.storage.get_contacts() or [])
                except Exception:
                    contacts = []
                for c in contacts:
                    did = getattr(c, "device_id", None) or (c.get("device_id") if isinstance(c, dict) else None)
                    if not did:
                        continue
                    try:
                        if not self.storage.get_session_key(did):
                            pub = getattr(c, "public_key", None) or (c.get("public_key") if isinstance(c, dict) else None)
                            if pub:
                                try:
                                    shared = perform_key_exchange(
                                        self.identity.private_key, bytes.fromhex(pub)
                                    )
                                    self._set_session_key_fs(did, shared)
                                except Exception:
                                    pass
                        # keepalive HELLO ușor – reface canalul E2EE pe relay
                        await self._send_hello(did)
                        await self._flush_pending_relay(did)
                    except Exception as e:
                        print(f"[Keep] peer {did[:8]}: {e}")
                    await asyncio.sleep(0.2)
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[Keep] loop: {e}")
                await asyncio.sleep(5.0)


    async def _relay_poll_loop(self):
        """Poll continuu + recuperare la căderi (Tor/TLS)."""
        bad = 0
        while not self._signal_stop and self.main_window is not None:
            try:
                if self.signaling and self.signaling.connected:
                    items = await self.signaling.relay_poll()
                    # relay_poll întoarce [] și la auth_fail – detectăm prin token pierdut
                    if items is None:
                        bad += 1
                    else:
                        bad = 0
                        acknowledged_ids = []
                        for it in items or []:
                            try:
                                raw = base64.b64decode(it["payload"])
                                if raw and raw[0] in (MSG_GROUP_TEXT, MSG_GROUP_META):
                                    print(
                                        f"[Relay] inbound group type=0x{raw[0]:02x} "
                                        f"from={str(it.get('from') or '')[:8]}"
                                    )
                                await self._handle_relay_payload(it.get("from"), raw)
                                if it.get("id"):
                                    acknowledged_ids.append(it["id"])
                            except Exception as e:
                                print(f"[Relay] item: {e}")
                        if acknowledged_ids and not await self.signaling.relay_ack(acknowledged_ids):
                            print(
                                f"[Relay] {len(acknowledged_ids)} messages were handled "
                                "but not acknowledged"
                            )
                    if bad >= 3:
                        print("[Relay] poll eșuat x3 → reconnect")
                        self.signaling.connected = False
                        bad = 0
                        await self._signal_connect_and_register()
                else:
                    await asyncio.sleep(1.5)
                    continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[Relay] poll: {e}")
                if self.signaling:
                    self.signaling.connected = False
                bad += 1
            await asyncio.sleep(random.uniform(RELAY_POLL_JITTER_MIN, RELAY_POLL_JITTER_MAX))


    async def _flush_pending_relay_inbox(self, device_id: str):
        """Re-procesează mesajele primite înainte de stabilirea cheii."""
        bag = self._pending_relay_inbox.pop(device_id, None) or []
        if not bag:
            return
        print(f"[Relay] flush {len(bag)} mesaje buffer pentru {device_id[:12]}")
        for raw in bag:
            try:
                await self._handle_relay_payload(device_id, raw)
            except Exception as e:
                print(f"[Relay] flush item: {e}")

    async def _handle_relay_payload(self, from_id: str, raw: bytes):
        if not from_id or not raw:
            return
        # Contact șters definitiv: ignoră TOT (HELLO, text, fișiere) până la add/pair manual
        if not self._peer_auto_allowed(from_id):
            if not self._is_known_group_sender(from_id, raw):
                return
            print(f"[Relay] deleted contact allowed as known group member {from_id[:8]}")
        msg_type, payload = raw[0], raw[1:]

        # Notificare pair_joined de la server → încearcă P2P invers
        if msg_type == 0xFE:
            await self._handle_pair_joined_notify(from_id, payload)
            return

        if msg_type in (MSG_HELLO, MSG_HELLO_ACK):
            await self._handle_hello(from_id, payload, is_hello=(msg_type == MSG_HELLO))
            return

        if msg_type in (MSG_TEXT, MSG_FILE_START, MSG_FILE_CHUNK, MSG_FILE_END, MSG_GROUP_TEXT, MSG_GROUP_META):
            sk = self.storage.get_session_key(from_id)
            c = self.storage.get_contact(from_id)
            if not sk and c and c.public_key:
                try:
                    sk = perform_key_exchange(self.identity.private_key, bytes.fromhex(c.public_key))
                    self._set_session_key_fs(from_id, sk)
                except Exception as e:
                    print(f"[Relay] rebuild key: {e}")
            if not sk:
                print(f"[Relay] no key for {from_id[:12]} type=0x{msg_type:02x} – buffer + HELLO (nu pierdem mesajul)")
                if not c:
                    if not self._peer_auto_allowed(from_id):
                        print(f"[App] ignore auto-add (șters) {from_id[:12]}")
                        return
                    c = Contact(
                        device_id=from_id, display_name=f"Peer-{from_id[:8]}",
                        public_key="", created_at=time.time(), last_seen=time.time(),
                    )
                    self.storage.add_contact(c)
                    if self.main_window:
                        self.main_window.after(
                            0, lambda fid=from_id: self.main_window.add_contact_to_list(
                                f"Peer-{fid[:8]}", fid,
                                command=lambda cid=fid: self._select_contact(cid)
                            )
                        )
                # păstrează payload-ul până avem cheie
                bag = self._pending_relay_inbox.setdefault(from_id, [])
                if len(bag) < 50:
                    bag.append(raw)  # include msg_type byte
                await self._send_hello(from_id)
                return

        if msg_type == MSG_TEXT:
            sk = self.storage.get_session_key(from_id)
            if not sk:
                return
            try:
                text = self._decrypt_direct(from_id, payload, sk).decode("utf-8")
            except Exception as e:
                print(f"[Relay] FS2 decrypt rejected (no legacy downgrade): {e}")
                # Legacy ciphertext is intentionally rejected after protocol migration.
                await self._send_hello(from_id)
                return
            if not self.storage.get_contact(from_id):
                if not self._peer_auto_allowed(from_id):
                    print(f"[App] mesaj de la contact șters {from_id[:12]} – ignorat în listă")
                    return
                c = Contact(device_id=from_id, display_name=f"Peer-{from_id[:8]}", public_key="",
                            created_at=time.time(), last_seen=time.time())
                self.storage.add_contact(c)
                self.main_window.after(0, lambda: self.main_window.add_contact_to_list(
                    c.display_name, from_id, command=lambda cid=from_id: self._select_contact(cid)
                ))
            self._ingest_text_message(from_id, text, "relay")
            return

        if msg_type == MSG_FILE_START:
            await self._handle_relay_file_start(from_id, payload)
            return
        if msg_type == MSG_FILE_CHUNK:
            await self._handle_relay_file_chunk(from_id, payload)
            return
        if msg_type == MSG_FILE_END:
            await self._handle_relay_file_end(from_id, payload)
            return

        if msg_type == MSG_GROUP_TEXT:
            await self._handle_group_text(from_id, payload)
            return
        if msg_type == MSG_GROUP_META:
            await self._handle_group_meta(from_id, payload)
            return


    async def _handle_pair_joined_notify(self, from_id: str, payload: bytes):
        # filtrat după extragerea peer_id

        # peer_id extras mai jos; gate după parse

        """Server anunță creatorul codului că cineva a intrat — setează contact + chei + HELLO."""
        try:
            data = json.loads(payload.decode("utf-8"))
        except Exception:
            data = {}
        peer_id = data.get("device_id") or data.get("peer_id") or from_id
        if peer_id and not self._peer_auto_allowed(peer_id):
            print(f"[App] pair_joined drop – contact șters {str(peer_id)[:12]}")
            return
        name = (data.get("display_name") or "").strip() or f"Peer-{(peer_id or '')[:8]}"
        pub = data.get("public_key") or ""
        verify_key = data.get("verify_key") or ""
        if not peer_id:
            return
        print(f"[App] pair_joined notify de la {peer_id[:12]}… name={name}")

        c = self.storage.get_contact(peer_id)
        fp = ""
        if verify_key:
            try:
                fp = public_key_fingerprint(bytes.fromhex(verify_key))
            except Exception:
                fp = ""
        if not c:
            c = Contact(
                device_id=peer_id, display_name=name, public_key=pub,
                fingerprint=fp, created_at=time.time(), last_seen=time.time(),
            )
            self.storage.add_contact(c)
            self.main_window.after(
                0, lambda n=name, pid=peer_id: self.main_window.add_contact_to_list(
                    n, pid, command=lambda cid=pid: self._select_contact(cid)
                )
            )
        else:
            if name and (not c.display_name or c.display_name.startswith("Peer-")):
                c.display_name = name
            if pub:
                c.public_key = pub
            if fp:
                c.fingerprint = fp
            self.storage.add_contact(c)
            self.main_window.after(
                0, lambda n=c.display_name, pid=peer_id: self.main_window.add_contact_to_list(
                    n, pid, command=lambda cid=pid: self._select_contact(cid)
                )
            )

        if pub:
            try:
                shared = perform_key_exchange(self.identity.private_key, bytes.fromhex(pub))
                self._set_session_key_fs(peer_id, shared)
                print(f"[App] session din pair_joined OK {name}")
            except Exception as e:
                print(f"[App] pair_joined ecdh: {e}")

        await self._send_hello(peer_id)
        await asyncio.sleep(0.3)
        await self._send_hello(peer_id)
        await self._flush_pending_relay(peer_id)
        self.main_window.after(0, lambda n=name: self.main_window.show_info(
            f"Peer conectat: {n} – poți scrie"
        ))
        self.main_window.after(0, lambda pid=peer_id: self._select_contact(pid))

    async def _handle_hello(self, from_id: str, payload: bytes, is_hello: bool):
        try:
            if not verify_key_exchange(payload):
                print(f"[Relay] HELLO cu semnătură invalidă: {from_id[:12]}")
                return
            _, peer_pub, claimed_id, wire_name, peer_verify_key, _ = parse_key_exchange(payload)
            if claimed_id != from_id:
                print("[Relay] ID expeditor diferit de ID-ul semnat")
                return
            # Numele pe fir e gol (privacy) — nu inlocui contactul existent cu Peer-xxx
            wire_name = (wire_name or "").strip()
        except Exception as exc:
            print(f"[Relay] HELLO invalid: {exc}")
            return

        c = self.storage.get_contact(from_id)
        peer_sign_fp = public_key_fingerprint(peer_verify_key)
        if c and not fingerprint_transition_allowed(
                c.fingerprint, c.public_key, peer_sign_fp, peer_pub.hex()):
            print(f"[SECURITY] Cheia de identitate s-a schimbat pentru {from_id[:12]}; respins")
            self.main_window.after(0, lambda: self.main_window.show_info(
                "ATENTIE: cheia de identitate a contactului s-a schimbat. Mesaj respins."))
            return

        if c and c.display_name and not c.display_name.startswith("Peer-"):
            name = c.display_name
        elif wire_name:
            name = wire_name
        elif c and c.display_name:
            name = c.display_name
        else:
            name = f"Peer-{from_id[:8]}"

        if not c:
            c = Contact(
                device_id=from_id, display_name=name, public_key=peer_pub.hex(),
                fingerprint=peer_sign_fp, created_at=time.time(), last_seen=time.time(),
            )
            self.storage.add_contact(c)
            self.main_window.after(0, lambda n=name, fid=from_id: self.main_window.add_contact_to_list(
                n, fid, command=lambda cid=fid: self._select_contact(cid)
            ))
        else:
            c.public_key = peer_pub.hex()
            # nu suprascrie "antonio" cu "" / Peer-
            if wire_name and (not c.display_name or c.display_name.startswith("Peer-")):
                c.display_name = wire_name
            c.fingerprint = peer_sign_fp
            self.storage.add_contact(c)
            name = c.display_name or name

        try:
            shared = perform_key_exchange(self.identity.private_key, peer_pub)
            self._set_session_key_fs(from_id, shared)
            await self._flush_pending_relay_inbox(from_id)
            await self._request_group_epochs_from_peer(from_id)
            await self._sync_creator_group_keys_to_peer(from_id)
            print(f"[App] HELLO session OK {name}")
        except Exception as e:
            print(f"[App] HELLO ecdh: {e}")
            return

        if is_hello and self.signaling and self.signaling.connected:
            try:
                pk = self.identity.public_key.encode(encoder=RawEncoder)
                pl = create_key_exchange(
                    pk, self.identity.device_id, "", self.identity.get_signing_key()
                )
                await self.signaling.relay_send(from_id, bytes([MSG_HELLO_ACK]) + pl)
            except Exception as e:
                print(f"[App] HELLO_ACK send: {e}")

        # o singura notificare per peer (evita spam / „erori” vizuale)
        if not hasattr(self, "_secure_notified"):
            self._secure_notified = set()
        if from_id not in self._secure_notified:
            self._secure_notified.add(from_id)
            self.main_window.after(
                0, lambda n=name: self.main_window.show_info(f"Canal securizat cu {n}")
            )
        # Completeaza numele din register (pe fir HELLO e gol)
        try:
            if self.signaling and self.signaling.connected:
                info = await self.signaling.lookup(from_id)
                dn = (info or {}).get("display_name") or ""
                if dn.strip():
                    c2 = self.storage.get_contact(from_id)
                    if c2:
                        c2.display_name = dn.strip()
                        self.storage.add_contact(c2)
                        name = c2.display_name
                        self.main_window.after(
                            0, lambda n=name, fid=from_id: self.main_window.add_contact_to_list(
                                n, fid, command=lambda cid=fid: self._select_contact(cid)
                            )
                        )
                        if self.current_contact_id == from_id:
                            self.main_window.after(
                                0, lambda n=name: self.main_window.set_chat_title(n, online=True)
                            )
        except Exception as e:
            print(f"[App] lookup name: {e}")
        await self._flush_pending_relay(from_id)
        # încearcă P2P direct via lookup pe serverul de semnalizare
        if self.signaling and self.signaling.connected and from_id not in self.network.connections:
            try:
                lookup = await self.signaling.lookup(from_id)
                if lookup:
                    port = int(lookup.get("port") or DEFAULT_PORT)
                    for k in ("ipv6", "ipv4"):
                        if lookup.get(k):
                            await self._try_connect_and_exchange(from_id, lookup[k], port)
            except Exception as e:
                print(f"[App] P2P after HELLO: {e}")

    async def _flush_pending_relay(self, device_id: str):
        sk = self.storage.get_session_key(device_id)
        if not sk or not self.signaling:
            return
        pending = self.storage.get_pending(device_id)
        for payload in pending:
            try:
                blob = self._encrypt_direct(device_id, payload, sk)
                await self.signaling.relay_send(device_id, bytes([MSG_TEXT]) + blob)
            except Exception as e:
                print(f"[App] flush: {e}")
                return
        if pending:
            self.storage.clear_pending(device_id)
        await self._flush_pending_group_frames(device_id)

    async def _flush_pending_group_frames(self, device_id: str):
        if not self.signaling or not self.signaling.connected:
            return set()
        lock = self._pending_group_flush_locks.setdefault(device_id, asyncio.Lock())
        async with lock:
            pending = self.storage.get_pending_group_frames(device_id)
            sent_ids = set()
            for item in pending:
                gid = item["group_id"]
                payload = item["payload"]
                packed = item["packed"]
                if not packed:
                    sk = self.storage.get_session_key(device_id)
                    if not sk:
                        await self._send_hello(device_id)
                        return sent_ids
                    gid_bytes = gid.encode("utf-8")
                    if len(gid_bytes) > 64 or len(payload) < 12:
                        raise ValueError("invalid pending group frame")
                    epoch = struct.unpack(">Q", payload[4:12])[0]
                    group = self._groups.get(gid) or {}
                    if group.get("creator_id") == self.identity.device_id:
                        secret = self.storage.load_group_crypto_state(f"gk|{gid}|{epoch}")
                        if secret is None or not await self._send_group_epoch(
                            gid, device_id, secret, epoch
                        ):
                            await self._send_hello(device_id)
                            return sent_ids
                    encrypted = self._encrypt_direct(device_id, payload, sk)
                    payload = (
                        bytes([MSG_GROUP_TEXT]) + struct.pack(">H", len(gid_bytes))
                        + gid_bytes + encrypted
                    )
                    self.storage.update_pending_group_frame(
                        item["id"], gid, device_id, payload, True
                    )
                if not await self.signaling.relay_send(device_id, payload):
                    return sent_ids
                self.storage.delete_pending_group_frame(item["id"])
                sent_ids.add(item["id"])
            return sent_ids


    def _ingest_text_message(self, from_id: str, text: str, via: str = ""):
        """Salvează și afișează un mesaj inbound, cu deduplicare (anti dublu P2P+relay)."""
        now = time.time()
        # cheie stabilă ~60s – același text de la același peer nu se afișează de 2 ori
        key = f"{from_id}:{hash(text)}"
        if not hasattr(self, "_recent_msg_ts"):
            self._recent_msg_ts = {}
        last = self._recent_msg_ts.get(key, 0)
        if now - last < 60.0:
            return
        self._recent_msg_ts[key] = now
        # curățare
        if len(self._recent_msg_ts) > 400:
            cutoff = now - 120
            self._recent_msg_ts = {k: t for k, t in self._recent_msg_ts.items() if t >= cutoff}
        self._recent_msg_ids.add(key)
        if len(self._recent_msg_ids) > 500:
            self._recent_msg_ids = set(list(self._recent_msg_ids)[-200:])
        self.storage.save_message(Message(
            id=None, contact_id=from_id, direction="in", msg_type="text",
            content=text, timestamp=time.time(), status="delivered"
        ))
        if not self.current_group_id:
            if self.current_contact_id == from_id:
                self.main_window.after(0, lambda t=text: self.main_window.add_message_bubble(t, False))
            else:
                # mesaj de la alt contact – asigură-l în listă
                c = self.storage.get_contact(from_id)
                label = (c.display_name if c else None) or f"Peer-{from_id[:8]}"
                self.main_window.after(
                    0, lambda n=label, fid=from_id: self.main_window.add_contact_to_list(
                        n, fid, command=lambda cid=fid: self._select_contact(cid)
                    )
                )

        # ── Send / receive text ────────────────────────────────
    def _on_send_message(self, text):
        if self.current_group_id:
            asyncio.run_coroutine_threadsafe(self._send_group_message(text), self.loop)
            return
        if not self.current_contact_id:
            self.main_window.show_info("Selectează un contact sau un grup")
            return
        if not self._rate.allow("out"):
            self.main_window.show_info("Prea multe mesaje")
            return
        # Același model ca grupul: async pe loop, relay-first
        asyncio.run_coroutine_threadsafe(
            self._send_direct_message(text), self.loop
        )

    async def _on_network_message(self, conn, msg_type, payload):
        did = getattr(conn, "device_id", None) if conn else None
        if did and not self._peer_auto_allowed(did):
            return
        if not conn.device_id or msg_type != MSG_TEXT:
            return
        sk = self.storage.get_session_key(conn.device_id) or conn.session_key
        if not sk:
            return
        try:
            text = self._decrypt_direct(conn.device_id, payload, sk).decode("utf-8")
        except Exception as e:
            print(f"[App] p2p decrypt: {e}")
            return
        self._ingest_text_message(conn.device_id, text, "p2p")

    async def _on_key_exchange(self, conn, payload):
        try:
            if not verify_key_exchange(payload):
                raise ValueError("Semnătura handshake-ului este invalidă")
            version, peer_pubkey, peer_device_id, peer_name, peer_verify_key, _ = parse_key_exchange(payload)
            expected_id = getattr(conn, "expected_device_id", None)
            if expected_id and peer_device_id != expected_id:
                raise ValueError("ID-ul peer-ului nu corespunde destinației cerute")
            c_existing = self.storage.get_contact(peer_device_id)
            peer_sign_fp = public_key_fingerprint(peer_verify_key)
            if c_existing and not fingerprint_transition_allowed(
                    c_existing.fingerprint, c_existing.public_key,
                    peer_sign_fp, peer_pubkey.hex()):
                raise ValueError("Cheia de identitate a contactului s-a schimbat")
            shared = perform_key_exchange(self.identity.private_key, peer_pubkey)
            conn.device_id = peer_device_id
            conn.display_name = peer_name
            conn.session_key = shared
            self.network.connections[peer_device_id] = conn
            self._set_session_key_fs(peer_device_id, shared)
            peer_ip = None
            try:
                peer_addr = conn.writer.get_extra_info("peername")
                if peer_addr and peer_addr[0]:
                    peer_ip = str(peer_addr[0])
            except Exception:
                pass

            c = self.storage.get_contact(peer_device_id)
            if not c:
                c = Contact(
                    device_id=peer_device_id, display_name=peer_name,
                    public_key=peer_pubkey.hex(), fingerprint=peer_sign_fp,
                    created_at=time.time(), last_seen=time.time(),
                )
                self.storage.add_contact(c)
                self.main_window.after(0, lambda: self.main_window.add_contact_to_list(
                    peer_name, peer_device_id,
                    command=lambda cid=peer_device_id: self._select_contact(cid)
                ))
            else:
                c.public_key = peer_pubkey.hex()
                if peer_name and (not c.display_name or c.display_name.startswith("Peer-")):
                    c.display_name = peer_name
                c.fingerprint = peer_sign_fp
                self.storage.add_contact(c)
            if peer_ip:
                # Remote source port is ephemeral; the peer listens on DEFAULT_PORT.
                self.storage.update_contact_endpoint(peer_device_id, peer_ip, DEFAULT_PORT)

            if peer_device_id not in self._exchanged:
                self._exchanged.add(peer_device_id)
                my_pub = self.identity.public_key.encode(encoder=RawEncoder)
                await self.network.send_message(
                    conn, MSG_KEY_EXCHANGE,
                    create_key_exchange(my_pub, self.identity.device_id, "",  # nume NU pe fir (anti-Wireshark)
                                       self.identity.get_signing_key())
                )
            print(f"[App] P2P session cu {peer_name} (tls={getattr(conn, 'tls', False)})")
            # mesaje din coadă pe P2P dacă există
            try:
                await self._flush_pending_relay(peer_device_id)
            except Exception:
                pass
            if self.current_contact_id == peer_device_id:
                self.main_window.after(0, lambda: self.main_window.set_chat_title(peer_name, online=True))
        except Exception as e:
            print(f"[App] KE respins: {e}")
            try:
                await self.network._close_conn(conn)
            except Exception:
                pass

    def _on_send_file(self, path):
        if self.current_group_id:
            p = Path(path)
            if not p.is_file():
                self.main_window.show_info("Fișier invalid")
                return
            if p.stat().st_size > MAX_FILE_SIZE or p.stat().st_size == 0:
                self.main_window.show_info("Fișier prea mare / gol")
                return
            asyncio.run_coroutine_threadsafe(self._send_group_file_async(p), self.loop)
            return
        if not self.current_contact_id:
            self.main_window.show_info("Selectează un contact")
            return
        p = Path(path)
        if not p.is_file():
            self.main_window.show_info("Fișier invalid")
            return
        size = p.stat().st_size
        if size > MAX_FILE_SIZE or size == 0:
            self.main_window.show_info("Fișier prea mare / gol")
            return
        cid = self.current_contact_id
        sk = self.storage.get_session_key(cid)
        if not sk:
            self.main_window.show_info("Se așteaptă conectarea la contact")
            asyncio.run_coroutine_threadsafe(self._send_hello(cid), self.loop)
            return
        conn = self.network.connections.get(cid)
        asyncio.run_coroutine_threadsafe(self._send_file_async(conn, sk, p, cid), self.loop)

    def _toggle_voice_recording(self):
        if self._voice_recorder is None:
            try:
                recorder = VoiceRecorder()
                path = self.temp_dir / f"voice_{uuid.uuid4().hex}.wav"
                recorder.start(path)
                self._voice_recorder = recorder
                self._voice_recording_path = path
                self.main_window.set_voice_recording(True)
                self.main_window.show_info("Se înregistrează vocea — apasă ■ pentru oprire și trimitere")
            except Exception as exc:
                self._voice_recorder = None
                self._voice_recording_path = None
                self.main_window.show_info(f"Nu s-a putut porni înregistrarea: {exc}")
            return

        recorder = self._voice_recorder
        self._voice_recorder = None
        self.main_window.set_voice_recording(False)
        try:
            path = recorder.stop()
            self._voice_recording_path = None
            self._on_send_file(str(path))
        except Exception as exc:
            self._voice_recording_path = None
            self.main_window.show_info(f"Înregistrarea vocală a eșuat: {exc}")

    def _cancel_voice_recording(self):
        recorder = self._voice_recorder
        self._voice_recorder = None
        if recorder:
            try:
                recorder.cancel()
            except Exception as exc:
                print(f"[Audio] stop recorder: {exc}")
        self._voice_recording_path = None
        if self.main_window:
            self.main_window.set_voice_recording(False)

    async def _handle_relay_file_start(self, from_id: str, payload: bytes):
        try:
            sk = self.storage.get_session_key(from_id)
            if not sk:
                return
            plain = self._decrypt_direct(from_id, payload, sk)
            tid, filename, fsize, total = parse_file_start(plain)
            if not filename or not 0 < fsize <= MAX_FILE_SIZE or total <= 0:
                return
            self._incoming_files[tid] = {
                "filename": Path(filename).name,
                "total": total,
                "size": fsize,
                "chunks": {},
                "device_id": from_id,
                "session_key": sk,
            }
            self.main_window.after(0, lambda: self.main_window.show_transfer_progress(f"Se primește {filename}…"))
        except Exception as e:
            print(f"[Relay] FILE_START: {e}")

    async def _handle_relay_file_chunk(self, from_id: str, payload: bytes):
        try:
            tid, idx, enc = parse_file_chunk(payload)
            st = self._incoming_files.get(tid)
            if not st or st.get("device_id") != from_id or not st.get("session_key"):
                return
            if not 0 <= idx < st["total"]:
                return
            chunk = self._decrypt_direct(from_id, enc, st["session_key"])
            st["chunks"][idx] = chunk
            total = st["total"]
            done = len(st["chunks"])
            name = st["filename"]
            self.main_window.after(0, lambda: self.main_window.show_transfer_progress(f"Se primește {name} ({done * 100 // total}%)…"))
        except Exception as e:
            print(f"[Relay] FILE_CHUNK: {e}")

    async def _handle_relay_file_end(self, from_id: str, payload: bytes):
        try:
            sk = self.storage.get_session_key(from_id)
            if not sk:
                return
            plain = self._decrypt_direct(from_id, payload, sk)
            tid = parse_file_end(plain)
            st = self._incoming_files.pop(tid, None)
            if not st or st.get("device_id") != from_id or len(st["chunks"]) < st["total"]:
                return
            data = b"".join(st["chunks"][i] for i in range(st["total"]))
            fname = st["filename"]
            mk = self.identity.get_master_key()
            dest = save_encrypted_file(self.files_dir, mk, fname, data)
            self.storage.save_message(Message(
                id=None, contact_id=from_id, direction="in", msg_type="file",
                content=f"{fname}|{dest}", timestamp=time.time(), status="delivered"
            ))
            is_img = Path(fname).suffix.lower() in IMAGE_EXTENSIONS
            tmp = export_to_temp(dest, mk, self.temp_dir)
            if self.current_contact_id == from_id:
                self.main_window.after(0, lambda: self.main_window.add_file_bubble(fname, str(tmp), False, is_img))
            self.main_window.after(0, lambda: self.main_window.show_transfer_progress(f"✓ Primit: {fname}"))
        except Exception as e:
            print(f"[Relay] FILE_END: {e}")

    async def _send_group_file_async(self, path: Path):
        gid = self.current_group_id
        if not gid:
            return
        membership_changed = await self._refresh_group_members(gid)
        group = self._groups.get(gid) or {}
        members = [mid for mid in group.get("members", []) if mid != self.identity.device_id]
        if not members:
            self.main_window.after(0, lambda: self.main_window.show_info("Grupul nu are alți membri"))
            return
        missing = [mid for mid in members if not self.storage.get_session_key(mid)]
        if missing:
            for mid in missing:
                await self._send_hello(mid)
            self.main_window.after(0, lambda: self.main_window.show_info(
                "Se pregătesc canalele securizate; încearcă din nou după conectare"
            ))
            return
        secret = self._refresh_group_epoch(gid, membership_changed)
        if secret is None:
            await self._request_group_epoch(gid)
            self.main_window.after(0, lambda: self.main_window.show_info(
                "Se așteaptă cheia securizată a grupului"
            ))
            return
        if group.get("creator_id") == self.identity.device_id:
            await self._distribute_group_epoch(gid, secret)

        data = path.read_bytes()
        master_key = self.identity.get_master_key()
        vault = save_encrypted_file(self.files_dir, master_key, path.name, data)
        transfer_id = uuid.uuid4().hex[:16]
        total = math.ceil(len(data) / GROUP_FILE_CHUNK_SIZE)
        self.main_window.after(0, lambda: self.main_window.show_transfer_progress(
            f"Se trimite {path.name}…"
        ))
        events = [{
            "kind": "file_start", "transfer_id": transfer_id, "filename": path.name,
            "file_size": len(data), "total_chunks": total,
        }]
        sent = await self._broadcast_group_event(gid, members, secret, events[0])
        if sent != len(members):
            self.main_window.after(0, lambda: self.main_window.show_info(
                f"Trimitere incompletă: {path.name}"
            ))
            return
        for index in range(total):
            event = {
                "kind": "file_chunk", "transfer_id": transfer_id, "chunk_index": index,
                "data": base64.b64encode(data[index * GROUP_FILE_CHUNK_SIZE:
                                               (index + 1) * GROUP_FILE_CHUNK_SIZE]).decode("ascii"),
            }
            sent = await self._broadcast_group_event(gid, members, secret, event)
            if sent != len(members):
                self.main_window.after(0, lambda: self.main_window.show_info(
                    f"Trimitere întreruptă: {path.name}"
                ))
                return
            self.main_window.after(0, lambda n=index + 1, t=total: self.main_window.show_transfer_progress(
                f"Se trimite {path.name} ({n * 100 // t}%)"
            ))
            await asyncio.sleep(0.05)
        sent = await self._broadcast_group_event(gid, members, secret, {
            "kind": "file_end", "transfer_id": transfer_id,
        })
        if sent == len(members):
            self.storage.save_message(Message(
                id=None, contact_id=f"group:{gid}", direction="out", msg_type="file",
                content=f"{path.name}|{vault}", timestamp=time.time(), status="sent",
            ))
            is_img = path.suffix.lower() in IMAGE_EXTENSIONS
            self.main_window.after(0, lambda: self.main_window.add_file_bubble(
                path.name, str(path), True, is_img
            ))
            self.main_window.after(0, lambda: self.main_window.show_transfer_progress(f"✓ {path.name}"))

    async def _send_file_async(self, conn, session_key, path: Path, peer_id: str):
        tid = uuid.uuid4().hex[:16]
        data = path.read_bytes()
        total = max(1, math.ceil(len(data) / FILE_CHUNK_SIZE))
        self.main_window.after(0, lambda: self.main_window.show_transfer_progress(f"Se trimite {path.name}…"))
        start_plain = create_file_start(tid, path.name, len(data), total)
        enc_start = self._encrypt_direct(peer_id, start_plain, session_key)
        if conn:
            await self.network.send_message(conn, MSG_FILE_START, enc_start)
        elif self.signaling and self.signaling.connected:
            await self.signaling.relay_send(peer_id, bytes([MSG_FILE_START]) + enc_start)

        for i in range(total):
            chunk = data[i * FILE_CHUNK_SIZE:(i + 1) * FILE_CHUNK_SIZE]
            chunk_payload = create_file_chunk(tid, i, self._encrypt_direct(peer_id, chunk, session_key))
            if conn:
                await self.network.send_message(conn, MSG_FILE_CHUNK, chunk_payload)
            elif self.signaling and self.signaling.connected:
                await self.signaling.relay_send(peer_id, bytes([MSG_FILE_CHUNK]) + chunk_payload)
            await asyncio.sleep(0.01)

        end_plain = create_file_end(tid)
        enc_end = self._encrypt_direct(peer_id, end_plain, session_key)
        if conn:
            await self.network.send_message(conn, MSG_FILE_END, enc_end)
        elif self.signaling and self.signaling.connected:
            await self.signaling.relay_send(peer_id, bytes([MSG_FILE_END]) + enc_end)

        mk = self.identity.get_master_key()
        dest = save_encrypted_file(self.files_dir, mk, path.name, data)
        self.storage.save_message(Message(
            id=None, contact_id=peer_id, direction="out", msg_type="file",
            content=f"{path.name}|{dest}", timestamp=time.time(), status="sent"
        ))
        is_img = path.suffix.lower() in IMAGE_EXTENSIONS
        tmp = export_to_temp(dest, mk, self.temp_dir)
        self.main_window.after(0, lambda: self.main_window.add_file_bubble(
            path.name, str(tmp), True, is_img
        ))
        self.main_window.after(0, lambda: self.main_window.show_transfer_progress(f"✓ {path.name}"))

    async def _on_file_start(self, conn, payload):
        try:
            session_key = self.storage.get_session_key(conn.device_id) or conn.session_key
            if not session_key:
                raise ValueError("missing session key for file transfer")
            plain = self._decrypt_direct(conn.device_id, payload, session_key)
            tid, filename, fsize, total = parse_file_start(plain)
            self._incoming_files[tid] = {
                "filename": filename, "total": total, "chunks": {},
                "device_id": conn.device_id,
                "session_key": self.storage.get_session_key(conn.device_id) or conn.session_key,
            }
            self.main_window.after(0, lambda: self.main_window.show_transfer_progress(f"Se primește {filename}…"))
        except Exception as e:
            print(f"FILE_START: {e}")

    async def _on_file_chunk(self, conn, payload):
        try:
            tid, idx, enc = parse_file_chunk(payload)
            st = self._incoming_files.get(tid)
            if not st or not st.get("session_key"):
                return
            st["chunks"][idx] = self._decrypt_direct(st["device_id"], enc, st["session_key"])
        except Exception as e:
            print(f"FILE_CHUNK: {e}")

    async def _on_file_end(self, conn, payload):
        try:
            session_key = self.storage.get_session_key(conn.device_id) or conn.session_key
            if not session_key:
                raise ValueError("missing session key for file transfer")
            plain = self._decrypt_direct(conn.device_id, payload, session_key)
            tid = parse_file_end(plain)
            st = self._incoming_files.pop(tid, None)
            if not st or len(st["chunks"]) < st["total"]:
                return
            data = b"".join(st["chunks"][i] for i in range(st["total"]))
            fname = st["filename"]
            mk = self.identity.get_master_key()
            dest = save_encrypted_file(self.files_dir, mk, fname, data)
            self.storage.save_message(Message(
                id=None, contact_id=st["device_id"], direction="in", msg_type="file",
                content=f"{fname}|{dest}", timestamp=time.time(), status="delivered"
            ))
            is_img = Path(fname).suffix.lower() in IMAGE_EXTENSIONS
            tmp = export_to_temp(dest, mk, self.temp_dir) if is_img else dest
            if self.current_contact_id == st["device_id"]:
                self.main_window.after(0, lambda: self.main_window.add_file_bubble(fname, str(tmp), False, is_img))
            self.main_window.after(0, lambda: self.main_window.show_transfer_progress(f"✓ Primit: {fname}"))
        except Exception as e:
            print(f"FILE_END: {e}")

    def _open_file_safe(self, path: str):
        p = Path(path)
        try:
            if p.suffix == ".vault":
                mk = self.identity.get_master_key()
                if not mk:
                    return
                path = str(export_to_temp(p, mk, self.temp_dir))
                p = Path(path)
            if p.suffix.lower() in RISKY_EXTENSIONS | {
                ".exe", ".com", ".bat", ".cmd", ".ps1", ".msi", ".scr",
                ".vbs", ".js", ".jar", ".reg", ".sh",
            }:
                from tkinter import messagebox
                if not messagebox.askokcancel("Atenție", f"Fișierul {p.name} poate fi riscant. Deschizi?"):
                    return
            if sys.platform.startswith("win"):
                os.startfile(path)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception as e:
            print(f"[App] open: {e}")

    def _on_local_typing(self):
        now = time.time()
        if now - self._last_typing_sent < 2.0:
            return
        self._last_typing_sent = now
        conn = self.network.connections.get(self.current_contact_id) if self.current_contact_id else None
        if conn and self.loop:
            asyncio.run_coroutine_threadsafe(self.network.send_message(conn, MSG_TYPING, b""), self.loop)

    async def _on_peer_typing(self, device_id):
        if device_id != self.current_contact_id:
            return
        c = self.storage.get_contact(device_id)
        name = c.display_name if c else "Peer"
        self.main_window.after(0, lambda: self.main_window.set_typing(name))

    async def _on_peer_disconnect(self, device_id):
        if self.current_contact_id == device_id:
            c = self.storage.get_contact(device_id)
            name = c.display_name if c else device_id[:12]
            # tot e "online" pe relay dacă avem session key
            online = bool(self.storage.get_session_key(device_id))
            self.main_window.after(0, lambda: self.main_window.set_chat_title(name, online=online))

    def _bind_activity_tracking(self):
        def bump(_e=None):
            self._last_activity = time.time()
        try:
            self.main_window.bind_all("<Key>", bump)
            self.main_window.bind_all("<Button>", bump)
        except Exception:
            pass

    def _arm_idle_lock(self):
        """IDLE_LOCK_SECONDS <= 0 → dezactivat (conexiune persistentă)."""
        if not self.main_window:
            return
        try:
            if not IDLE_LOCK_SECONDS or IDLE_LOCK_SECONDS <= 0:
                return
            if time.time() - getattr(self, "_last_activity", time.time()) >= IDLE_LOCK_SECONDS:
                self.main_window.after(0, self._on_logout)
                return
            self.main_window.after(15000, self._arm_idle_lock)
        except Exception:
            pass


    # ── Groups ─────────────────────────────────────────────
    def _on_create_group(self):
        if not self.signaling or not self.signaling.connected:
            self.main_window.show_info("Serverul de semnalizare e necesar pentru grupuri")
            return
        dialog = __import__("customtkinter", fromlist=["CTkInputDialog"]).CTkInputDialog(
            text="Numele grupului:", title="Creează grup"
        )
        name = dialog.get_input()
        if name and name.strip():
            asyncio.run_coroutine_threadsafe(self._create_group_async(name.strip()), self.loop)

    def _on_join_group(self):
        if not self.signaling or not self.signaling.connected:
            self.main_window.show_info("Serverul de semnalizare e necesar")
            return
        dialog = __import__("customtkinter", fromlist=["CTkInputDialog"]).CTkInputDialog(
            text="Cod invitație grup (ca la pair):", title="Intră în grup"
        )
        code = dialog.get_input()
        if code and code.strip():
            asyncio.run_coroutine_threadsafe(
                self._join_group_async(code.strip().upper()), self.loop
            )

    async def _create_group_async(self, name: str):
        info = await self.signaling.group_create(name)
        if not info:
            self.main_window.after(0, lambda: self.main_window.show_info(
                "Creare grup eșuată – Online (relay)? Server actualizat?"
            ))
            return
        gid = info["group_id"]
        code = info["invite_code"]
        self._groups[gid] = {
            "name": name,
            "members": [self.identity.device_id],
            "invite_code": code,
            "creator_id": info.get("creator_id") or self.identity.device_id,
            "epoch": 0,
            "epoch_members": [self.identity.device_id],
        }
        self._persist_group(gid)
        self.main_window.after(0, lambda: self.main_window.add_group_to_list(
            name, gid, command=lambda g=gid: self._select_group(g)
        ))
        self.main_window.after(0, lambda: self.main_window.show_pair_code(code))
        self.main_window.after(0, lambda: self.main_window.show_info(
            f"Grup «{name}» creat. Dă codul: {code}"
        ))
        self.main_window.after(0, lambda: self._select_group(gid))
        print(f"[Group] created {gid} code={code}")

    async def _join_group_async(self, code: str):
        info = await self.signaling.group_join(code)
        if not info:
            self.main_window.after(0, lambda: self.main_window.show_info(
                "Cod grup invalid / auth – verifică codul și că serverul e actualizat"
            ))
            return
        gid = info["group_id"]
        name = info.get("name") or "Grup"
        previous_group = self._groups.get(gid) or {}
        members = info.get("members") or []
        member_ids = []
        for m in members:
            mid = m.get("device_id") if isinstance(m, dict) else m
            if not mid:
                continue
            member_ids.append(mid)
            if mid == self.identity.device_id:
                continue
            pub = (m.get("public_key") or "") if isinstance(m, dict) else ""
            dname = (m.get("display_name") or f"anon-{mid[:6]}") if isinstance(m, dict) else f"anon-{mid[:6]}"
            if pub:
                try:
                    shared = perform_key_exchange(
                        self.identity.private_key, bytes.fromhex(pub)
                    )
                    self._set_session_key_fs(mid, shared)
                except Exception as e:
                    print(f"[Group] ecdh {mid[:8]}: {e}")
            if not self.storage.get_contact(mid):
                self.storage.add_contact(Contact(
                    device_id=mid, display_name=dname, public_key=pub or "",
                    created_at=time.time(), last_seen=time.time(),
                ))
            await self._send_hello(mid)
        self._groups[gid] = {
            "name": name,
            "members": member_ids,
            "invite_code": code,
            "creator_id": info.get("creator_id") or next(
                (m.get("device_id") for m in members if isinstance(m, dict) and m.get("device_id")),
                "",
            ),
            "epoch": previous_group.get("epoch", 0),
            "epoch_members": previous_group.get("epoch_members", []),
        }
        self._persist_group(gid)
        await self._request_group_epoch(gid)
        self.main_window.after(0, lambda: self.main_window.add_group_to_list(
            name, gid, command=lambda g=gid: self._select_group(g)
        ))
        self.main_window.after(0, lambda: self.main_window.show_info(
            f"✓ Intrat în «{name}» ({len(member_ids)} membri)"
        ))
        self.main_window.after(0, lambda: self._select_group(gid))
        print(f"[Group] joined {gid} members={len(member_ids)}")

    def _select_group(self, group_id: str):
        self.current_group_id = group_id
        self.current_contact_id = None
        g = self._groups.get(group_id) or {}
        name = g.get("name") or "Grup"
        code = g.get("invite_code") or ""
        title = f"👥 {name}" + (f"  [{code}]" if code else "")
        self.main_window.set_chat_title(title, online=True)
        self.main_window.clear_messages()
        for msg in self.storage.get_messages(f"group:{group_id}"):
            if msg.msg_type == "file":
                filename, vault_path = msg.content.split("|", 1)
                try:
                    filepath = export_to_temp(
                        vault_path, self.identity.get_master_key(), self.temp_dir
                    )
                except Exception as exc:
                    print(f"[Group] cannot restore file {filename}: {exc}")
                    continue
                is_image = Path(filename).suffix.lower() in IMAGE_EXTENSIONS
                self.main_window.add_file_bubble(
                    filename, str(filepath), msg.direction == "out", is_image
                )
            elif msg.direction == "out":
                self.main_window.add_message_bubble(f"Tu: {msg.content}", True)
            else:
                self.main_window.add_message_bubble(msg.content, False)
        if self.loop and self.signaling:
            asyncio.run_coroutine_threadsafe(
                self._refresh_group_members(group_id), self.loop
            )

    async def _refresh_group_members(self, group_id: str):
        info = await self.signaling.group_info(group_id)
        if not info:
            return False
        previous_members = set((self._groups.get(group_id) or {}).get("members", []))
        members = info.get("members") or []
        ids = []
        for m in members:
            mid = m.get("device_id")
            if not mid:
                continue
            ids.append(mid)
            pub = m.get("public_key") or ""
            dname = m.get("display_name") or f"anon-{mid[:6]}"
            if mid == self.identity.device_id:
                continue
            if pub:
                try:
                    if not self.storage.get_session_key(mid):
                        shared = perform_key_exchange(
                            self.identity.private_key, bytes.fromhex(pub)
                        )
                        self._set_session_key_fs(mid, shared)
                except Exception:
                    pass
            if not self.storage.get_contact(mid):
                self.storage.add_contact(Contact(
                    device_id=mid, display_name=dname, public_key=pub or "",
                    created_at=time.time(), last_seen=time.time(),
                ))
            if not self.storage.get_session_key(mid):
                await self._send_hello(mid)
        self._groups[group_id] = {
            "name": info.get("name") or self._groups.get(group_id, {}).get("name", "Grup"),
            "members": ids,
            "invite_code": info.get("invite_code")
                or self._groups.get(group_id, {}).get("invite_code"),
            "creator_id": info.get("creator_id")
                or self._groups.get(group_id, {}).get("creator_id")
                or (ids[0] if ids else ""),
            "epoch": (self._groups.get(group_id) or {}).get("epoch", 0),
            "epoch_members": (self._groups.get(group_id) or {}).get("epoch_members", []),
        }
        self._persist_group(group_id)
        print(f"[Group] refreshed {group_id[:8]} members={len(ids)}")
        return previous_members != set(ids)

    async def _handle_group_text(self, from_id: str, payload: bytes):
        """Decrypt pairwise FS2 transport and the shared group sender-key frame."""
        if len(payload) < 4:
            return
        glen = struct.unpack(">H", payload[:2])[0]
        if glen > 64 or len(payload) < 2 + glen:
            return
        gid = payload[2:2 + glen].decode("utf-8", errors="replace")
        enc = payload[2 + glen:]
        group = self._groups.get(gid)
        if not group:
            print(f"[Group] drop frame: unknown group={gid[:8]} sender={from_id[:8]}")
            return
        if from_id not in group.get("members", []):
            await self._refresh_group_members(gid)
            group = self._groups.get(gid) or {}
            if from_id not in group.get("members", []):
                print(f"[Group] drop frame: sender not member group={gid[:8]} sender={from_id[:8]}")
                return
        sk = self.storage.get_session_key(from_id)
        if not sk:
            c = self.storage.get_contact(from_id)
            if c and c.public_key:
                try:
                    sk = perform_key_exchange(
                        self.identity.private_key, bytes.fromhex(c.public_key)
                    )
                    self._set_session_key_fs(from_id, sk)
                except Exception:
                    pass
        if not sk:
            print(f"[Group] no FS2 key group={gid[:8]} sender={from_id[:8]}")
            await self._send_hello(from_id)
            return
        try:
            frame = self._decrypt_direct(from_id, enc, sk)
            if not GroupSenderKeyChain.is_frame(frame):
                raise ValueError("invalid GSK1 group frame")
            epoch = struct.unpack(">Q", frame[4:12])[0]
        except Exception as e:
            print(f"[Group] transport decrypt: {e}")
            return
        secret = self.storage.load_group_crypto_state(f"gk|{gid}|{epoch}")
        if secret is None:
            self.storage.add_pending_group_inbox(gid, from_id, epoch, frame)
            print(
                f"[Group] waiting for epoch key group={gid[:8]} epoch={epoch} "
                f"sender={from_id[:8]}"
            )
            await self._request_group_epoch(gid)
            return
        try:
            event = self._decrypt_group_sender_frame(gid, from_id, epoch, frame, secret)
        except Exception as e:
            print(f"[Group] GSK decrypt failed group={gid[:8]} epoch={epoch} sender={from_id[:8]}: {e}")
            return
        if event is not None:
            self._dispatch_group_event(gid, from_id, event)

    def _decrypt_group_sender_frame(self, gid, from_id, epoch, frame, secret):
        state_key = f"gs|{gid}|{epoch}|{from_id}"
        raw_state = self.storage.load_group_crypto_state(state_key)
        chain = (GroupSenderKeyChain.import_state(secret, raw_state)
                 if raw_state else GroupSenderKeyChain(secret, gid, epoch, from_id))
        event = json.loads(chain.decrypt(frame).decode("utf-8"))
        self.storage.save_group_crypto_state(state_key, chain.export_state())
        return event

    def _dispatch_group_event(self, gid, from_id, event):
        c = self.storage.get_contact(from_id)
        sender_name = c.display_name if c else f"Peer-{from_id[:8]}"
        kind = event.get("kind")
        if kind == "text":
            display = f"{sender_name}: {event['text']}"
            self.storage.save_message(Message(
                id=None, contact_id=f"group:{gid}", direction="in", msg_type="text",
                content=display, timestamp=time.time(), status="delivered",
            ))
            if self.current_group_id == gid:
                self.main_window.after(0, lambda d=display: self.main_window.add_message_bubble(d, False))
            print(f"[Group] received text group={gid[:8]} sender={from_id[:8]}")
        elif kind == "file_start":
            try:
                self._group_file_start(gid, from_id, event)
            except Exception as exc:
                print(f"[Group] file start rejected: {exc}")
        elif kind == "file_chunk":
            try:
                self._group_file_chunk(gid, from_id, event)
            except Exception as exc:
                print(f"[Group] file chunk rejected: {exc}")
        elif kind == "file_end":
            try:
                self._group_file_end(gid, from_id, event)
            except Exception as exc:
                print(f"[Group] file completion rejected: {exc}")
        else:
            print(f"[Group] unsupported event kind: {kind}")

    def _flush_pending_group_inbox(self, gid, epoch):
        secret = self.storage.load_group_crypto_state(f"gk|{gid}|{epoch}")
        if secret is None:
            return
        for item in self.storage.get_pending_group_inbox(gid):
            if item["epoch"] != epoch:
                continue
            try:
                event = self._decrypt_group_sender_frame(
                    gid, item["sender_id"], epoch, item["payload"], secret
                )
                self._dispatch_group_event(gid, item["sender_id"], event)
            except Exception as exc:
                print(f"[Group] queued frame rejected: {exc}")
            finally:
                self.storage.delete_pending_group_inbox(item["id"])

    def _group_file_start(self, gid, from_id, event):
        tid = event["transfer_id"]
        filename = Path(event["filename"]).name
        size, total = int(event["file_size"]), int(event["total_chunks"])
        if not filename or not 0 < size <= MAX_FILE_SIZE:
            raise ValueError("invalid group file metadata")
        if total != math.ceil(size / GROUP_FILE_CHUNK_SIZE) or tid in self._incoming_files:
            raise ValueError("invalid group file chunk count or duplicate transfer")
        self._incoming_files[tid] = {
            "filename": filename, "total": total, "size": size, "chunks": {},
            "device_id": from_id, "group_id": gid,
        }

    def _group_file_chunk(self, gid, from_id, event):
        state = self._incoming_files.get(event["transfer_id"])
        if not state or state.get("group_id") != gid or state["device_id"] != from_id:
            return
        index = int(event["chunk_index"])
        if not 0 <= index < state["total"]:
            raise ValueError("group file chunk index out of range")
        chunk = base64.b64decode(event["data"], validate=True)
        expected = min(GROUP_FILE_CHUNK_SIZE, state["size"] - index * GROUP_FILE_CHUNK_SIZE)
        if len(chunk) != expected:
            raise ValueError("group file chunk has invalid size")
        state["chunks"][index] = chunk

    def _group_file_end(self, gid, from_id, event):
        state = self._incoming_files.get(event["transfer_id"])
        if (not state or state.get("group_id") != gid or state["device_id"] != from_id
                or len(state["chunks"]) != state["total"]):
            return
        data = b"".join(state["chunks"][i] for i in range(state["total"]))
        if len(data) != state["size"]:
            raise ValueError("group file size mismatch")
        self._incoming_files.pop(event["transfer_id"], None)
        name = state["filename"]
        master_key = self.identity.get_master_key()
        dest = save_encrypted_file(self.files_dir, master_key, name, data)
        self.storage.save_message(Message(
            id=None, contact_id=f"group:{gid}", direction="in", msg_type="file",
            content=f"{name}|{dest}", timestamp=time.time(), status="delivered",
        ))
        if self.current_group_id == gid:
            is_img = Path(name).suffix.lower() in IMAGE_EXTENSIONS
            temp = export_to_temp(dest, master_key, self.temp_dir)
            self.main_window.after(0, lambda: self.main_window.add_file_bubble(
                name, str(temp), False, is_img
            ))


    async def _send_direct_message(self, text: str):
        """1:1 ca la grup: HELLO dacă trebuie, apoi RELAY (stabil pe Tor)."""
        cid = self.current_contact_id
        if not cid:
            return
        if not self.signaling or not self.signaling.connected:
            self.storage.add_pending(cid, text.encode("utf-8"))
            self.storage.save_message(Message(
                id=None, contact_id=cid, direction="out", msg_type="text",
                content=text, timestamp=time.time(), status="queued",
            ))
            if self.main_window:
                self.main_window.after(0, lambda: self.main_window.add_message_bubble(text, True))
                self.main_window.after(0, lambda: self.main_window.show_info(
                    "Offline – mesaj în coadă"
                ))
            return

        sk = self.storage.get_session_key(cid)
        if not sk:
            await self._send_hello(cid)
            await asyncio.sleep(0.5)
            sk = self.storage.get_session_key(cid)
        if not sk:
            # încă o dată – ca la grup
            await self._send_hello(cid)
            await asyncio.sleep(0.6)
            sk = self.storage.get_session_key(cid)
        if not sk:
            self.storage.add_pending(cid, text.encode("utf-8"))
            self.storage.save_message(Message(
                id=None, contact_id=cid, direction="out", msg_type="text",
                content=text, timestamp=time.time(), status="queued",
            ))
            if self.main_window:
                self.main_window.after(0, lambda: self.main_window.add_message_bubble(text, True))
                self.main_window.after(0, lambda: self.main_window.show_info(
                    "Se stabilește canalul (HELLO)… mesajul e în coadă"
                ))
            return

        try:
            blob = self._encrypt_direct(cid, text.encode("utf-8"), sk)
        except Exception as e:
            if self.main_window:
                self.main_window.after(0, lambda: self.main_window.show_info(f"Eroare criptare: {e}"))
            return

        self.storage.save_message(Message(
            id=None, contact_id=cid, direction="out", msg_type="text",
            content=text, timestamp=time.time(), status="sent",
        ))
        if self.main_window:
            self.main_window.after(0, lambda: self.main_window.add_message_bubble(text, True))

        # RELAY first (ca grupul) – pe Tor e calea stabilă
        ok = False
        for attempt in range(3):
            try:
                ok = await self.signaling.relay_send(cid, bytes([MSG_TEXT]) + blob)
                if ok:
                    break
            except Exception as e:
                print(f"[App] relay_send 1:1 try {attempt}: {e}")
            await asyncio.sleep(0.4 * (attempt + 1))

        if ok:
            print(f"[App] 1:1 relay OK → {cid[:12]}")
        else:
            print("[App] 1:1 relay FAILED – coadă")
            self.storage.add_pending(cid, text.encode("utf-8"))
            if self.signaling:
                self.signaling.connected = False
            if self.main_window:
                self.main_window.after(0, lambda: self.main_window.show_info(
                    "Relay eșuat – reconectare…"
                ))

        # P2P opțional (bonus), fără a înlocui relay-ul deja trimis
        conn = self.network.connections.get(cid)
        if conn:
            try:
                await self.network.send_message(conn, MSG_TEXT, blob)
            except Exception as e:
                print(f"[App] p2p bonus fail: {e}")

    async def _send_group_message(self, text: str, group_id=None):
        gid = group_id or self.current_group_id
        if not gid:
            return
        membership_changed = await self._refresh_group_members(gid)
        g = self._groups.get(gid) or {}
        members = [m for m in g.get("members", []) if m != self.identity.device_id]
        if not members:
            self.main_window.after(0, lambda: self.main_window.show_info(
                "Niciun alt membru în grup încă – dă codul de invitație"
            ))
            return
        secret = self._refresh_group_epoch(gid, membership_changed)
        if secret is None:
            pending = self._pending_group_texts.setdefault(gid, [])
            if len(pending) >= 100:
                self.main_window.after(0, lambda: self.main_window.show_info(
                    "Coada mesajelor de grup este plină; încearcă din nou mai târziu"
                ))
                return
            pending.append(text)
            await self._request_group_epoch(gid)
            self.main_window.after(0, lambda: self.main_window.show_info(
                "Se așteaptă cheia securizată a grupului; mesajul va fi trimis după conectare"
            ))
            return
        if g.get("creator_id") == self.identity.device_id:
            await self._distribute_group_epoch(gid, secret)
        sent = await self._broadcast_group_event(gid, members, secret, {
            "kind": "text", "text": text,
        })
        self.storage.save_message(Message(
            id=None, contact_id=f"group:{gid}", direction="out", msg_type="text",
            content=text, timestamp=time.time(), status="sent" if sent else "failed",
        ))
        if sent:
            self.main_window.after(0, lambda: self.main_window.add_message_bubble(f"Tu: {text}", True))
        print(f"[Group] sent to {sent}/{len(members)} members")
        if not sent:
            self.main_window.after(0, lambda: self.main_window.show_info(
                "Nu am putut livra – așteaptă HELLO / pair pe relay"
            ))

    async def _flush_pending_group_texts(self, gid):
        pending = self._pending_group_texts.pop(gid, [])
        for index, text in enumerate(pending):
            try:
                await self._send_group_message(text, gid)
            except Exception as exc:
                print(f"[Group] pending text flush failed: {exc}")
                self._pending_group_texts.setdefault(gid, []).extend(pending[index:])
                return

    def _refresh_group_epoch(self, gid, membership_changed=False):
        group = self._groups.get(gid) or {}
        creator_id = group.get("creator_id")
        epoch = int(group.get("epoch", 0))
        if creator_id == self.identity.device_id:
            secret = self.storage.load_group_crypto_state(f"gk|{gid}|{epoch}") if epoch else None
            membership_changed = membership_changed or (
                set(group.get("members", [])) != set(group.get("epoch_members", []))
            )
            if epoch == 0 or membership_changed or secret is None:
                epoch += 1
                secret = os.urandom(32)
                self.storage.save_group_crypto_state(f"gk|{gid}|{epoch}", secret)
                group["epoch"] = epoch
                group["epoch_members"] = list(group.get("members", []))
                self._groups[gid] = group
                self._persist_group(gid)
            return secret
        if epoch == 0:
            return None
        return self.storage.load_group_crypto_state(f"gk|{gid}|{epoch}")

    def _persist_group(self, gid):
        group = self._groups.get(gid)
        if group is not None:
            self.storage.save_group(gid, group)

    async def _broadcast_group_event(self, gid, members, secret, event):
        lock = self._group_send_locks.setdefault(gid, asyncio.Lock())
        async with lock:
            return await self._broadcast_group_event_locked(gid, members, secret, event)

    async def _broadcast_group_event_locked(self, gid, members, secret, event):
        group = self._groups[gid]
        epoch = int(group["epoch"])
        local_id = self.identity.device_id
        state_key = f"gs|{gid}|{epoch}|{local_id}"
        raw = self.storage.load_group_crypto_state(state_key)
        chain = (GroupSenderKeyChain.import_state(secret, raw)
                 if raw else GroupSenderKeyChain(secret, gid, epoch, local_id))
        frame = chain.encrypt(json.dumps(event, separators=(",", ":")).encode("utf-8"))
        self.storage.save_group_crypto_state(state_key, chain.export_state())
        sent = 0
        for mid in members:
            try:
                frame_id = self.storage.add_pending_group_frame(gid, mid, frame)
                if not self.storage.get_session_key(mid):
                    await self._send_hello(mid)
                delivered_ids = await self._flush_pending_group_frames(mid)
                if frame_id in delivered_ids:
                    sent += 1
            except Exception as exc:
                print(f"[Group] send {mid[:8]}: {exc}")
        return sent

    async def _send_group_epoch(self, gid, member_id, secret, epoch=None):
        group = self._groups.get(gid) or {}
        sk = self.storage.get_session_key(member_id)
        if not sk or not self.signaling or not self.signaling.connected:
            return False
        packet = json.dumps({
            "kind": "epoch_key", "group_id": gid,
            "epoch": epoch if epoch is not None else group["epoch"],
            "creator_id": self.identity.device_id,
            "secret": base64.b64encode(secret).decode("ascii"),
        }, separators=(",", ":")).encode("utf-8")
        encrypted = self._encrypt_direct(member_id, packet, sk)
        sent = await self.signaling.relay_send(
            member_id, bytes([MSG_GROUP_META]) + encrypted
        )
        if sent:
            if not hasattr(self, "_group_epoch_sent"):
                self._group_epoch_sent = set()
            sent_epoch = int(epoch if epoch is not None else group["epoch"])
            self._group_epoch_sent.add((gid, sent_epoch, member_id))
        return sent

    async def _distribute_group_epoch(self, gid, secret):
        group = self._groups.get(gid) or {}
        for member_id in group.get("members", []):
            if member_id != self.identity.device_id:
                if not self.storage.get_session_key(member_id):
                    await self._send_hello(member_id)
                    print(
                        f"[Group] epoch {group.get('epoch')} waiting for FS2 "
                        f"session with {member_id[:8]}"
                    )
                    continue
                if not await self._send_group_epoch(gid, member_id, secret):
                    print(
                        f"[Group] epoch {group.get('epoch')} relay rejected "
                        f"for {member_id[:8]}"
                    )

    async def _request_group_epoch(self, gid):
        group = self._groups.get(gid) or {}
        creator = group.get("creator_id")
        if not creator or creator == self.identity.device_id:
            return
        if not hasattr(self, "_group_epoch_retry_tasks"):
            self._group_epoch_retry_tasks = {}
        task = self._group_epoch_retry_tasks.get(gid)
        if task is None or task.done():
            self._group_epoch_retry_tasks[gid] = asyncio.create_task(
                self._retry_group_epoch_request(gid)
            )
        if not hasattr(self, "_group_epoch_request_at"):
            self._group_epoch_request_at = {}
        now = time.monotonic()
        if now - self._group_epoch_request_at.get(gid, 0) < 3.0:
            return
        sk = self.storage.get_session_key(creator)
        if not sk:
            await self._send_hello(creator)
            return
        if not self.signaling or not self.signaling.connected:
            return
        packet = json.dumps({
            "kind": "key_request", "group_id": gid,
            "requester_id": self.identity.device_id,
        }, separators=(",", ":")).encode("utf-8")
        encrypted = self._encrypt_direct(creator, packet, sk)
        if await self.signaling.relay_send(
            creator, bytes([MSG_GROUP_META]) + encrypted
        ):
            self._group_epoch_request_at[gid] = time.monotonic()
        else:
            print(f"[Group] key request relay rejected group={gid[:8]}")

    async def _retry_group_epoch_request(self, gid):
        delay = 3.0
        try:
            while True:
                group = self._groups.get(gid) or {}
                if not group or group.get("creator_id") == self.identity.device_id:
                    return
                epoch = int(group.get("epoch", 0))
                if epoch and self.storage.load_group_crypto_state(f"gk|{gid}|{epoch}"):
                    return
                await asyncio.sleep(delay)
                self._group_epoch_request_at.pop(gid, None)
                try:
                    await self._request_group_epoch(gid)
                except Exception as exc:
                    print(f"[Group] key request retry failed group={gid[:8]}: {exc}")
                delay = min(delay * 1.7, 30.0)
        finally:
            self._group_epoch_retry_tasks.pop(gid, None)

    async def _request_group_epochs_from_peer(self, peer_id):
        for gid, group in list(self._groups.items()):
            if group.get("creator_id") != peer_id:
                continue
            epoch = int(group.get("epoch", 0))
            if not epoch or self.storage.load_group_crypto_state(f"gk|{gid}|{epoch}") is None:
                await self._request_group_epoch(gid)

    async def _sync_creator_group_keys_to_peer(self, peer_id):
        if not peer_id or not self.signaling or not self.signaling.connected:
            return
        if not hasattr(self, "_group_epoch_sent"):
            self._group_epoch_sent = set()
        for gid, group in list(self._groups.items()):
            if group.get("creator_id") != self.identity.device_id:
                continue
            try:
                membership_changed = await self._refresh_group_members(gid)
                group = self._groups.get(gid) or {}
                members = group.get("members", [])
                if peer_id not in members:
                    continue
                secret = self._refresh_group_epoch(gid, membership_changed)
                if secret is None:
                    continue
                targets = members if membership_changed else [peer_id]
                for member_id in targets:
                    if member_id == self.identity.device_id:
                        continue
                    epoch_key = (gid, int(group.get("epoch", 0)), member_id)
                    if epoch_key in self._group_epoch_sent:
                        continue
                    if not self.storage.get_session_key(member_id):
                        await self._send_hello(member_id)
                        continue
                    if not await self._send_group_epoch(gid, member_id, secret):
                        print(
                            f"[Group] epoch {group['epoch']} not delivered yet "
                            f"to {member_id[:8]}"
                        )
            except Exception as exc:
                print(f"[Group] key sync {gid[:8]}: {exc}")

    async def _handle_group_meta(self, from_id, payload):
        sk = self.storage.get_session_key(from_id)
        if not sk:
            for gid, group in list(self._groups.items()):
                if group.get("creator_id") == self.identity.device_id:
                    try:
                        await self._refresh_group_members(gid)
                    except Exception as exc:
                        print(f"[Group] member refresh before key request {gid[:8]}: {exc}")
                    sk = self.storage.get_session_key(from_id)
                    if sk:
                        break
            if not sk:
                await self._send_hello(from_id)
                return
        try:
            event = json.loads(self._decrypt_direct(from_id, payload, sk).decode("utf-8"))
            gid = event["group_id"]
            group = self._groups.get(gid)
            if not group:
                print(f"[Group] metadata for unknown group={gid[:8]}")
                return
            print(
                f"[Group] metadata kind={event.get('kind')} group={gid[:8]} "
                f"sender={from_id[:8]}"
            )
            if event["kind"] == "key_request":
                if (group.get("creator_id") != self.identity.device_id
                        or event.get("requester_id") != from_id):
                    return
                membership_changed = await self._refresh_group_members(gid)
                group = self._groups.get(gid) or {}
                if from_id not in group.get("members", []):
                    return
                secret = self._refresh_group_epoch(gid, membership_changed)
                if secret:
                    await self._distribute_group_epoch(gid, secret)
            elif event["kind"] == "epoch_key":
                if from_id != group.get("creator_id") or event.get("creator_id") != from_id:
                    return
                epoch = int(event["epoch"])
                if epoch < int(group.get("epoch", 0)):
                    return
                secret = base64.b64decode(event["secret"], validate=True)
                if len(secret) != 32:
                    raise ValueError("invalid group epoch secret")
                existing = self.storage.load_group_crypto_state(f"gk|{gid}|{epoch}")
                if epoch == int(group.get("epoch", 0)) and existing is not None:
                    if secret != existing:
                        raise ValueError("conflicting group epoch secret")
                    self._group_epoch_request_at.pop(gid, None)
                    self._flush_pending_group_inbox(gid, epoch)
                    await self._flush_pending_group_texts(gid)
                    return
                self.storage.save_group_crypto_state(f"gk|{gid}|{epoch}", secret)
                group["epoch"] = epoch
                self._persist_group(gid)
                self._group_epoch_request_at.pop(gid, None)
                self._flush_pending_group_inbox(gid, epoch)
                await self._flush_pending_group_texts(gid)
            elif event["kind"] == "treekem_commit":
                frame = base64.b64decode(event["commit_frame"])
                tk_state_key = f"treekem|{gid}"
                raw_tk = self.storage.load_group_crypto_state(tk_state_key)
                if raw_tk:
                    tk_group = TreeKEMGroup.import_state(raw_tk)
                else:
                    members = group.get("members", [])
                    tk_group = TreeKEMGroup(gid, int(group.get("epoch", 0)), self.identity.device_id, members)
                    for idx, mid in enumerate(tk_group.roster):
                        c = self.storage.get_contact(mid)
                        pub = bytes.fromhex(c.public_key) if c and c.public_key else None
                        if pub:
                            priv = self.identity.private_key if mid == self.identity.device_id else None
                            tk_group.set_leaf_keypair(idx, priv, pub)
                secret = tk_group.process_commit(frame)
                if secret and len(secret) == 32:
                    epoch = tk_group.epoch
                    self.storage.save_group_crypto_state(f"gk|{gid}|{epoch}", secret)
                    self.storage.save_group_crypto_state(tk_state_key, tk_group.export_state())
                    group["epoch"] = epoch
                    self._persist_group(gid)
                    self._group_epoch_request_at.pop(gid, None)
                    self._flush_pending_group_inbox(gid, epoch)
                    await self._flush_pending_group_texts(gid)
            else:
                raise ValueError("unknown group metadata type")
        except Exception as exc:
            print(f"[Group] metadata rejected: {exc}")


    def _on_clear_chat(self):
        """Șterge doar mesajele conversației curente (contact sau grup)."""
        if self.current_group_id:
            cid = f"group:{self.current_group_id}"
        elif self.current_contact_id:
            cid = self.current_contact_id
        else:
            if self.main_window:
                self.main_window.show_info("Selectează un chat")
            return
        n = self.storage.delete_messages(cid)
        if self.main_window:
            self.main_window.clear_messages()
            self.main_window.show_info(f"Conversație ștearsă ({n} mesaje)")

    def _on_delete_contact(self):
        """Șterge contactul + conversația (sau părăsește grupul local)."""
        if self.current_group_id:
            gid = self.current_group_id
            self.storage.delete_messages(f"group:{gid}")
            self.storage.delete_group_crypto_state(gid)
            self.storage.delete_group(gid)
            self._groups.pop(gid, None)
            self.current_group_id = None
            if self.main_window:
                self.main_window.clear_messages()
                self.main_window.set_chat_title("Selectează un contact", online=False)
                self.main_window.clear_contacts_list()
                for c in self.storage.get_contacts():
                    self.main_window.add_contact_to_list(
                        c.display_name, c.device_id,
                        command=lambda cid=c.device_id: self._select_contact(cid)
                    )
                for g_id, g in self._groups.items():
                    self.main_window.add_group_to_list(
                        g.get("name") or "Grup", g_id,
                        command=lambda x=g_id: self._select_group(x)
                    )
                self.main_window.show_info("Grup eliminat local")
            return
        if not self.current_contact_id:
            if self.main_window:
                self.main_window.show_info("Selectează un contact")
            return
        did = self.current_contact_id
        # închide P2P + curăță buffer-e locale
        try:
            conn = self.network.connections.pop(did, None)
            if conn and self.loop:
                asyncio.run_coroutine_threadsafe(self.network._close_conn(conn), self.loop)
        except Exception:
            pass
        try:
            self._pending_relay_inbox.pop(did, None)
        except Exception:
            pass
        try:
            self._fs_chains.pop(did, None)
        except Exception:
            pass
        try:
            self._exchanged.discard(did)
        except Exception:
            pass
        # delete_contact → DB + session + pending + deleted_peers (definitiv până la add/pair manual)
        self.storage.delete_contact(did)
        try:
            # dublu: asigură intrarea în deleted_peers
            if hasattr(self.storage, "is_deleted_peer") and not self.storage.is_deleted_peer(did):
                self.storage.delete_contact(did)
        except Exception:
            pass
        self.current_contact_id = None
        if self.main_window:
            self.main_window.clear_messages()
            self.main_window.set_chat_title("Selectează un contact", online=False)
            self.main_window.clear_contacts_list()
            for c in self.storage.get_contacts():
                self.main_window.add_contact_to_list(
                    c.display_name, c.device_id,
                    command=lambda cid=c.device_id: self._select_contact(cid)
                )
            self.main_window.show_info(
                "Contact șters definitiv – reapare doar dacă îl adaugi / pair din nou"
            )

    def _on_logout(self):
        self._cancel_voice_recording()
        self._shutdown_network()
        try:
            for f in self.temp_dir.glob("*"):
                f.unlink(missing_ok=True)
        except Exception:
            pass
        if self.storage:
            self.storage.clear_session_keys()
        self.identity.lock()
        self._exchanged.clear()
        try:
            self.main_window.destroy()
        except Exception:
            pass
        self.storage = self.main_window = self.current_contact_id = None
        self.run()

    def _on_close(self):
        self._cancel_voice_recording()
        self._shutdown_network()
        try:
            for f in self.temp_dir.glob("*"):
                f.unlink(missing_ok=True)
        except Exception:
            pass
        if self.storage:
            self.storage.clear_session_keys()
        self.identity.lock()
        try:
            self.main_window.destroy()
        except Exception:
            pass

    def _shutdown_network(self):
        try:
            if self.loop:
                async def cleanup():
                    if self._p2p_maintenance_task:
                        self._p2p_maintenance_task.cancel()
                    if self.signaling:
                        try:
                            await self.signaling.unregister(self.identity.device_id)
                        except Exception:
                            pass
                        await self.signaling.close()
                    await self.network.stop()
                fut = asyncio.run_coroutine_threadsafe(cleanup(), self.loop)
                try:
                    fut.result(timeout=5)
                except Exception:
                    pass
                self.loop.call_soon_threadsafe(self.loop.stop)
        except Exception:
            pass


def main():
    SecureChatApp().run()


if __name__ == "__main__":
    main()
