# -*- coding: utf-8 -*-
"""Client semnalizare: pair codes + relay criptat"""

import asyncio
import json
import time
import base64
import hashlib
import secrets
from typing import Optional, Dict, Any, List
from pathlib import Path


class SignalingClient:
    def __init__(self, host: str, port: int, use_tls: bool = True, ca_file: str = None,
                 insecure_skip_verify: bool = False,
                 socks_host: str = None, socks_port: int = None,
                 proxy_pool=None, pin_file=None):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.ca_file = ca_file
        self.insecure_skip_verify = insecure_skip_verify
        self.socks_host = socks_host  # Tor explicit
        self.socks_port = socks_port
        self.proxy_pool = proxy_pool  # ProxyPool opțional (clearnet)
        self.pin_file = Path(pin_file) if pin_file else None
        self.reader = None
        self.writer = None
        self.connected = False
        self.last_error = ""
        self._lock = asyncio.Lock()
        self._signing_key = None
        self._verify_key_hex = None
        self._device_id = None
        self._public_key_hex = None
        self._display_name = None
        self._session_token = None
        self.last_cert_fp = None  # SHA256 hex al certificatului TLS

    def set_identity(self, device_id: str, signing_key, verify_key_bytes: bytes,
                     public_key_hex: str = "", display_name: str = ""):
        self._device_id = device_id
        self._signing_key = signing_key
        self._verify_key_hex = verify_key_bytes.hex() if verify_key_bytes else None
        self._public_key_hex = public_key_hex
        self._display_name = display_name

    def _load_pin(self) -> Optional[str]:
        if not self.pin_file or not self.pin_file.is_file():
            return None
        try:
            return self.pin_file.read_text(encoding="utf-8").strip().lower()
        except OSError:
            return None

    def _save_pin(self, fp: str) -> None:
        if not self.pin_file or not fp:
            return
        try:
            self.pin_file.parent.mkdir(parents=True, exist_ok=True)
            self.pin_file.write_text(fp.lower() + chr(10), encoding="utf-8")
            try:
                self.pin_file.chmod(0o600)
            except OSError:
                pass
        except OSError as e:
            print(f"[Signal] pin save: {e}")

    def _cert_fingerprint(self, der: bytes) -> str:
        return hashlib.sha256(der).hexdigest().lower()

    def verify_or_pin_peer_cert(self) -> bool:
        """TOFU pinning: prima conexiune salveaza amprenta; apoi trebuie sa coincida."""
        if not self.use_tls or not self.writer:
            return True
        try:
            sslobj = self.writer.get_extra_info("ssl_object")
            if sslobj is None:
                print("[SECURITY] TLS solicitat, dar conexiunea nu are obiect SSL")
                return False
            der = sslobj.getpeercert(binary_form=True)
            if not der:
                print("[Signal] TLS fara certificat peer")
                return False
            fp = self._cert_fingerprint(der)
            self.last_cert_fp = fp
            pinned = self._load_pin()
            if not pinned:
                self._save_pin(fp)
                print(f"[Signal] TLS pin TOFU salvat: {fp[:16]}...")
                return True
            if pinned == fp:
                return True
            print(f"[SECURITY] TLS PIN MISMATCH! asteptat {pinned[:16]}... primit {fp[:16]}...")
            print("[SECURITY] Posibil MITM sau certificat schimbat pe server.")
            return False
        except Exception as e:
            print(f"[Signal] pin check: {e}")
            return False

    def _build_client_ssl(self):
        if not self.use_tls:
            return None
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if hasattr(ssl, "TLSVersion"):
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            try:
                ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            except Exception:
                pass
        if self.insecure_skip_verify:
            # doar pentru test cu self-signed; NU pentru producție publică
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            if self.ca_file:
                ctx.load_verify_locations(cafile=self.ca_file)
            else:
                ctx.load_default_certs()
        return ctx

    async def _open_via_socks(self, scheme: str, phost: str, pport: int, ssl_ctx, is_onion: bool):
        from python_socks.async_.asyncio import Proxy
        proxy = Proxy.from_url(f"{scheme}://{phost}:{pport}")
        timeout = 60.0 if is_onion else 20.0
        sock = await asyncio.wait_for(
            proxy.connect(dest_host=self.host, dest_port=self.port),
            timeout=timeout,
        )
        if ssl_ctx:
            # .onion: SNI = hostname onion; cert self-signed -> CERT_NONE / insecure
            sni = self.host if self.host else "localhost"
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(
                    sock=sock, ssl=ssl_ctx,
                    server_hostname=sni,
                    limit=1024 * 1024,
                ),
                timeout=60.0 if is_onion else 20.0,
            )
        else:
            self.reader, self.writer = await asyncio.open_connection(sock=sock, limit=1024 * 1024)

    async def connect(self) -> bool:
        """Conectează folosind exclusiv transportul configurat; nu face downgrade TLS.

        Pentru servicii .onion fără TLS, utilizatorul trebuie să dezactiveze TLS
        explicit în configurație. Eșecul TLS nu autorizează trecerea automată la TCP.
        """
        is_onion = str(self.host).lower().endswith(".onion")

        if is_onion and not (self.socks_host and self.socks_port):
            self.socks_host = self.socks_host or "127.0.0.1"
            self.socks_port = self.socks_port or 9150

        try:
            from python_socks.async_.asyncio import Proxy  # noqa: F401
            has_socks = True
        except ImportError:
            has_socks = False

        if is_onion and not (self.socks_host and self.socks_port):
            print("[Signal] .onion necesită Tor SOCKS (9150 Tor Browser sau 9050 tor)")
            self.connected = False
            self.last_error = "lipsă SOCKS 9150"
            return False
        # Transportul este strict cel configurat. Nici .onion nu autorizează
        # downgrade automat TLS -> TCP; dezactivarea TLS trebuie să fie explicită.
        tls_modes = [bool(self.use_tls)]
        if not tls_modes[0] and self.host not in ("localhost", "127.0.0.1", "::1"):
            print("[SECURITY] Semnalizare TCP fără TLS configurată explicit.")
        saved_tls = self.use_tls
        last_err = None
        for use_tls_try in tls_modes:
            self.use_tls = use_tls_try
            ssl_ctx = self._build_client_ssl() if use_tls_try else None
            try:
                mode = "TCP"
                if self.socks_host and self.socks_port:
                    if not has_socks:
                        print("[Signal] Lipseste python-socks: pip install \"python-socks[asyncio]\"")
                        last_err = "no-python-socks"
                        self.last_error = "pip install python-socks[asyncio]"
                        continue
                    await self._open_via_socks(
                        "socks5", self.socks_host, int(self.socks_port), ssl_ctx, is_onion
                    )
                    mode = f"SOCKS5 {self.socks_host}:{self.socks_port}"
                elif self.proxy_pool and not self.proxy_pool.empty() and not is_onion:
                    if not has_socks:
                        last_err = "no-python-socks"
                        self.last_error = "pip install python-socks[asyncio]"
                        continue
                    ok_proxy = False
                    for attempt in range(min(3, max(1, len(self.proxy_pool.proxies)))):
                        entry = self.proxy_pool.pick(force_next=(attempt > 0))
                        if not entry:
                            break
                        try:
                            await self._open_via_socks(
                                entry.scheme, entry.host, entry.port, ssl_ctx, False
                            )
                            self.proxy_pool.mark_ok(entry)
                            mode = f"pool {entry.label()}"
                            ok_proxy = True
                            break
                        except Exception as e:
                            last_err = e
                            self.proxy_pool.mark_fail(entry)
                            self.reader = self.writer = None
                    if not ok_proxy:
                        continue
                else:
                    self.reader, self.writer = await asyncio.wait_for(
                        asyncio.open_connection(
                            self.host, self.port, limit=1024 * 1024, ssl=ssl_ctx,
                            server_hostname=self.host if ssl_ctx else None,
                        ),
                        timeout=20.0 if not is_onion else 60.0,
                    )
                    mode = "TLS" if ssl_ctx else "TCP"

                if not self.verify_or_pin_peer_cert():
                    await self.close()
                    last_err = "tls-pin-mismatch"
                    print("[Signal] pin TLS respins — verifică certificatul și schimbarea legitimă a cheii")
                    break

                self.connected = True
                tls_s = "TLS" if ssl_ctx else "plain"
                print(f"[Signal] conectat {self.host}:{self.port} ({mode}, {tls_s})")
                return True
            except Exception as e:
                last_err = e
                print(f"[Signal] attempt tls={use_tls_try} fail: {e}")
                try:
                    await self.close()
                except Exception:
                    pass
                self.reader = self.writer = None
                self.connected = False
                continue

        print(f"[Signal] offline {self.host}:{self.port} → {last_err}")
        self.connected = False
        try:
            self.use_tls = saved_tls
        except Exception:
            pass
        self.last_error = str(last_err or "connect failed")
        return False

    async def close(self):
        self.connected = False
        self._session_token = None
        if self.writer:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass
        self.reader = self.writer = None

    async def ensure_connected(self) -> bool:
        if self.connected and self.writer and self.reader:
            return True
        try:
            await self.close()
        except Exception:
            pass
        return await self.connect()

    async def _request(self, obj: dict) -> Optional[dict]:
        if self._session_token and "session_token" not in obj:
            obj = dict(obj)
            obj["session_token"] = self._session_token
        for attempt in range(4):
            if not self.connected or not self.writer:
                if not await self.ensure_connected():
                    await asyncio.sleep(0.5 * (attempt + 1))
                    continue
            async with self._lock:
                try:
                    self.writer.write((json.dumps(obj) + "\n").encode("utf-8"))
                    await self.writer.drain()
                    line = await asyncio.wait_for(self.reader.readline(), timeout=60.0)
                    if not line:
                        self.connected = False
                        self.reader = self.writer = None
                        continue
                    return json.loads(line.decode("utf-8").strip())
                except Exception as e:
                    print(f"[Signal] req attempt {attempt}: {e}")
                    self.connected = False
                    self.reader = self.writer = None
                    try:
                        await self.close()
                    except Exception:
                        pass
                    await asyncio.sleep(0.4 * (attempt + 1))
                    continue
        return None

    def _sign_register(self, ipv4, ipv6, port) -> dict:
        ts = int(time.time())
        canonical = (f"SecureP2PChat-register-v2|{self._device_id}|{ipv4 or ''}|{ipv6 or ''}|{port}|{ts}|"
                     f"{self._public_key_hex or ''}|{self._display_name or ''}").encode("utf-8")
        sig = self._signing_key.sign(canonical).signature.hex()
        return {
            "device_id": self._device_id,
            "ipv4": ipv4, "ipv6": ipv6, "port": port, "ts": ts,
            "verify_key": self._verify_key_hex,
            "signature": sig,
            "public_key": self._public_key_hex,
            "display_name": self._display_name,
        }

    async def register(self, device_id, ipv4, ipv6, port) -> bool:
        if not self._signing_key:
            return False
        body = self._sign_register(ipv4, ipv6, port)
        body["cmd"] = "register"
        resp = await self._request(body)
        if resp and resp.get("ok"):
            tok = resp.get("session_token")
            if tok:
                self._session_token = tok
                print(f"[Signal] session_token primit ({len(tok)} chars)")
            return True
        return False

    async def heartbeat(self, device_id, ipv4, ipv6, port) -> bool:
        if self._session_token:
            body = {
                "cmd": "heartbeat",
                "session_token": self._session_token,
                "device_id": self._device_id or device_id,
                "ipv4": ipv4, "ipv6": ipv6, "port": port,
            }
            # semnare opțională dacă avem chei (compat server vechi)
            if self._signing_key:
                try:
                    body.update(self._sign_register(ipv4, ipv6, port))
                    body["cmd"] = "heartbeat"
                    body["session_token"] = self._session_token
                except Exception:
                    pass
        else:
            if not self._signing_key:
                return False
            body = self._sign_register(ipv4, ipv6, port)
            body["cmd"] = "heartbeat"
        resp = await self._request(body)
        if resp and resp.get("ok"):
            tok = resp.get("session_token")
            if tok:
                self._session_token = tok
            return True
        return False

    async def lookup(self, device_id: str) -> Optional[Dict[str, Any]]:
        resp = await self._request({"cmd": "lookup", "device_id": device_id})
        return resp if resp and resp.get("ok") else None

    async def unregister(self, device_id: str) -> bool:
        body = {"cmd": "unregister"}
        body.update(self._signed_command("unregister"))
        resp = await self._request(body)
        return bool(resp and resp.get("ok"))

    async def pair_create(self) -> Optional[str]:
        """Returnează codul de 6 caractere. Token + semnătură + chei complete."""
        if not self._signing_key or not self._device_id:
            print("[Signal] pair_create: no identity")
            return None
        if not self._public_key_hex:
            print("[Signal] pair_create: missing public_key_hex")
            return None
        ts = int(time.time())
        can = f"{self._device_id}|pair_create|{ts}".encode()
        sig = self._signing_key.sign(can).signature.hex()
        body = {
            "cmd": "pair_create",
            "device_id": self._device_id,
            "verify_key": self._verify_key_hex,
            "signature": sig,
            "ts": ts,
            "public_key": self._public_key_hex or "",
            "display_name": (self._display_name or f"anon-{(self._device_id or '')[:6]}"),
        }
        if self._session_token:
            body["session_token"] = self._session_token
        resp = await self._request(body)
        if resp and resp.get("ok"):
            return resp.get("pair_code")
        print(f"[Signal] pair_create fail: {resp}")
        return None

    async def pair_status(self, code: str = "") -> Optional[Dict[str, Any]]:
        """Creator: a intrat cineva pe cod?"""
        body = {"cmd": "pair_status", "pair_code": (code or "").strip().upper()}
        if self._device_id:
            body["device_id"] = self._device_id
        if self._session_token:
            body["session_token"] = self._session_token
        resp = await self._request(body)
        return resp if resp and resp.get("ok") else None

    async def pair_join(self, code: str) -> Optional[Dict[str, Any]]:
        """Intră cu cod – trimite și cheile joinerului pentru notify creator."""
        if not self._device_id:
            return None
        body = {
            "cmd": "pair_join",
            "pair_code": (code or "").strip().upper(),
            "device_id": self._device_id,
            "public_key": self._public_key_hex or "",
            "verify_key": self._verify_key_hex or "",
            "display_name": self._display_name or "",
        }
        if self._session_token:
            body["session_token"] = self._session_token
        resp = await self._request(body)
        if resp and resp.get("ok"):
            return resp
        print(f"[Signal] pair_join fail: {resp}")
        return None

    def _signed_command(self, cmd: str, target: str = "", payload_b64: str = "") -> dict:
        if not self._signing_key or not self._device_id:
            return {}
        ts = int(time.time())
        nonce = secrets.token_hex(16)
        payload_hash = hashlib.sha256(payload_b64.encode("ascii")).hexdigest() if payload_b64 else "-"
        canonical = (f"SecureP2PChat-signal-v1|{cmd}|{self._device_id}|{target}|"
                     f"{payload_hash}|{ts}|{nonce}").encode("utf-8")
        return {"device_id": self._device_id, "ts": ts, "nonce": nonce,
                "signature": self._signing_key.sign(canonical).signature.hex()}

    async def relay_send(self, to_device_id: str, payload: bytes) -> bool:
        b64 = base64.b64encode(payload).decode("ascii")
        body = {"cmd": "relay_send", "to": to_device_id, "payload": b64}
        if self._session_token:
            # Auth cu session_token (fără device_id/semnătură pe fiecare send)
            body["session_token"] = self._session_token
        else:
            body.update(self._signed_command("relay_send", to_device_id, b64))
        resp = await self._request(body)
        return bool(resp and resp.get("ok"))

    async def relay_poll(self) -> List[Dict[str, Any]]:
        if self._session_token:
            body = {"cmd": "relay_poll", "session_token": self._session_token}
        else:
            body = {"cmd": "relay_poll"}
            body.update(self._signed_command("relay_poll"))
        resp = await self._request(body)
        if resp and resp.get("ok"):
            return resp.get("messages") or []
        # auth/token fail – None forțează reconnect în poll loop
        if resp is not None and not resp.get("ok"):
            err = (resp.get("error") or "")
            self.last_error = err or "relay_poll fail"
            if "auth" in err.lower() or "token" in err.lower() or err:
                self._session_token = None
            return None
        return None

    async def relay_ack(self, message_ids: List[str]) -> bool:
        ids = list(dict.fromkeys(mid for mid in message_ids if isinstance(mid, str) and mid))
        if not ids:
            return True
        resp = await self._request({"cmd": "relay_ack", "ids": ids})
        if not resp or not resp.get("ok"):
            error = (resp or {}).get("error") or "relay_ack failed"
            self.last_error = error
            print(f"[Signal] relay_ack failed: {error}")
            return False
        return True


    async def group_create(self, name: str):
        """Creează grup – aceeași schemă de semnătură ca pair_create."""
        if not self._signing_key or not self._device_id:
            print("[Signal] group_create: no identity")
            return None
        name = (name or "Grup").strip()[:64] or "Grup"
        ts = int(time.time())
        can = f"{self._device_id}|group_create|{ts}|{name}".encode("utf-8")
        sig = self._signing_key.sign(can).signature.hex()
        resp = await self._request({
            "cmd": "group_create",
            "device_id": self._device_id,
            "verify_key": self._verify_key_hex,
            "signature": sig,
            "ts": ts,
            "name": name,
            "public_key": self._public_key_hex or "",
            "display_name": self._display_name or "",
        })
        if resp and resp.get("ok"):
            return {
                "group_id": resp.get("group_id"),
                "invite_code": resp.get("invite_code"),
                "name": resp.get("name") or name,
            }
        print(f"[Signal] group_create fail: {resp}")
        return None

    async def group_join(self, code: str):
        if not self._signing_key or not self._device_id:
            print("[Signal] group_join: no identity")
            return None
        code = (code or "").strip().upper()
        ts = int(time.time())
        can = f"{self._device_id}|group_join|{ts}|{code}".encode("utf-8")
        sig = self._signing_key.sign(can).signature.hex()
        resp = await self._request({
            "cmd": "group_join",
            "device_id": self._device_id,
            "verify_key": self._verify_key_hex,
            "signature": sig,
            "ts": ts,
            "invite_code": code,
            "public_key": self._public_key_hex or "",
            "display_name": self._display_name or "",
        })
        if resp and resp.get("ok"):
            return resp
        print(f"[Signal] group_join fail: {resp}")
        return None

    async def group_info(self, group_id: str):
        if not self._signing_key or not self._device_id:
            return None
        gid = (group_id or "").strip()
        ts = int(time.time())
        can = f"{self._device_id}|group_info|{ts}|{gid}".encode("utf-8")
        sig = self._signing_key.sign(can).signature.hex()
        resp = await self._request({
            "cmd": "group_info",
            "device_id": self._device_id,
            "verify_key": self._verify_key_hex,
            "signature": sig,
            "ts": ts,
            "group_id": gid,
        })
        if resp and resp.get("ok"):
            return resp
        print(f"[Signal] group_info fail: {resp}")
        return None
