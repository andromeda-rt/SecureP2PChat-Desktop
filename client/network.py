# -*- coding: utf-8 -*-
"""P2P TCP + TLS 1.2/1.3 (cert self-signed per sesiune). Payload-ul rămâne E2EE."""
import asyncio
import ssl
import struct
import hashlib
from typing import Optional, Dict, List
from dataclasses import dataclass

from shared.protocol import pack_message, unpack_message, ProtocolError
from shared.constants import (
    DEFAULT_PORT, MSG_PING, MSG_PONG, MSG_KEY_EXCHANGE, MSG_TEXT, MSG_ACK,
    MSG_FILE_START, MSG_FILE_CHUNK, MSG_FILE_END, MSG_TYPING, MSG_DELIVERED, MSG_READ,
)


def _make_p2p_ssl_contexts():
    """Cert + cheie efemere în RAM; server + client (fără CA publică)."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"SecureP2PChat-P2P"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(minutes=5))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()

    import tempfile, os
    td = tempfile.mkdtemp(prefix="p2p_tls_")
    cert_path = os.path.join(td, "c.pem")
    key_path = os.path.join(td, "k.pem")
    open(cert_path, "wb").write(cert_pem)
    open(key_path, "wb").write(key_pem)

    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if hasattr(ssl, "TLSVersion"):
        server_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            server_ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        except Exception:
            pass
    try:
        server_ctx.load_cert_chain(cert_path, key_path)
    finally:
        try:
            os.remove(cert_path)
            os.remove(key_path)
            os.rmdir(td)
        except Exception:
            pass

    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if hasattr(ssl, "TLSVersion"):
        client_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            client_ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        except Exception:
            pass
    client_ctx.check_hostname = False
    client_ctx.verify_mode = ssl.CERT_NONE  # TOFU: E2EE + pair deja autentifică peer-ul

    return server_ctx, client_ctx, fp


@dataclass
class PeerConnection:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    device_id: Optional[str] = None
    session_key: Optional[bytes] = None
    display_name: Optional[str] = None
    tls: bool = False


class NetworkManager:
    def __init__(self, port: int = DEFAULT_PORT, use_tls: bool = True):
        self.port = port
        self.use_tls = use_tls
        self.servers: List[asyncio.AbstractServer] = []
        self.connections: Dict[str, PeerConnection] = {}
        self.on_message = None
        self.on_key_exchange = None
        self.on_file_start = None
        self.on_file_chunk = None
        self.on_file_end = None
        self.on_typing = None
        self.on_delivered = None
        self.on_read = None
        self.on_disconnect = None
        self._running = False
        self.upnp_ok = False
        self.upnp_message = ""
        self.external_ip = None
        self.tls_fingerprint = None
        self._server_ssl = None
        self._client_ssl = None
        if use_tls:
            try:
                self._server_ssl, self._client_ssl, self.tls_fingerprint = _make_p2p_ssl_contexts()
                print(f"[Network] P2P TLS activ fp={self.tls_fingerprint[:16]}…")
            except Exception as e:
                # Fail closed: nu transforma o eroare TLS într-un listener TCP necriptat.
                self._server_ssl = None
                self._client_ssl = None
                self.tls_fingerprint = None
                print(f"[SECURITY] P2P TLS initialization failed; secure networking disabled: {e}")

    async def start_server(self):
        self._running = True
        started = []
        self.upnp_ok = False
        self.upnp_message = "UPnP disabled (security policy)"
        self.external_ip = None
        if self.use_tls and self._server_ssl is None:
            self._running = False
            raise RuntimeError("P2P TLS este activ, dar contextul TLS nu a putut fi inițializat; refuz TCP necriptat")
        ssl_ctx = self._server_ssl if self.use_tls else None
        mode = "TLS" if ssl_ctx else "TCP (configurat explicit fără TLS)"
        print(f"[Network] Ascult P2P ({mode}) – fără UPnP")
        def _sock_opts(sock):
            try:
                import socket
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                if hasattr(socket, "TCP_KEEPIDLE"):
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
                if hasattr(socket, "TCP_NODELAY"):
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass

        try:
            srv = await asyncio.start_server(
                self._handle_client, "0.0.0.0", self.port, ssl=ssl_ctx, reuse_address=True
            )
            for s in srv.sockets or []:
                _sock_opts(s)
            self.servers.append(srv)
            started.append(f"IPv4:{self.port}/{mode}")
        except Exception as e:
            print(f"[Network] IPv4: {e}")
        try:
            srv = await asyncio.start_server(
                self._handle_client, "::", self.port, ssl=ssl_ctx, reuse_address=True
            )
            for s in srv.sockets or []:
                _sock_opts(s)
            self.servers.append(srv)
            started.append(f"IPv6:{self.port}/{mode}")
        except Exception as e:
            print(f"[Network] IPv6: {e}")
        print(f"[Network] Ascult: {', '.join(started) or 'NIMIC'}")

    async def stop(self):
        self._running = False
        for srv in self.servers:
            srv.close()
            await srv.wait_closed()
        self.servers.clear()
        for conn in list(self.connections.values()):
            try:
                await self._close_conn(conn)
            except Exception:
                pass
        self.connections.clear()

    async def connect_to_peer(self, host: str, port: int) -> Optional[PeerConnection]:
        """Conectare P2P. Nu face downgrade TLS automat.

        TCP simplu este permis numai dacă use_tls=False a fost configurat explicit.
        """
        if self.use_tls:
            if self._client_ssl is None:
                print("[SECURITY] P2P TLS solicitat, dar contextul TLS lipsește; conexiune refuzată")
                return None
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        host, port, ssl=self._client_ssl,
                        server_hostname="SecureP2PChat-P2P",
                    ),
                    timeout=15.0,
                )
                conn = PeerConnection(reader=reader, writer=writer, tls=True)
                asyncio.create_task(self._read_loop(conn))
                print(f"[Network] P2P TLS → {host}:{port}")
                return conn
            except Exception as e:
                print(f"[Network] P2P TLS failed {host}:{port}: {e}; plaintext fallback disabled")
                return None

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=15.0
            )
            conn = PeerConnection(reader=reader, writer=writer, tls=False)
            asyncio.create_task(self._read_loop(conn))
            print(f"[Network] P2P TCP explicit → {host}:{port}")
            return conn
        except Exception as e:
            print(f"[Network] connect fail {host}:{port}: {e}")
            return None

    async def send_message(self, conn: PeerConnection, msg_type: int, payload: bytes = b""):
        data = pack_message(msg_type, payload)
        conn.writer.write(data)
        await conn.writer.drain()

    async def _handle_client(self, reader, writer):
        sslobj = writer.get_extra_info("ssl_object")
        tls = sslobj is not None
        conn = PeerConnection(reader=reader, writer=writer, tls=tls)
        print(f"[Network] inbound {'TLS' if tls else 'plain'} de la {writer.get_extra_info('peername')}")
        asyncio.create_task(self._read_loop(conn))

    async def _read_loop(self, conn: PeerConnection):
        try:
            while self._running:
                header = await conn.reader.readexactly(4)
                length = struct.unpack(">I", header)[0]
                if length < 1 or length > 20 * 1024 * 1024:
                    break
                body = await conn.reader.readexactly(length)
                try:
                    msg_type, payload = unpack_message(header + body)
                except ProtocolError:
                    continue
                if msg_type == MSG_PING:
                    await self.send_message(conn, MSG_PONG)
                elif msg_type == MSG_KEY_EXCHANGE and self.on_key_exchange:
                    await self.on_key_exchange(conn, payload)
                elif msg_type == MSG_TEXT and self.on_message and conn.device_id:
                    await self.on_message(conn, msg_type, payload)
                elif msg_type == MSG_FILE_START and self.on_file_start and conn.device_id:
                    await self.on_file_start(conn, payload)
                elif msg_type == MSG_FILE_CHUNK and self.on_file_chunk and conn.device_id:
                    await self.on_file_chunk(conn, payload)
                elif msg_type == MSG_FILE_END and self.on_file_end and conn.device_id:
                    await self.on_file_end(conn, payload)
                elif msg_type == MSG_TYPING and self.on_typing and conn.device_id:
                    await self.on_typing(conn.device_id)
                elif msg_type == MSG_DELIVERED and self.on_delivered and conn.device_id:
                    await self.on_delivered(conn.device_id, payload)
                elif msg_type == MSG_READ and self.on_read and conn.device_id:
                    await self.on_read(conn.device_id, payload)
        except asyncio.IncompleteReadError:
            pass
        except Exception as e:
            print(f"[Network] read: {e}")
        finally:
            await self._close_conn(conn)

    async def _close_conn(self, conn: PeerConnection):
        try:
            conn.writer.close()
            await conn.writer.wait_closed()
        except Exception:
            pass
        if conn.device_id and conn.device_id in self.connections:
            del self.connections[conn.device_id]
            if self.on_disconnect:
                try:
                    await self.on_disconnect(conn.device_id)
                except Exception:
                    pass
