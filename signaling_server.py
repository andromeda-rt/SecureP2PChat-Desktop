# -*- coding: utf-8 -*-
"""
Server semnalizare + RELAY criptat (vede doar ciphertext).

Funcții:
  - register / heartbeat / lookup (cu Ed25519)
  - pair: creează/reclamă un cod scurt de împerechere
  - relay_send / relay_poll: coadă de mesaje criptate per destinatar

NU decriptează nimic. NU stochează pe disc (doar RAM, TTL).
"""

import asyncio
import json
import time
import secrets
import string
import hashlib
import base64
from typing import Dict, Any, List, Optional
from collections import defaultdict, deque
from pathlib import Path
import os

from shared.constants import DEFAULT_SIGNAL_PORT, SIGNAL_PEER_TTL

peers: Dict[str, Dict[str, Any]] = {}
TRUST_FILE = Path.home() / ".securep2pchat" / "signal_trust.json"

def _load_trust() -> Dict[str, str]:
    try:
        data = json.loads(TRUST_FILE.read_text(encoding="utf-8"))
        return {str(k): str(v) for k, v in data.items() if isinstance(k, str) and isinstance(v, str)}
    except (OSError, ValueError, TypeError):
        return {}


def _save_trust(data: Dict[str, str]) -> bool:
    try:
        TRUST_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = TRUST_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
        os.replace(tmp, TRUST_FILE)
        return True
    except OSError as exc:
        print(f"[Signal] Nu pot persista registrul de identități: {exc}")
        return False


trust: Dict[str, str] = _load_trust()
# pair_code -> {device_id, verify_key, created}
pairs: Dict[str, Dict[str, Any]] = {}
pair_join_attempts: Dict[str, deque] = defaultdict(deque)
# group_id -> {name, invite_code, members: {device_id: {public_key, display_name}}}
groups: Dict[str, Dict[str, Any]] = {}
group_codes: Dict[str, str] = {}  # invite_code -> group_id
# device_id -> deque of {from, payload_b64, ts}
relay_queues: Dict[str, deque] = defaultdict(deque)
# session_token -> {device_id, exp, created}
sessions: Dict[str, Dict[str, Any]] = {}
# device_id -> current session_token (un singur token activ)
device_sessions: Dict[str, str] = {}
SESSION_TTL = 86400  # 24 ore
lock = asyncio.Lock()
used_nonces: Dict[str, float] = {}
MAX_RELAY_PAYLOAD_B64 = 512 * 1024

PAIR_TTL = 600
RELAY_TTL = 3600
MAX_RELAY_PER_USER = 200


def _canonical(device_id: str, ipv4, ipv6, port, ts: int, public_key: str = "", display_name: str = "") -> bytes:
    return (f"SecureP2PChat-register-v2|{device_id}|{ipv4 or ''}|{ipv6 or ''}|{port}|{ts}|"
            f"{public_key}|{display_name}").encode("utf-8")


def _verify_sig(verify_key_hex: str, message: bytes, sig_hex: str) -> bool:
    try:
        from nacl.signing import VerifyKey
        VerifyKey(bytes.fromhex(verify_key_hex)).verify(message, bytes.fromhex(sig_hex))
        return True
    except Exception:
        return False


def _signed_request_message(cmd: str, device_id: str, target: str, payload: str, ts: int, nonce: str) -> bytes:
    payload_hash = hashlib.sha256(payload.encode("ascii", errors="strict")).hexdigest() if payload else "-"
    return f"SecureP2PChat-signal-v1|{cmd}|{device_id}|{target}|{payload_hash}|{ts}|{nonce}".encode("utf-8")



def _new_session_token() -> str:
    return secrets.token_urlsafe(32)


def _purge_sessions(now: Optional[float] = None) -> None:
    now = now if now is not None else time.time()
    dead = [t for t, info in sessions.items() if float(info.get("exp", 0)) < now]
    for t in dead:
        info = sessions.pop(t, None)
        if info:
            did = info.get("device_id")
            if did and device_sessions.get(did) == t:
                device_sessions.pop(did, None)


def _issue_session(device_id: str) -> str:
    """Emite token nou; invalidează tokenul vechi al aceluiași device."""
    _purge_sessions()
    old = device_sessions.get(device_id)
    if old:
        sessions.pop(old, None)
    token = _new_session_token()
    now = time.time()
    sessions[token] = {"device_id": device_id, "created": now, "exp": now + SESSION_TTL}
    device_sessions[device_id] = token
    return token


def _resolve_session(msg: dict) -> Optional[str]:
    """Returnează device_id din session_token valid, sau None.
    ATENȚIE: apelează doar sub `async with lock`.
    """
    token = (msg.get("session_token") or "").strip()
    if not token or token not in sessions:
        return None
    info = sessions[token]
    if float(info.get("exp", 0)) < time.time():
        sessions.pop(token, None)
        did = info.get("device_id")
        if did and device_sessions.get(did) == token:
            device_sessions.pop(did, None)
        return None
    # sliding expiry
    info["exp"] = time.time() + SESSION_TTL
    return info.get("device_id")


async def _authenticate_session(msg: dict) -> Optional[str]:
    """Auth doar cu session_token (după register)."""
    async with lock:
        return _resolve_session(msg)


async def _authenticate_signed_request(msg: dict, cmd: str, target: str = "", payload: str = "") -> Optional[str]:
    device_id = (msg.get("device_id") or "").strip()
    try:
        ts = int(msg.get("ts") or 0)
    except (TypeError, ValueError):
        return None
    nonce = (msg.get("nonce") or "").strip()
    sig = (msg.get("signature") or "").strip()
    if not nonce or len(nonce) > 80 or abs(time.time() - ts) > 180:
        return None
    async with lock:
        # Token de sesiune: leagă cererea de device_id fără a te baza doar pe câmpul client
        tok_dev = _resolve_session(msg)
        if tok_dev:
            if device_id and device_id != tok_dev:
                return None
            device_id = tok_dev
        if not device_id:
            return None
        verify_key = trust.get(device_id)
        # cache de nonce-uri pentru a respinge replay-uri în fereastra de timp
        now = time.time()
        for old_nonce, created in list(used_nonces.items()):
            if now - created > 240:
                used_nonces.pop(old_nonce, None)
        nonce_key = f"{device_id}:{nonce}"
        if nonce_key in used_nonces:
            return None
        if not verify_key:
            return None
        message = _signed_request_message(cmd, device_id, target, payload, ts, nonce)
        if not _verify_sig(verify_key, message, sig):
            return None
        used_nonces[nonce_key] = now
    return device_id


def _gen_pair_code() -> str:
    alphabet = string.ascii_uppercase + string.digits
    # evită caractere confuze
    alphabet = alphabet.replace("O", "").replace("0", "").replace("I", "").replace("1", "")
    return "".join(secrets.choice(alphabet) for _ in range(6))


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    addr = writer.get_extra_info("peername")
    print(f"[Signal] + {addr}")
    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            try:
                msg = json.loads(line.decode("utf-8").strip())
            except json.JSONDecodeError:
                await _send(writer, {"ok": False, "error": "invalid_json"})
                continue
            cmd = msg.get("cmd")
            handlers = {
                "register": _register,
                "lookup": _lookup,
                "heartbeat": _heartbeat,
                "unregister": _unregister,
                "pair_create": _pair_create,
                "pair_join": _pair_join,
                "pair_status": _pair_status,
                "relay_send": _relay_send,
                "relay_poll": _relay_poll,
                "group_create": _group_create,
                "group_join": _group_join,
                "group_info": _group_info,
            }
            h = handlers.get(cmd)
            if h:
                await h(msg, writer)
            else:
                await _send(writer, {"ok": False, "error": "unknown_cmd"})
    except Exception as e:
        print(f"[Signal] err {addr}: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def _send(writer, obj: dict):
    writer.write((json.dumps(obj) + "\n").encode("utf-8"))
    await writer.drain()


def _auth_register_fields(msg) -> tuple:
    device_id = (msg.get("device_id") or "").strip()
    verify_key = (msg.get("verify_key") or "").strip()
    sig = (msg.get("signature") or "").strip()
    ts = int(msg.get("ts") or 0)
    return device_id, verify_key, sig, ts


async def _register(msg, writer):
    device_id, verify_key, sig, ts = _auth_register_fields(msg)
    ipv4, ipv6 = msg.get("ipv4"), msg.get("ipv6")
    port = int(msg.get("port") or 37421)
    if len(device_id) < 8 or not verify_key or not sig:
        await _send(writer, {"ok": False, "error": "missing_auth"})
        return
    if abs(time.time() - ts) > 180:
        await _send(writer, {"ok": False, "error": "ts_expired"})
        return
    if not _verify_sig(verify_key, _canonical(device_id, ipv4, ipv6, port, ts, msg.get("public_key") or "", msg.get("display_name") or ""), sig):
        await _send(writer, {"ok": False, "error": "bad_signature"})
        return
    async with lock:
        if device_id in trust and trust[device_id] != verify_key:
            await _send(writer, {"ok": False, "error": "device_key_mismatch"})
            return
        previous_key = trust.get(device_id)
        trust[device_id] = verify_key
        if previous_key is None and not _save_trust(trust):
            trust.pop(device_id, None)
            await _send(writer, {"ok": False, "error": "identity_store_unavailable"})
            return
        peers[device_id] = {
            "ipv4": ipv4, "ipv6": ipv6, "port": port,
            "last_seen": time.time(), "verify_key": verify_key,
            "public_key": msg.get("public_key") or "",
            "display_name": msg.get("display_name") or "",
        }
    token = _issue_session(device_id)
    await _send(writer, {
        "ok": True, "cmd": "register",
        "session_token": token,
        "expires_in": SESSION_TTL,
    })


async def _heartbeat(msg, writer):
    """Heartbeat: session_token suficient; altfel fallback pe semnătură register."""
    device_id = await _authenticate_session(msg)
    if not device_id:
        device_id, verify_key, sig, ts = _auth_register_fields(msg)
        if not device_id:
            await _send(writer, {"ok": False, "error": "auth_fail", "cmd": "heartbeat"})
            return
        # validare semnătură ca la register dacă nu e token
        public_key = (msg.get("public_key") or "")[:128]
        display_name = (msg.get("display_name") or "")[:64]
        try:
            port = int(msg.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        if not _verify_sig(verify_key or trust.get(device_id, ""), _canonical(
                device_id, msg.get("ipv4"), msg.get("ipv6"), port, ts, public_key, display_name), sig or ""):
            # dacă e în trust și token lipsește, tot eșuează
            if not (verify_key and _verify_sig(verify_key, _canonical(
                    device_id, msg.get("ipv4"), msg.get("ipv6"), port, int(msg.get("ts") or 0), public_key, display_name), sig or "")):
                await _send(writer, {"ok": False, "error": "auth_fail", "cmd": "heartbeat"})
                return
    async with lock:
        if device_id not in peers and device_id not in trust:
            await _send(writer, {"ok": False, "error": "not_registered", "cmd": "heartbeat"})
            return
        peers[device_id] = {
            **(peers.get(device_id) or {}),
            "ipv4": msg.get("ipv4"),
            "ipv6": msg.get("ipv6"),
            "port": msg.get("port"),
            "last_seen": time.time(),
            "public_key": (msg.get("public_key") or (peers.get(device_id) or {}).get("public_key") or ""),
            "display_name": (msg.get("display_name") or (peers.get(device_id) or {}).get("display_name") or ""),
        }
        token = _issue_session(device_id)
    await _send(writer, {"ok": True, "cmd": "heartbeat", "session_token": token, "expires_in": SESSION_TTL})


async def _lookup(msg, writer):
    device_id = (msg.get("device_id") or "").strip()
    async with lock:
        _cleanup()
        info = peers.get(device_id)
    if not info:
        await _send(writer, {"ok": False, "error": "not_found", "cmd": "lookup"})
        return
    await _send(writer, {
        "ok": True, "cmd": "lookup", "device_id": device_id,
        "ipv4": info.get("ipv4"), "ipv6": info.get("ipv6"),
        "port": info.get("port"), "last_seen": info.get("last_seen"),
        "verify_key": info.get("verify_key"),
        "public_key": info.get("public_key"),
        "display_name": info.get("display_name"),
    })


async def _unregister(msg, writer):
    device_id = await _authenticate_session(msg)
    if not device_id:
        device_id = await _authenticate_signed_request(msg, "unregister")
    if device_id:
        async with lock:
            tok = device_sessions.pop(device_id, None)
            if tok:
                sessions.pop(tok, None)
    if not device_id:
        await _send(writer, {"ok": False, "error": "auth_fail"})
        return
    async with lock:
        peers.pop(device_id, None)
    await _send(writer, {"ok": True, "cmd": "unregister"})




async def _pair_create(msg, writer):
    """Creează cod de pair – token SAU semnătură; chei obligatorii."""
    device_id = None
    verify_key = None
    async with lock:
        device_id = _resolve_session(msg)
        if device_id:
            verify_key = trust.get(device_id) or (peers.get(device_id) or {}).get("verify_key")

    if not device_id:
        device_id, verify_key, sig, ts = _auth_register_fields(msg)
        can = f"{device_id}|pair_create|{ts}".encode()
        if (not device_id or not verify_key or not sig or abs(time.time() - ts) > 180
                or not _verify_sig(verify_key, can, sig)):
            await _send(writer, {"ok": False, "error": "auth_fail"})
            return
        async with lock:
            old = trust.get(device_id)
            if old and old != verify_key:
                mismatch = True
            else:
                mismatch = False
                trust[device_id] = verify_key
        if mismatch:
            await _send(writer, {"ok": False, "error": "identity_mismatch"})
            return

    if not device_id:
        await _send(writer, {"ok": False, "error": "auth_fail"})
        return

    code = None
    err = None
    async with lock:
        if not verify_key:
            verify_key = trust.get(device_id) or (peers.get(device_id) or {}).get("verify_key") or ""
        if not verify_key:
            verify_key = (msg.get("verify_key") or "").strip()
            if verify_key:
                trust[device_id] = verify_key
        peer = peers.get(device_id) or {}
        pub = (msg.get("public_key") or peer.get("public_key") or "").strip()
        name = (msg.get("display_name") or peer.get("display_name") or "").strip()
        if not pub:
            err = "missing_public_key"
        elif not verify_key:
            err = "missing_verify_key"
        else:
            for k, v in list(pairs.items()):
                if v.get("device_id") == device_id:
                    del pairs[k]
            code = _gen_pair_code()
            while code in pairs:
                code = _gen_pair_code()
            pairs[code] = {
                "device_id": device_id,
                "verify_key": verify_key,
                "public_key": pub,
                "display_name": name,
                "created": time.time(),
            }
            peers[device_id] = {
                **peer,
                "public_key": pub,
                "verify_key": verify_key,
                "display_name": name or peer.get("display_name") or "",
                "last_seen": time.time(),
            }

    if err:
        await _send(writer, {"ok": False, "error": err})
        return
    print(f"[Signal] PAIR {code} ← {device_id[:12]}…")
    await _send(writer, {"ok": True, "cmd": "pair_create", "pair_code": code})


async def _pair_join(msg, writer):
    """Join pe cod – returnează cheile creatorului + notify pe coada creatorului."""
    code = (msg.get("pair_code") or "").strip().upper()
    my_id = (msg.get("device_id") or "").strip()
    err = None
    info = None
    joiner_pub = (msg.get("public_key") or "").strip()
    joiner_vk = (msg.get("verify_key") or "").strip()
    joiner_name = (msg.get("display_name") or "").strip()

    async with lock:
        tok_dev = _resolve_session(msg)
        if tok_dev:
            if my_id and my_id != tok_dev:
                err = "auth_fail"
            else:
                my_id = tok_dev
        if not err and not my_id:
            err = "missing_device_id"
        if not err and my_id not in trust and my_id not in peers:
            # acceptă dacă trimite verify_key (register incomplet)
            if joiner_vk:
                trust[my_id] = joiner_vk
            else:
                err = "not_registered"
        if not err:
            _cleanup()
            source = f"dev:{my_id}"
            attempts = pair_join_attempts[source]
            now = time.time()
            while attempts and now - attempts[0] > 60:
                attempts.popleft()
            if len(attempts) >= 40:
                err = "rate_limited"
            else:
                attempts.append(now)
            info = pairs.get(code)
            if not info:
                err = "pair_not_found"
            elif info.get("device_id") == my_id:
                err = "self_pair"
            else:
                # completează chei goale din peers
                if not info.get("public_key"):
                    pe = peers.get(info["device_id"]) or {}
                    info["public_key"] = pe.get("public_key") or ""
                    info["verify_key"] = info.get("verify_key") or pe.get("verify_key") or trust.get(info["device_id"]) or ""
                    info["display_name"] = info.get("display_name") or pe.get("display_name") or ""
                if not info.get("public_key"):
                    err = "peer_incomplete"
                else:
                    # snapshot sub lock
                    info = dict(info)
                    peer_ep = dict(peers.get(info["device_id"]) or {})
                    joiner_ep = dict(peers.get(my_id) or {})
                    if joiner_pub:
                        joiner_ep["public_key"] = joiner_pub
                    if joiner_vk:
                        joiner_ep["verify_key"] = joiner_vk
                        trust[my_id] = joiner_vk
                    if joiner_name:
                        joiner_ep["display_name"] = joiner_name
                    peers[my_id] = {**joiner_ep, "last_seen": time.time()}

    if err:
        await _send(writer, {"ok": False, "error": err})
        return

    await _send(writer, {
        "ok": True, "cmd": "pair_join",
        "device_id": info["device_id"],
        "public_key": info.get("public_key") or "",
        "display_name": info.get("display_name") or "",
        "verify_key": info.get("verify_key") or "",
        "ipv4": peer_ep.get("ipv4"),
        "ipv6": peer_ep.get("ipv6"),
        "port": peer_ep.get("port") or 37421,
    })

    # Notify creator (în afara lock-ului la send)
    try:
        import json as _json
        note = _json.dumps({
            "type": "pair_joined",
            "from": my_id,
            "device_id": my_id,
            "public_key": joiner_pub or joiner_ep.get("public_key") or "",
            "verify_key": joiner_vk or joiner_ep.get("verify_key") or trust.get(my_id) or "",
            "display_name": joiner_name or joiner_ep.get("display_name") or "",
            "ipv4": joiner_ep.get("ipv4"),
            "ipv6": joiner_ep.get("ipv6"),
            "port": joiner_ep.get("port") or 37421,
        }, separators=(",", ":"))
        raw = bytes([0xFE]) + note.encode("utf-8")
        b64 = base64.b64encode(raw).decode("ascii")
        async with lock:
            q = relay_queues[info["device_id"]]
            q.append({"from": my_id, "payload": b64, "ts": time.time()})
            # stochează joiner pe cod – creatorul poate face pair_status
            for c, pinfo in list(pairs.items()):
                if pinfo.get("device_id") == info["device_id"]:
                    pinfo["joined_by"] = {
                        "device_id": my_id,
                        "public_key": joiner_pub or joiner_ep.get("public_key") or "",
                        "verify_key": joiner_vk or joiner_ep.get("verify_key") or trust.get(my_id) or "",
                        "display_name": joiner_name or joiner_ep.get("display_name") or "",
                        "ts": time.time(),
                    }
                    pairs[c] = pinfo
            print(f"[Signal] pair_joined → {info['device_id'][:12]} from {my_id[:12]} q={len(q)}")
    except Exception as exc:
        print(f"[Signal] pair notify: {exc}")



async def _pair_status(msg, writer):
    """Creatorul întreabă dacă cineva a intrat pe codul lui."""
    code = (msg.get("pair_code") or "").strip().upper()
    device_id = None
    async with lock:
        device_id = _resolve_session(msg)
    if not device_id:
        device_id = (msg.get("device_id") or "").strip()
    if not device_id:
        await _send(writer, {"ok": False, "error": "auth_fail"})
        return
    async with lock:
        info = pairs.get(code) if code else None
        if not info:
            # caută orice cod al acestui user cu joined_by
            for c, pinfo in pairs.items():
                if pinfo.get("device_id") == device_id and pinfo.get("joined_by"):
                    info = pinfo
                    code = c
                    break
        if not info or info.get("device_id") != device_id:
            await _send(writer, {"ok": True, "cmd": "pair_status", "joined": False})
            return
        jb = info.get("joined_by")
        if not jb:
            await _send(writer, {"ok": True, "cmd": "pair_status", "joined": False, "pair_code": code})
            return
        # o singură livrare – consumă joined_by
        info = dict(info)
        jb = dict(jb)
        info.pop("joined_by", None)
        pairs[code] = info
    await _send(writer, {
        "ok": True, "cmd": "pair_status", "joined": True, "pair_code": code,
        "device_id": jb.get("device_id"),
        "public_key": jb.get("public_key") or "",
        "verify_key": jb.get("verify_key") or "",
        "display_name": jb.get("display_name") or "",
    })


async def _relay_send(msg, writer):
    """Acceptă ciphertext doar de la o identitate înregistrată și semnatară."""
    to_id = (msg.get("to") or "").strip()
    payload = msg.get("payload")
    if not to_id or not isinstance(payload, str) or not payload:
        await _send(writer, {"ok": False, "error": "missing_fields"})
        return
    if len(payload) > MAX_RELAY_PAYLOAD_B64:
        await _send(writer, {"ok": False, "error": "payload_too_large"})
        return
    try:
        base64.b64decode(payload, validate=True)
    except Exception:
        await _send(writer, {"ok": False, "error": "invalid_payload"})
        return
    # Auth principal: session_token; fallback: semnătură Ed25519
    from_id = await _authenticate_session(msg)
    if not from_id:
        from_id = await _authenticate_signed_request(msg, "relay_send", to_id, payload)
    if not from_id:
        await _send(writer, {"ok": False, "error": "auth_fail"})
        return
    async with lock:
        q = relay_queues[to_id]
        now = time.time()
        while q and now - q[0]["ts"] > RELAY_TTL:
            q.popleft()
        if len(q) >= MAX_RELAY_PER_USER:
            await _send(writer, {"ok": False, "error": "queue_full"})
            return
        q.append({"from": from_id, "payload": payload, "ts": now})
    await _send(writer, {"ok": True, "cmd": "relay_send"})


async def _relay_poll(msg, writer):
    # Token first (client modern); fallback semnătură
    device_id = await _authenticate_session(msg)
    if not device_id:
        device_id = await _authenticate_signed_request(msg, "relay_poll")
    if not device_id:
        await _send(writer, {"ok": False, "error": "auth_fail", "messages": []})
        return
    async with lock:
        q = relay_queues.get(device_id)
        items = []
        if q:
            now = time.time()
            while q:
                item = q.popleft()
                if now - item["ts"] <= RELAY_TTL:
                    items.append(item)
    await _send(writer, {"ok": True, "cmd": "relay_poll", "messages": items})




async def _group_create(msg, writer):
    """Creează grup + cod invitație (auth ca pair_create – dovedit stabil)."""
    device_id, verify_key, sig, ts = _auth_register_fields(msg)
    name = (msg.get("name") or "Grup").strip()[:64] or "Grup"
    can = f"{device_id}|group_create|{ts}|{name}".encode("utf-8")
    if (not device_id or not verify_key or not sig or abs(time.time() - ts) > 180
            or not _verify_sig(verify_key, can, sig) or trust.get(device_id) != verify_key):
        print(f"[Signal] group_create auth_fail id={device_id[:10] if device_id else '?'}")
        await _send(writer, {"ok": False, "error": "auth_fail"})
        return
    async with lock:
        code = _gen_pair_code()
        while code in group_codes:
            code = _gen_pair_code()
        gid = secrets.token_hex(8)
        groups[gid] = {
            "name": name,
            "invite_code": code,
            "creator": device_id,
            "created": time.time(),
            "members": {
                device_id: {
                    "public_key": msg.get("public_key") or "",
                    "display_name": msg.get("display_name") or "",
                }
            },
        }
        group_codes[code] = gid
    print(f"[Signal] GROUP CREATE {code} «{name}» by {device_id[:10]}")
    await _send(writer, {
        "ok": True, "cmd": "group_create",
        "group_id": gid, "invite_code": code, "name": name,
        "creator_id": device_id,
    })


async def _group_join(msg, writer):
    """Intră în grup cu codul de invitație."""
    device_id, verify_key, sig, ts = _auth_register_fields(msg)
    code = (msg.get("invite_code") or msg.get("pair_code") or "").strip().upper()
    can = f"{device_id}|group_join|{ts}|{code}".encode("utf-8")
    if (not device_id or not verify_key or not sig or not code
            or abs(time.time() - ts) > 180
            or not _verify_sig(verify_key, can, sig)
            or trust.get(device_id) != verify_key):
        print(f"[Signal] group_join auth_fail code={code}")
        await _send(writer, {"ok": False, "error": "auth_fail"})
        return
    async with lock:
        gid = group_codes.get(code)
        if not gid or gid not in groups:
            await _send(writer, {"ok": False, "error": "group_not_found"})
            return
        g = groups[gid]
        g["members"][device_id] = {
            "public_key": msg.get("public_key") or "",
            "display_name": msg.get("display_name") or "",
        }
        members = [
            {
                "device_id": mid,
                "public_key": info.get("public_key") or "",
                "display_name": info.get("display_name") or "",
            }
            for mid, info in g["members"].items()
        ]
    print(f"[Signal] GROUP JOIN {code} ← {device_id[:10]} members={len(members)}")
    await _send(writer, {
        "ok": True, "cmd": "group_join", "group_id": gid,
        "name": g["name"], "members": members, "invite_code": code,
        "creator_id": g.get("creator", ""),
    })


async def _group_info(msg, writer):
    device_id, verify_key, sig, ts = _auth_register_fields(msg)
    gid = (msg.get("group_id") or "").strip()
    can = f"{device_id}|group_info|{ts}|{gid}".encode("utf-8")
    if (not device_id or not verify_key or not sig or not gid
            or abs(time.time() - ts) > 180
            or not _verify_sig(verify_key, can, sig)
            or trust.get(device_id) != verify_key):
        await _send(writer, {"ok": False, "error": "auth_fail"})
        return
    async with lock:
        g = groups.get(gid)
        if not g or device_id not in g["members"]:
            await _send(writer, {"ok": False, "error": "not_member"})
            return
        members = [
            {
                "device_id": mid,
                "public_key": info.get("public_key") or "",
                "display_name": info.get("display_name") or "",
            }
            for mid, info in g["members"].items()
        ]
    await _send(writer, {
        "ok": True, "cmd": "group_info", "group_id": gid,
        "name": g["name"], "members": members, "invite_code": g.get("invite_code"),
        "creator_id": g.get("creator", ""),
    })


def _cleanup():
    now = time.time()
    for k, v in list(peers.items()):
        if now - v["last_seen"] > SIGNAL_PEER_TTL:
            del peers[k]
    for k, v in list(pairs.items()):
        if now - v["created"] > PAIR_TTL:
            del pairs[k]
    for did, q in list(relay_queues.items()):
        while q and now - q[0]["ts"] > RELAY_TTL:
            q.popleft()
        if not q:
            del relay_queues[did]
    for source, attempts in list(pair_join_attempts.items()):
        while attempts and now - attempts[0] > 60:
            attempts.popleft()
        if not attempts:
            pair_join_attempts.pop(source, None)


def build_ssl_context(certfile: str, keyfile: str, require_client_cert: bool = False):
    """TLS 1.2 + 1.3, fără ciphers vechi."""
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Minimum TLS 1.2 (pe Python modern e default rezonabil; forțăm explicit)
    if hasattr(ssl, "TLSVersion"):
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        # Preferă 1.3 când e disponibil
        try:
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        except Exception:
            pass
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    ctx.options |= getattr(ssl, "OP_NO_SSLv2", 0)
    ctx.options |= getattr(ssl, "OP_NO_SSLv3", 0)
    ctx.options |= getattr(ssl, "OP_NO_TLSv1", 0)
    ctx.options |= getattr(ssl, "OP_NO_TLSv1_1", 0)
    # pe server nu verificăm client cert în mod normal
    ctx.verify_mode = ssl.CERT_REQUIRED if require_client_cert else ssl.CERT_NONE
    return ctx


async def main(host="0.0.0.0", port=DEFAULT_SIGNAL_PORT, ssl_ctx=None):
    server = await asyncio.start_server(
        handle_client, host, port, limit=1024 * 1024, ssl=ssl_ctx
    )
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets or [])
    mode = "TLS 1.2/1.3" if ssl_ctx else "TCP clar (fără TLS)"
    print(f"[Signal] SecureP2PChat relay pe {addrs}  [{mode}]")
    print("[Signal] Nu decriptează mesaje. Doar ciphertext în RAM.")
    if ssl_ctx:
        print("[Signal] Metadatele JSON (device_id, pair, relay) sunt protejate de TLS.")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    import sys
    import argparse
    from pathlib import Path
    base = getattr(sys, "_MEIPASS", None) or str(Path(__file__).resolve().parent)
    if str(Path(__file__).resolve().parent) not in sys.path:
        sys.path.insert(0, str(Path(__file__).resolve().parent))

    parser = argparse.ArgumentParser(description="SecureP2PChat Signaling + Relay")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=DEFAULT_SIGNAL_PORT)
    parser.add_argument("--cert", default=os.environ.get("SIGNAL_TLS_CERT", ""),
                        help="Cale certificat PEM (activează TLS)")
    parser.add_argument("--key", default=os.environ.get("SIGNAL_TLS_KEY", ""),
                        help="Cale cheie privată PEM")
    args = parser.parse_args()

    ssl_ctx = None
    if args.cert and args.key:
        if not Path(args.cert).is_file() or not Path(args.key).is_file():
            print("[Signal] EROARE: --cert / --key invalide")
            sys.exit(1)
        ssl_ctx = build_ssl_context(args.cert, args.key)
        print(f"[Signal] TLS activ: cert={args.cert}")
    else:
        print("[Signal] ATENȚIE: rulează fără TLS. Folosește --cert și --key pentru TLS.")

    try:
        asyncio.run(main(host=args.host, port=args.port, ssl_ctx=ssl_ctx))
    except KeyboardInterrupt:
        print("\n[Signal] Oprit.")
