# -*- coding: utf-8 -*-
"""Reguli pentru migrarea sigură a fingerprint-urilor de contact."""
import hashlib


def _fingerprint(raw: bytes) -> str:
    h = hashlib.sha256(raw).hexdigest().upper()
    return " ".join(h[i:i + 4] for i in range(0, 48, 4))


def fingerprint_transition_allowed(old_fingerprint, old_public_key_hex,
                                   new_signing_fingerprint, peer_public_key_hex):
    """Permite aceeași cheie de semnare sau migrarea explicită din schema veche.

    Înainte de v0.7.3, câmpul `contacts.fingerprint` conținea fingerprint-ul
    cheii X25519. În v0.7.3, câmpul conține fingerprint-ul cheii Ed25519.
    Tranziția este acceptată numai dacă cheia X25519 salvată este identică
    cu cea prezentată acum și fingerprint-ul vechi corespunde exact acelei
    chei. O cheie X25519 diferită sau un fingerprint necunoscut rămâne refuzat.
    """
    if not old_fingerprint:
        return True
    if old_fingerprint == new_signing_fingerprint:
        return True
    if not old_public_key_hex or not peer_public_key_hex:
        return False
    try:
        old_pub = bytes.fromhex(old_public_key_hex)
        peer_pub = bytes.fromhex(peer_public_key_hex)
        if len(old_pub) != 32 or len(peer_pub) != 32:
            return False
        return (old_pub == peer_pub and
                old_fingerprint == _fingerprint(old_pub))
    except (ValueError, TypeError):
        return False
