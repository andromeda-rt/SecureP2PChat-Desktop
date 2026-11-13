# -*- coding: utf-8 -*-
"""
UPnP / IGD helper - încearcă să deschidă portul pe router automat
"""

from typing import Optional, Tuple
import socket


def try_upnp_port_mapping(port: int, description: str = "SecureP2PChat") -> Tuple[bool, str, Optional[str]]:
    """
    Încearcă maparea portului TCP prin UPnP.
    Returnează: (success, message, external_ip)
    """
    try:
        import miniupnpc
    except ImportError:
        return False, "UPnP: miniupnpc lipsă (opțional pe Windows; relay Tor nu depinde de el)", None

    try:
        upnp = miniupnpc.UPnP()
        upnp.discoverdelay = 200  # ms
        ndevices = upnp.discover()
        if ndevices == 0:
            return False, "Niciun dispozitiv UPnP găsit pe rețea", None

        upnp.selectigd()
        external_ip = upnp.externalipaddress()
        local_ip = upnp.lanaddr

        # Ștergem o mapare veche dacă există (ca să nu avem conflict)
        try:
            upnp.deleteportmapping(port, "TCP")
        except Exception:
            pass

        # Adăugăm maparea nouă
        result = upnp.addportmapping(
            port,           # external port
            "TCP",
            local_ip,       # internal IP
            port,           # internal port
            description,
            ""              # remote host (any)
        )

        if result:
            return True, f"Port {port} deschis pe router (IP public: {external_ip})", external_ip
        else:
            return False, "Routerul a refuzat maparea portului", external_ip

    except Exception as e:
        err = str(e).lower()
        if "no igd" in err or "not found" in err:
            return False, "Routerul nu suportă UPnP sau este dezactivat", None
        return False, f"UPnP eșuat: {e}", None


def remove_upnp_port_mapping(port: int) -> None:
    """Șterge maparea la închidere (best-effort)."""
    try:
        import miniupnpc
        upnp = miniupnpc.UPnP()
        upnp.discoverdelay = 150
        if upnp.discover() > 0:
            upnp.selectigd()
            try:
                upnp.deleteportmapping(port, "TCP")
            except Exception:
                pass
    except Exception:
        pass


def get_public_ip_via_upnp() -> Optional[str]:
    """Obține IP-ul public raportat de router (dacă UPnP e disponibil)."""
    try:
        import miniupnpc
        upnp = miniupnpc.UPnP()
        upnp.discoverdelay = 150
        if upnp.discover() > 0:
            upnp.selectigd()
            return upnp.externalipaddress()
    except Exception:
        pass
    return None
