# -*- coding: utf-8 -*-
"""
GUI - Dark Electro Blue + Setări (IPv4/IPv6/Device ID ascunse)
"""

import customtkinter as ctk
from tkinter import filedialog
from typing import Optional, Callable
from pathlib import Path
from PIL import Image
from shared.constants import COLORS, APP_NAME




def fit_geometry(win, ideal_w: int, ideal_h: int, min_w: int = 320, min_h: int = 400):
    """Ajustează fereastra la ecran (laptop, 1080p, 4K, portrait)."""
    try:
        win.update_idletasks()
        sw = win.winfo_screenwidth()
        sh = win.winfo_screenheight()
        w = max(min_w, min(ideal_w, int(sw * 0.92)))
        h = max(min_h, min(ideal_h, int(sh * 0.88)))
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 3)
        win.geometry(f"{w}x{h}+{x}+{y}")
        win.minsize(min_w, min_h)
    except Exception:
        win.geometry(f"{ideal_w}x{ideal_h}")

class TrustDialog(ctk.CTkToplevel):
    """Confirmare fingerprint TOFU la primul contact."""
    def __init__(self, parent, display_name: str, fingerprint: str, on_result):
        super().__init__(parent)
        self.on_result = on_result
        self.title("Verificare securitate")
        fit_geometry(self, 520, 360, 360, 280)
        self.resizable(True, True)
        self.configure(fg_color=COLORS["bg_dark"])
        self.transient(parent)
        self.grab_set()
        self.resizable(False, False)

        ctk.CTkLabel(self, text="Verifică identitatea contactului",
                     font=ctk.CTkFont(size=16, weight="bold"),
                     text_color=COLORS["accent"]).pack(pady=(20, 8))
        ctk.CTkLabel(self, text=f"Nume: {display_name}",
                     text_color=COLORS["text"]).pack()
        ctk.CTkLabel(self, text="Fingerprint (compară pe un canal sigur):",
                     text_color=COLORS["text_secondary"],
                     font=ctk.CTkFont(size=12)).pack(pady=(16, 4))
        ctk.CTkLabel(self, text=fingerprint,
                     font=ctk.CTkFont(size=13, family="Consolas"),
                     text_color=COLORS["success"], wraplength=480).pack(padx=20, pady=8)

        ctk.CTkLabel(self, text="Dacă fingerprint-ul nu coincide, refuză conexiunea!",
                     text_color=COLORS["warning"], font=ctk.CTkFont(size=11)).pack(pady=6)

        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(pady=16)
        ctk.CTkButton(row, text="Refuză", width=120, height=36,
                      fg_color=COLORS["danger"], hover_color="#C9184A",
                      command=lambda: self._done(False)).pack(side="left", padx=8)
        ctk.CTkButton(row, text="Am verificat – Încredere", width=180, height=36,
                      fg_color=COLORS["accent"], hover_color=COLORS["accent_hover"],
                      text_color="#000",
                      command=lambda: self._done(True)).pack(side="left", padx=8)

    def _done(self, trusted: bool):
        self.on_result(trusted)
        self.destroy()


class LoginWindow(ctk.CTk):
    def __init__(self, on_login: Callable, on_create: Callable, has_existing: bool = False):
        super().__init__()
        self.on_login = on_login
        self.on_create = on_create

        self.title(f"{APP_NAME} – Autentificare")
        self.resizable(True, True)
        fit_geometry(self, 440, 640, 360, 520)
        self.configure(fg_color=COLORS["bg_dark"])
        ctk.set_appearance_mode("dark")

        header = ctk.CTkLabel(
            self, text=APP_NAME,
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
            text_color=COLORS["accent"]
        )
        header.pack(pady=(36, 4))

        sub = ctk.CTkLabel(
            self, text="Secure Peer-to-Peer Chat  •  E2EE",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["text_secondary"]
        )
        sub.pack(pady=(0, 24))

        frame = ctk.CTkFrame(self, fg_color=COLORS["bg_secondary"], corner_radius=14)
        frame.pack(padx=36, pady=6, fill="x")

        ctk.CTkLabel(frame, text="Nume afișat", text_color=COLORS["text_secondary"]).pack(anchor="w", padx=22, pady=(22, 4))
        self.name_entry = ctk.CTkEntry(
            frame, placeholder_text="ex: Andromeda",
            fg_color=COLORS["bg_card"], border_color=COLORS["border"],
            text_color=COLORS["text"], height=40, corner_radius=8
        )
        self.name_entry.pack(padx=22, fill="x")

        ctk.CTkLabel(frame, text="Parolă", text_color=COLORS["text_secondary"]).pack(anchor="w", padx=22, pady=(14, 4))
        self.pass_entry = ctk.CTkEntry(
            frame, placeholder_text="minim 8 caractere", show="•",
            fg_color=COLORS["bg_card"], border_color=COLORS["border"],
            text_color=COLORS["text"], height=40, corner_radius=8
        )
        self.pass_entry.pack(padx=22, fill="x")
        self.pass_entry.bind("<Return>", lambda e: self._do_login() if has_existing else self._do_create())

        self.status_label = ctk.CTkLabel(frame, text="", text_color=COLORS["danger"], font=ctk.CTkFont(size=12))
        self.status_label.pack(pady=(12, 4))

        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.pack(pady=(6, 24), padx=22, fill="x")

        if has_existing:
            self.login_btn = ctk.CTkButton(
                btn_frame, text="Deblochează contul",
                fg_color=COLORS["accent"], hover_color=COLORS["accent_hover"],
                text_color="#000000", height=42, corner_radius=8,
                font=ctk.CTkFont(size=14, weight="bold"),
                command=self._do_login
            )
            self.login_btn.pack(fill="x")
            self.name_entry.configure(state="disabled")
            ctk.CTkLabel(frame, text="Cont existent detectat – introdu parola",
                         text_color=COLORS["text_secondary"], font=ctk.CTkFont(size=11)).pack(pady=(0, 12))
        else:
            self.create_btn = ctk.CTkButton(
                btn_frame, text="Creează cont nou",
                fg_color=COLORS["accent"], hover_color=COLORS["accent_hover"],
                text_color="#000000", height=42, corner_radius=8,
                font=ctk.CTkFont(size=14, weight="bold"),
                command=self._do_create
            )
            self.create_btn.pack(fill="x")
        ctk.CTkLabel(
            self,
            text="E2EE · Tor recomandat (.onion + SOCKS 9150)",
            text_color=COLORS["text_secondary"], font=ctk.CTkFont(size=10),
            wraplength=360
        ).pack(padx=36, pady=(0, 12))

    def _do_login(self):
        password = self.pass_entry.get()
        if not password:
            self.status_label.configure(text="Introdu parola")
            return
        ok = self.on_login(password)
        if not ok:
            self.status_label.configure(text="Parolă greșită sau fișier corupt")

    def _do_create(self):
        name = self.name_entry.get().strip()
        password = self.pass_entry.get()
        if len(name) < 2:
            self.status_label.configure(text="Numele trebuie să aibă minim 2 caractere")
            return
        if len(password) < 8:
            self.status_label.configure(text="Parola trebuie să aibă minim 8 caractere")
            return
        self.on_create(name, password)


class SettingsWindow(ctk.CTkToplevel):
    """Fereastră Setări – coduri de conectare ascunse aici."""

    def __init__(self, parent, device_id: str, code_ipv4: str, code_ipv6: str,
                 signal_host: str, signal_port: int, on_save_signal: Callable,
                 use_tls: bool = True, ca_file: str = "", tls_insecure: bool = False,
                 proxy_list: str = "", proxy_rotate: int = 0,
                 socks_host: str = "", socks_port: str = ""):
        super().__init__(parent)
        self.title("Setări")
        self.resizable(True, True)
        fit_geometry(self, 540, 640, 380, 420)
        self.configure(fg_color=COLORS["bg_dark"])
        self.transient(parent)
        self.grab_set()

        self.on_save_signal = on_save_signal
        self.code_ipv4 = code_ipv4 or "—"
        self.code_ipv6 = code_ipv6 or "—"
        self.device_id = device_id

        ctk.CTkLabel(self, text="Setări", font=ctk.CTkFont(size=20, weight="bold"),
                     text_color=COLORS["accent"]).pack(pady=(16, 4))

        # Corp derulabil – toate setările vizibile prin scroll
        body = ctk.CTkScrollableFrame(
            self, fg_color="transparent",
            scrollbar_button_color=COLORS["border"],
            scrollbar_button_hover_color=COLORS["accent_dark"],
        )
        body.pack(fill="both", expand=True, padx=8, pady=(0, 4))

        # --- Coduri de conectare ---
        codes_frame = ctk.CTkFrame(body, fg_color=COLORS["bg_secondary"], corner_radius=12)
        codes_frame.pack(fill="x", padx=12, pady=8)

        ctk.CTkLabel(codes_frame, text="Coduri de conectare", font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=COLORS["text"]).pack(anchor="w", padx=16, pady=(14, 8))

        # Device ID (pentru semnalizare)
        self._add_copy_row(codes_frame, "Device ID (semnalizare)", device_id)

        # IPv4
        self._add_copy_row(codes_frame, "Cod IPv4", self.code_ipv4)

        # IPv6
        self._add_copy_row(codes_frame, "Cod IPv6", self.code_ipv6)

        ctk.CTkLabel(codes_frame, text="", height=6).pack()

        # --- Server semnalizare ---
        sig_frame = ctk.CTkFrame(body, fg_color=COLORS["bg_secondary"], corner_radius=12)
        sig_frame.pack(fill="x", padx=12, pady=8)

        ctk.CTkLabel(sig_frame, text="Server de semnalizare", font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=COLORS["text"]).pack(anchor="w", padx=16, pady=(14, 4))

        ctk.CTkLabel(sig_frame, text="Ajută la conectare pe internet. Nu vede mesajele.",
                     font=ctk.CTkFont(size=11), text_color=COLORS["text_secondary"]).pack(anchor="w", padx=16)

        row = ctk.CTkFrame(sig_frame, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=(10, 4))

        self.signal_host_entry = ctk.CTkEntry(
            row, placeholder_text="IP sau domeniu server",
            fg_color=COLORS["bg_card"], border_color=COLORS["border"],
            text_color=COLORS["text"], height=36
        )
        self.signal_host_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        if signal_host:
            self.signal_host_entry.insert(0, signal_host)

        self.signal_port_entry = ctk.CTkEntry(
            row, width=80, placeholder_text="Port",
            fg_color=COLORS["bg_card"], border_color=COLORS["border"],
            text_color=COLORS["text"], height=36
        )
        self.signal_port_entry.pack(side="left")
        self.signal_port_entry.insert(0, str(signal_port))

        self.tls_var = ctk.BooleanVar(value=use_tls)
        ctk.CTkCheckBox(
            sig_frame, text="TLS 1.2 / 1.3 (ascunde metadatele JSON)",
            variable=self.tls_var, text_color=COLORS["text"]
        ).pack(anchor="w", padx=16, pady=(10, 2))

        self.insecure_var = ctk.BooleanVar(value=tls_insecure)
        ctk.CTkCheckBox(
            sig_frame, text="Acceptă certificat self-signed (doar test)",
            variable=self.insecure_var, text_color=COLORS["warning"]
        ).pack(anchor="w", padx=16, pady=2)

        ctk.CTkLabel(
            sig_frame, text="Fișier CA / cert server (PEM, opțional):",
            text_color=COLORS["text_secondary"], font=ctk.CTkFont(size=11)
        ).pack(anchor="w", padx=16, pady=(8, 2))
        self.ca_entry = ctk.CTkEntry(
            sig_frame, fg_color=COLORS["bg_card"], border_color=COLORS["border"],
            text_color=COLORS["text"], height=32
        )
        self.ca_entry.pack(fill="x", padx=16, pady=2)
        if ca_file:
            self.ca_entry.insert(0, ca_file)


        ctk.CTkLabel(
            sig_frame, text="Tor SOCKS (Tor Browser: 127.0.0.1:9150 / tor: 9050):",
            text_color=COLORS["text_secondary"], font=ctk.CTkFont(size=11)
        ).pack(anchor="w", padx=16, pady=(8, 2))
        tor_row = ctk.CTkFrame(sig_frame, fg_color="transparent")
        tor_row.pack(fill="x", padx=16, pady=2)
        self.socks_host_entry = ctk.CTkEntry(tor_row, placeholder_text="127.0.0.1", width=140,
            fg_color=COLORS["bg_card"], border_color=COLORS["border"], text_color=COLORS["text"], height=32)
        self.socks_host_entry.pack(side="left", padx=(0, 6))
        if socks_host:
            self.socks_host_entry.insert(0, socks_host)
        self.socks_port_entry = ctk.CTkEntry(tor_row, placeholder_text="9150", width=70,
            fg_color=COLORS["bg_card"], border_color=COLORS["border"], text_color=COLORS["text"], height=32)
        self.socks_port_entry.pack(side="left")
        if socks_port:
            self.socks_port_entry.insert(0, str(socks_port))

        ctk.CTkLabel(
            sig_frame, text="Pool proxy SOCKS4/5 (câte unul pe linie, failover):",
            text_color=COLORS["text_secondary"], font=ctk.CTkFont(size=11)
        ).pack(anchor="w", padx=16, pady=(10, 2))
        self.proxy_box = ctk.CTkTextbox(
            sig_frame, height=72, fg_color=COLORS["bg_card"],
            border_color=COLORS["border"], text_color=COLORS["text"],
            font=ctk.CTkFont(size=11, family="Consolas")
        )
        self.proxy_box.pack(fill="x", padx=16, pady=2)
        if proxy_list:
            self.proxy_box.insert("1.0", proxy_list)
        rot_row = ctk.CTkFrame(sig_frame, fg_color="transparent")
        rot_row.pack(fill="x", padx=16, pady=(4, 2))
        ctk.CTkLabel(rot_row, text="Rotație (sec, 0=doar failover):",
                     text_color=COLORS["text_secondary"], font=ctk.CTkFont(size=11)).pack(side="left")
        self.proxy_rotate_entry = ctk.CTkEntry(rot_row, width=70, fg_color=COLORS["bg_card"],
            border_color=COLORS["border"], text_color=COLORS["text"], height=28)
        self.proxy_rotate_entry.pack(side="left", padx=8)
        self.proxy_rotate_entry.insert(0, str(int(proxy_rotate or 0)))

        save_btn = ctk.CTkButton(
            sig_frame, text="Salvează & reconectează",
            fg_color=COLORS["accent_dark"], hover_color=COLORS["accent"],
            text_color="#fff", height=36, corner_radius=8,
            command=self._save_signal
        )
        save_btn.pack(fill="x", padx=16, pady=(8, 16))

        close_btn = ctk.CTkButton(
            self, text="Închide",
            fg_color=COLORS["bg_card"], hover_color=COLORS["border"],
            text_color=COLORS["text"], height=38, corner_radius=8,
            command=self.destroy
        )
        close_btn.pack(pady=(4, 14), padx=24, fill="x")

    def _add_copy_row(self, parent, label: str, value: str):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.pack(fill="x", padx=16, pady=4)

        ctk.CTkLabel(frame, text=label, font=ctk.CTkFont(size=11),
                     text_color=COLORS["text_secondary"]).pack(anchor="w")

        row = ctk.CTkFrame(frame, fg_color="transparent")
        row.pack(fill="x", pady=(2, 0))

        entry = ctk.CTkEntry(
            row, fg_color=COLORS["bg_card"], border_color=COLORS["border"],
            text_color=COLORS["accent"], height=32, font=ctk.CTkFont(size=11, family="Consolas")
        )
        entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        entry.insert(0, value)
        entry.configure(state="readonly")

        def do_copy(v=value, b=None):
            self.clipboard_clear()
            self.clipboard_append(v)
            if b:
                b.configure(text="✓")
                self.after(1500, lambda: b.configure(text="Copiază"))

        btn = ctk.CTkButton(
            row, text="Copiază", width=70, height=32, corner_radius=6,
            fg_color=COLORS["accent_dark"], hover_color=COLORS["accent"],
            text_color="#fff", font=ctk.CTkFont(size=11)
        )
        btn.configure(command=lambda: do_copy(b=btn))
        btn.pack(side="left")

    def _save_signal(self):
        host = self.signal_host_entry.get().strip()
        try:
            port = int(self.signal_port_entry.get().strip())
        except ValueError:
            port = 37422
        use_tls = bool(self.tls_var.get()) if hasattr(self, "tls_var") else True
        insecure = bool(self.insecure_var.get()) if hasattr(self, "insecure_var") else False
        ca = self.ca_entry.get().strip() if hasattr(self, "ca_entry") else ""
        sh = self.socks_host_entry.get().strip() if hasattr(self, "socks_host_entry") else ""
        sp = self.socks_port_entry.get().strip() if hasattr(self, "socks_port_entry") else ""
        plist = self.proxy_box.get("1.0", "end").strip() if hasattr(self, "proxy_box") else ""
        try:
            prot = int(self.proxy_rotate_entry.get().strip() or "0") if hasattr(self, "proxy_rotate_entry") else 0
        except ValueError:
            prot = 0
        self.on_save_signal(host, port, use_tls, ca, insecure, sh, sp, plist, prot)
        self.destroy()


class MainWindow(ctk.CTk):
    def __init__(self, display_name: str, device_id: str, connection_code: str = ""):
        super().__init__()
        self.display_name = display_name
        self.device_id = device_id
        self.connection_code = connection_code
        self.code_ipv4 = ""
        self.code_ipv6 = ""
        self.signal_host = ""
        self.signal_port = 37422
        self.signal_tls = True
        self.signal_ca = ""
        self.signal_tls_insecure = False

        self.title(f"{APP_NAME} – {display_name}")
        self.resizable(True, True)
        fit_geometry(self, 1100, 720, 640, 480)
        # pe ecrane înguste sidebar mai subțire
        try:
            sw = self.winfo_screenwidth()
            self._sidebar_w = 220 if sw < 900 else (260 if sw < 1400 else 300)
        except Exception:
            self._sidebar_w = 260
        self.configure(fg_color=COLORS["bg_dark"])

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=getattr(self, "_sidebar_w", 260), fg_color=COLORS["bg_secondary"], corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)
        self.grid_columnconfigure(0, minsize=180)

        header = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(16, 8))

        top_row = ctk.CTkFrame(header, fg_color="transparent")
        top_row.pack(fill="x")
        ctk.CTkLabel(top_row, text=APP_NAME, font=ctk.CTkFont(size=18, weight="bold"),
                     text_color=COLORS["accent"]).pack(side="left")
        self.settings_btn = ctk.CTkButton(
            top_row, text="⚙", width=36, height=32, corner_radius=8,
            fg_color=COLORS["bg_card"], hover_color=COLORS["border"],
            text_color=COLORS["text"], font=ctk.CTkFont(size=16),
            command=self._open_settings
        )
        self.settings_btn.pack(side="right")

        ctk.CTkLabel(header, text=display_name, font=ctk.CTkFont(size=13),
                     text_color=COLORS["text"]).pack(anchor="w")
        ctk.CTkLabel(header, text=f"ID: {device_id[:16]}…", font=ctk.CTkFont(size=11),
                     text_color=COLORS["text_secondary"]).pack(anchor="w", pady=(2, 0))
        self.signal_status = ctk.CTkLabel(
            header, text="", font=ctk.CTkFont(size=11),
            text_color=COLORS["text_secondary"]
        )
        self.signal_status.pack(anchor="w", pady=(4, 0))

        pair_row = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        pair_row.pack(fill="x", padx=14, pady=(12, 4))
        self.pair_btn = ctk.CTkButton(
            pair_row, text="Generează cod",
            fg_color=COLORS["accent"], hover_color=COLORS["accent_hover"],
            text_color="#000", height=36, corner_radius=8,
            command=self._gen_pair_code
        )
        self.pair_btn.pack(side="left", expand=True, fill="x", padx=(0, 4))
        self.join_btn = ctk.CTkButton(
            pair_row, text="Intră cu cod",
            fg_color=COLORS["accent_dark"], hover_color=COLORS["accent"],
            text_color="#fff", height=36, corner_radius=8,
            command=self._join_pair_code
        )
        self.join_btn.pack(side="left", expand=True, fill="x", padx=(4, 0))

        grp_row = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        grp_row.pack(fill="x", padx=14, pady=(4, 4))
        self.create_group_btn = ctk.CTkButton(
            grp_row, text="Creează grup",
            fg_color=COLORS["accent_dark"], hover_color=COLORS["accent"],
            text_color="#fff", height=32, corner_radius=8,
            command=self._create_group
        )
        self.create_group_btn.pack(side="left", expand=True, fill="x", padx=(0, 4))
        self.join_group_btn = ctk.CTkButton(
            grp_row, text="Intră în grup",
            fg_color=COLORS["bg_card"], hover_color=COLORS["border"],
            text_color=COLORS["text"], height=32, corner_radius=8,
            command=self._join_group
        )
        self.join_group_btn.pack(side="left", expand=True, fill="x", padx=(4, 0))

        self.on_create_group = None
        self.on_join_group = None
        self.on_gen_pair = None
        self.on_join_pair = None
        self.on_clear_chat = None
        self.on_delete_contact = None

        self.add_btn = ctk.CTkButton(
            self.sidebar, text="+ Adaugă (ID / IP avansat)",
            fg_color=COLORS["bg_card"], hover_color=COLORS["border"],
            text_color=COLORS["text_secondary"], height=32, corner_radius=8,
            command=self._show_add_contact
        )
        self.add_btn.pack(padx=14, pady=(6, 6), fill="x")

        self.contacts_frame = ctk.CTkScrollableFrame(
            self.sidebar, fg_color="transparent",
            label_text="Contacte", label_text_color=COLORS["text_secondary"]
        )
        self.contacts_frame.pack(fill="both", expand=True, padx=10, pady=(0, 8))

        self.logout_btn = ctk.CTkButton(
            self.sidebar, text="DECONECTARE",
            fg_color=COLORS["danger"], hover_color="#C9184A",
            text_color="#FFFFFF", height=42, corner_radius=8,
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self._do_logout
        )
        self.logout_btn.pack(side="bottom", padx=14, pady=(8, 16), fill="x")

        # Chat area
        self.chat_area = ctk.CTkFrame(self, fg_color=COLORS["bg_dark"], corner_radius=0)
        self.chat_area.grid(row=0, column=1, sticky="nsew")
        self.chat_area.grid_rowconfigure(1, weight=1)
        self.chat_area.grid_columnconfigure(0, weight=1)
        self.bind("<Configure>", self._on_win_configure)

        self.chat_header = ctk.CTkFrame(self.chat_area, height=58, fg_color=COLORS["bg_secondary"], corner_radius=0)
        self.chat_header.grid(row=0, column=0, sticky="ew")
        self.chat_header.grid_propagate(False)

        self.chat_title = ctk.CTkLabel(
            self.chat_header, text="Selectează un contact",
            font=ctk.CTkFont(size=16, weight="bold"), text_color=COLORS["text"]
        )
        self.chat_title.pack(side="left", padx=20, pady=14)

        # Acțiuni chat: șterge conversație / șterge contact
        head_actions = ctk.CTkFrame(self.chat_header, fg_color="transparent")
        head_actions.pack(side="right", padx=12)
        self.clear_chat_btn = ctk.CTkButton(
            head_actions, text="Șterge conversația", width=130, height=28, corner_radius=6,
            fg_color=COLORS["bg_card"], hover_color=COLORS["border"],
            text_color=COLORS["text_secondary"], font=ctk.CTkFont(size=11),
            command=self._clear_chat
        )
        self.clear_chat_btn.pack(side="left", padx=4)
        self.delete_contact_btn = ctk.CTkButton(
            head_actions, text="Șterge chat", width=100, height=28, corner_radius=6,
            fg_color=COLORS["bg_card"], hover_color="#3a1520",
            text_color=COLORS["danger"], font=ctk.CTkFont(size=11),
            command=self._delete_contact
        )
        self.delete_contact_btn.pack(side="left", padx=4)

        self.status_dot = ctk.CTkLabel(
            self.chat_header, text="", text_color=COLORS["text_secondary"],
            font=ctk.CTkFont(size=12)
        )
        self.status_dot.pack(side="right", padx=8)

        self.messages_frame = ctk.CTkScrollableFrame(self.chat_area, fg_color=COLORS["bg_dark"])
        self.messages_frame.grid(row=1, column=0, sticky="nsew", padx=12, pady=8)
        # Keep the newest message visible after widgets have completed layout.
        self._scroll_job = None
        self.messages_frame.bind("<Configure>", lambda _e: None)
        self.after(100, self._bind_message_scroll)

        input_frame = ctk.CTkFrame(self.chat_area, fg_color=COLORS["bg_secondary"], height=72, corner_radius=0)
        input_frame.grid(row=2, column=0, sticky="ew")
        input_frame.grid_propagate(False)

        self.attach_btn = ctk.CTkButton(
            input_frame, text="📎", width=42, height=42, corner_radius=8,
            fg_color=COLORS["bg_card"], hover_color=COLORS["border"],
            text_color=COLORS["text"], font=ctk.CTkFont(size=18),
            command=self._attach_file
        )
        self.attach_btn.pack(side="left", padx=(12, 4), pady=15)

        self.voice_btn = ctk.CTkButton(
            input_frame, text="🎙️", width=42, height=42, corner_radius=8,
            fg_color=COLORS["bg_card"], hover_color=COLORS["border"],
            text_color=COLORS["text"], font=ctk.CTkFont(size=18),
            command=self._toggle_voice_recording
        )
        self.voice_btn.pack(side="left", padx=(0, 4), pady=15)

        self.emoji_btn = ctk.CTkButton(
            input_frame, text="😀", width=42, height=42, corner_radius=8,
            fg_color=COLORS["bg_card"], hover_color=COLORS["border"],
            text_color=COLORS["text"], font=ctk.CTkFont(size=18),
            command=self._toggle_emoji_picker
        )
        self.emoji_btn.pack(side="left", padx=(0, 6), pady=15)
        self._emoji_popup = None

        self.msg_entry = ctk.CTkEntry(
            input_frame, placeholder_text="Scrie un mesaj… (Enter = trimite)",
            fg_color=COLORS["bg_card"], border_color=COLORS["border"],
            text_color=COLORS["text"], height=42, corner_radius=8,
            font=ctk.CTkFont(size=14)
        )
        self.msg_entry.pack(side="left", fill="x", expand=True, padx=(0, 10), pady=15)
        self.msg_entry.bind("<Return>", lambda e: self._send_message())
        self.msg_entry.bind("<Key>", lambda e: self._on_key_typing())

        self.send_btn = ctk.CTkButton(
            input_frame, text="Trimite",
            fg_color=COLORS["accent"], hover_color=COLORS["accent_hover"],
            text_color="#000", width=100, height=42, corner_radius=8,
            command=self._send_message
        )
        self.send_btn.pack(side="right", padx=(0, 16), pady=15)

        self.on_send_message: Optional[Callable] = None
        self.on_send_file: Optional[Callable] = None
        self.on_voice_record: Optional[Callable] = None
        self.on_add_contact: Optional[Callable] = None
        self.on_logout: Optional[Callable] = None
        self.on_save_signal: Optional[Callable] = None
        self.on_open_file: Optional[Callable] = None
        self.on_typing: Optional[Callable] = None

    def set_codes(self, ipv4: str, ipv6: str):
        self.code_ipv4 = ipv4 or ""
        self.code_ipv6 = ipv6 or ""

    def set_signal_config(self, host: str, port: int, use_tls: bool = True, ca_file: str = "", insecure: bool = False,
                           proxy_list: str = "", proxy_rotate: int = 0, socks_host: str = "", socks_port: str = ""):
        self.signal_host = host or ""
        self.signal_port = port
        self.signal_tls = use_tls
        self.signal_ca = ca_file or ""
        self.signal_tls_insecure = insecure
        self.proxy_list_text = proxy_list or ""
        self.proxy_rotate_sec = int(proxy_rotate or 0)
        self.socks_host_ui = socks_host or ""
        self.socks_port_ui = str(socks_port or "")

    def set_signal_status(self, text: str, ok: bool = False):
        color = COLORS["success"] if ok else COLORS["text_secondary"]
        prefix = "● " if ok else "○ "
        t = text if text.startswith("●") or text.startswith("○") else prefix + text
        self.signal_status.configure(text=t, text_color=color)

    def _open_settings(self):
        SettingsWindow(
            self,
            device_id=self.device_id,
            code_ipv4=self.code_ipv4,
            code_ipv6=self.code_ipv6,
            signal_host=self.signal_host,
            signal_port=self.signal_port,
            on_save_signal=self._on_save_signal,
            use_tls=getattr(self, "signal_tls", True),
            ca_file=getattr(self, "signal_ca", "") or "",
            tls_insecure=getattr(self, "signal_tls_insecure", False),
            proxy_list=getattr(self, "proxy_list_text", "") or "",
            proxy_rotate=getattr(self, "proxy_rotate_sec", 0) or 0,
            socks_host=getattr(self, "socks_host_ui", "") or "",
            socks_port=getattr(self, "socks_port_ui", "") or ""
        )

    def _on_save_signal(self, host: str, port: int, use_tls: bool = True, ca_file: str = "", insecure: bool = False,
                         socks_host: str = "", socks_port: str = "", proxy_list: str = "", proxy_rotate: int = 0):
        self.signal_host = host
        self.signal_port = port
        self.signal_tls = use_tls
        self.signal_ca = ca_file
        self.signal_tls_insecure = insecure
        self.proxy_list_text = proxy_list
        self.proxy_rotate_sec = proxy_rotate
        self.socks_host_ui = socks_host
        self.socks_port_ui = socks_port
        if self.on_save_signal:
            self.on_save_signal(host, port, use_tls, ca_file, insecure, socks_host, socks_port, proxy_list, proxy_rotate)

    def _create_group(self):
        if self.on_create_group:
            self.on_create_group()
        else:
            self.show_info("Grup: callback neconectat – recompilează app")

    def _join_group(self):
        if self.on_join_group:
            self.on_join_group()
        else:
            self.show_info("Grup: callback neconectat – recompilează app")

    def add_group_to_list(self, name: str, group_id: str, command=None):
        row = ctk.CTkFrame(self.contacts_frame, fg_color="transparent", height=44)
        row.pack(fill="x", pady=2, padx=2)
        av = ctk.CTkLabel(
            row, text="👥", width=32, height=32, corner_radius=16,
            fg_color=COLORS["bg_card"], text_color=COLORS["accent"],
            font=ctk.CTkFont(size=14)
        )
        av.pack(side="left", padx=(4, 8))
        btn = ctk.CTkButton(
            row, text=name, fg_color="transparent",
            hover_color=COLORS["bg_card"], text_color=COLORS["accent"],
            anchor="w", height=36, font=ctk.CTkFont(size=13),
            command=command
        )
        btn.pack(side="left", fill="x", expand=True)

    def _gen_pair_code(self):
        if self.on_gen_pair:
            self.on_gen_pair()

    def _join_pair_code(self):
        dialog = ctk.CTkInputDialog(text="Introdu codul de 6 caractere primit de la prieten", title="Intră cu cod")
        value = dialog.get_input()
        if value and self.on_join_pair:
            self.on_join_pair(value.strip().upper())

    def show_pair_code(self, code: str):
        win = ctk.CTkToplevel(self)
        win.title("Codul tău")
        win.geometry("360x200")
        win.configure(fg_color=COLORS["bg_dark"])
        win.transient(self)
        ctk.CTkLabel(win, text="Dă acest cod prietenului", text_color=COLORS["text_secondary"]).pack(pady=(24, 8))
        ctk.CTkLabel(win, text=code, font=ctk.CTkFont(size=32, weight="bold"), text_color=COLORS["accent"]).pack(pady=8)
        def copy():
            self.clipboard_clear()
            self.clipboard_append(code)
        ctk.CTkButton(win, text="Copiază", command=copy, fg_color=COLORS["accent_dark"]).pack(pady=12)

    def _show_add_contact(self):
        dialog = ctk.CTkInputDialog(
            text="Lipește Device ID sau cod complet\n(ex: abc123… sau abc123…@IP:port)",
            title="Adaugă contact"
        )
        value = dialog.get_input()
        if value and self.on_add_contact:
            self.on_add_contact(value.strip())

    def _on_key_typing(self):
        if self.on_typing:
            self.on_typing()


    # Emoji frecvente (Unicode – merge pe fir ca text UTF-8)
    _EMOJI_SET = (
        "😀 😃 😄 😁 😅 😂 🤣 😊 😇 🙂 😉 😍 🥰 😘 😗 😋 😜 🤪 😝 🤑 "
        "🤗 🤭 🤫 🤔 🤐 😐 😑 😶 🙄 😏 😣 😥 😮 😯 😪 😫 🥱 😴 😌 😛 "
        "😷 🤒 🤕 🤢 🤮 🥵 🥶 🥴 😵 🤯 🤠 🥳 😎 🤓 🧐 😕 😟 🙁 ☹️ 😮 "
        "👍 👎 👋 ✌️ 🤞 🤟 🤘 👌 🤌 👏 🙌 🤝 🙏 💪 ❤️ 🧡 💛 💚 💙 💜 "
        "🖤 🤍 💔 ❣️ 💕 💞 🔥 ⭐ ✨ 🎉 🎊 ✅ ❌ ⚠️ 💯 🚀 💻 🔒 🔑 💬 "
        "🇷🇴 🌙 ☀️ ⚡ 🌈 🍕 ☕ 🍺 🏠 📱 🎮 🎧 📸 🐱 🐶 🦊 🐻 🐼 🦄 🌸"
    ).split()

    def _toggle_emoji_picker(self):
        if self._emoji_popup is not None:
            try:
                self._emoji_popup.destroy()
            except Exception:
                pass
            self._emoji_popup = None
            return
        pop = ctk.CTkToplevel(self)
        pop.title("Emoji")
        pop.geometry("360x280")
        pop.configure(fg_color=COLORS["bg_secondary"])
        pop.transient(self)
        pop.resizable(True, True)
        try:
            pop.attributes("-topmost", True)
        except Exception:
            pass
        # poziție lângă buton
        try:
            x = self.winfo_rootx() + 40
            y = self.winfo_rooty() + self.winfo_height() - 340
            pop.geometry(f"360x280+{x}+{y}")
        except Exception:
            pass
        frame = ctk.CTkScrollableFrame(pop, fg_color=COLORS["bg_dark"])
        frame.pack(fill="both", expand=True, padx=8, pady=8)
        row_f = None
        for i, em in enumerate(self._EMOJI_SET):
            if i % 8 == 0:
                row_f = ctk.CTkFrame(frame, fg_color="transparent")
                row_f.pack(fill="x", pady=2)
            b = ctk.CTkButton(
                row_f, text=em, width=36, height=36, corner_radius=6,
                fg_color=COLORS["bg_card"], hover_color=COLORS["accent_dark"],
                font=ctk.CTkFont(size=16),
                command=lambda e=em: self._insert_emoji(e)
            )
            b.pack(side="left", padx=2)
        self._emoji_popup = pop
        pop.protocol("WM_DELETE_WINDOW", self._toggle_emoji_picker)

    def _insert_emoji(self, emoji: str):
        try:
            self.msg_entry.insert("end", emoji)
            self.msg_entry.focus_set()
        except Exception:
            pass

    def _send_message(self):
        text = self.msg_entry.get().strip()
        if text and self.on_send_message:
            self.on_send_message(text)
            self.msg_entry.delete(0, "end")

    def _clear_chat(self):
        if self.on_clear_chat:
            self.on_clear_chat()

    def _delete_contact(self):
        if self.on_delete_contact:
            self.on_delete_contact()

    def clear_contacts_list(self):
        for w in self.contacts_frame.winfo_children():
            w.destroy()
        self._contact_btns = {}

    def _do_logout(self):
        if self.on_logout:
            self.on_logout()

    def _attach_file(self):
        path = filedialog.askopenfilename(
            title="Alege fișier",
            filetypes=[
                ("Toate fișierele", "*.*"),
                ("Imagini", "*.png *.jpg *.jpeg *.gif *.bmp *.webp"),
                ("Video", "*.mp4 *.mkv *.avi *.mov *.webm"),
                ("Audio", "*.mp3 *.wav *.m4a *.aac *.flac *.ogg *.opus *.wma *.3gp"),
                ("Documente", "*.txt *.doc *.docx *.pdf *.odt *.rtf *.csv"),
            ]
        )
        if path and self.on_send_file:
            self.on_send_file(path)

    def _toggle_voice_recording(self):
        if self.on_voice_record:
            self.on_voice_record()

    def set_voice_recording(self, recording: bool):
        self.voice_btn.configure(
            text="■" if recording else "🎙️",
            fg_color=COLORS["danger"] if recording else COLORS["bg_card"],
        )

    def _on_win_configure(self, event=None):
        """Pe ecrane mici: wrap mesaje mai îngust."""
        try:
            w = self.winfo_width()
            if w < 100:
                return
            # sidebar ~ fixed; chat width approx
            chat_w = max(200, w - getattr(self, "_sidebar_w", 260) - 40)
            self._bubble_wrap = min(520, max(180, chat_w - 80))
        except Exception:
            self._bubble_wrap = 420

    def _bind_message_scroll(self):
        """Permite control manual fluid; auto-scroll doar jos / la trimitere."""
        try:
            canvas = self.messages_frame._parent_canvas
            def _mw(e):
                self._on_user_scroll()
            canvas.bind("<MouseWheel>", _mw, add="+")
            canvas.bind("<Button-4>", _mw, add="+")
            canvas.bind("<Button-5>", _mw, add="+")
            canvas.bind("<B1-Motion>", lambda e: self._on_user_scroll(), add="+")
            canvas.bind("<ButtonRelease-1>", lambda e: self._on_user_scroll(), add="+")
        except Exception:
            pass

    def _is_near_bottom(self, threshold: float = 0.08) -> bool:
        """True dacă utilizatorul e aproape de jos (sau nu a scrollat deloc)."""
        try:
            canvas = self.messages_frame._parent_canvas
            top, bottom = canvas.yview()
            return bottom >= 1.0 - threshold
        except Exception:
            return True

    def _schedule_scroll_bottom(self, force: bool = False):
        """Auto-scroll doar dacă ești deja jos, sau force=True (mesaj trimis de tine)."""
        try:
            if not force and not getattr(self, "_stick_to_bottom", True):
                if not self._is_near_bottom():
                    return
            if self._scroll_job is not None:
                self.after_cancel(self._scroll_job)
            self._scroll_job = self.after_idle(self._scroll_messages_to_bottom)
        except Exception:
            self._scroll_job = None

    def _scroll_messages_to_bottom(self):
        self._scroll_job = None
        try:
            canvas = self.messages_frame._parent_canvas
            canvas.update_idletasks()
            canvas.configure(scrollregion=canvas.bbox("all"))
            canvas.yview_moveto(1.0)
            self._stick_to_bottom = True
        except Exception:
            pass

    def _on_user_scroll(self, event=None):
        """Utilizatorul controlează bara – oprim auto-scroll dacă nu e jos."""
        try:
            self._stick_to_bottom = self._is_near_bottom()
        except Exception:
            self._stick_to_bottom = False

    def add_file_bubble(self, filename: str, filepath: str, is_outgoing: bool, is_image: bool = False):
        bubble_color = COLORS["accent_dark"] if is_outgoing else COLORS["bg_card"]
        frame = ctk.CTkFrame(self.messages_frame, fg_color="transparent")
        frame.pack(fill="x", pady=4, padx=4)

        inner = ctk.CTkFrame(frame, fg_color=bubble_color, corner_radius=12)
        if is_outgoing:
            inner.pack(side="right", padx=4)
        else:
            inner.pack(side="left", padx=4)

        # Preview imagine
        if is_image and filepath and Path(filepath).is_file():
            try:
                img = Image.open(filepath)
                img.thumbnail((280, 200))
                ctk_img = ctk.CTkImage(light_image=img, dark_image=img, size=img.size)
                img_label = ctk.CTkLabel(inner, image=ctk_img, text="")
                img_label.image = ctk_img
                img_label.pack(padx=8, pady=(8, 2))
            except Exception:
                pass

        lower = filename.lower()
        if is_image or lower.endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp")):
            icon = "🖼️"
        elif lower.endswith((".mp4", ".mkv", ".avi", ".mov", ".webm")):
            icon = "🎬"
        elif lower.endswith((".mp3", ".wav", ".m4a", ".aac", ".flac", ".ogg", ".opus", ".wma", ".3gp")):
            icon = "🎵"
        else:
            icon = "📄"

        row = ctk.CTkFrame(inner, fg_color="transparent")
        row.pack(fill="x", padx=8, pady=(4, 8))

        lbl = ctk.CTkLabel(row, text=f"{icon}  {filename}", text_color="#FFFFFF",
                           font=ctk.CTkFont(size=12))
        lbl.pack(side="left")

        def open_it(p=filepath):
            if self.on_open_file:
                self.on_open_file(p)

        btn = ctk.CTkButton(
            row, text="Redă audio" if icon == "🎵" else "Deschide",
            width=82 if icon == "🎵" else 70, height=26, corner_radius=6,
            fg_color=COLORS["accent"], hover_color=COLORS["accent_hover"],
            text_color="#000", font=ctk.CTkFont(size=11), command=open_it
        )
        btn.pack(side="right", padx=(8, 0))

        self._schedule_scroll_bottom(force=False)

    def set_typing(self, name: str = ""):
        if name:
            self.status_dot.configure(text=f"{name} scrie…", text_color=COLORS["warning"])
        else:
            # restore will be done by set_chat_title
            pass

    def show_transfer_progress(self, text: str):
        self.show_info(text)

    def add_contact_to_list(self, display_name: str, device_id: str, command: Callable):
        label = (display_name or "").strip() or f"Peer-{(device_id or '')[:8]}"
        if not hasattr(self, "_contact_btns"):
            self._contact_btns = {}
        if device_id in self._contact_btns:
            try:
                self._contact_btns[device_id].configure(text=label, command=command)
                return
            except Exception:
                pass
        btn = ctk.CTkButton(
            self.contacts_frame, text=label,
            fg_color="transparent", hover_color=COLORS["bg_card"],
            text_color=COLORS["text"], anchor="w", height=40,
            command=command
        )
        btn.pack(fill="x", pady=2)
        self._contact_btns[device_id] = btn

    def set_chat_title(self, name: str, online: bool = False):
        self.chat_title.configure(text=name)
        if online:
            self.status_dot.configure(text="● online", text_color=COLORS["success"])
        else:
            self.status_dot.configure(text="○ offline", text_color=COLORS["text_secondary"])

    def add_message_bubble(self, text: str, is_outgoing: bool):
        bubble_color = COLORS["accent_dark"] if is_outgoing else COLORS["bg_card"]
        frame = ctk.CTkFrame(self.messages_frame, fg_color="transparent")
        frame.pack(fill="x", pady=3, padx=4)
        bubble = ctk.CTkLabel(
            frame, text=text, wraplength=getattr(self, "_bubble_wrap", 420),
            fg_color=bubble_color, text_color="#FFFFFF",
            corner_radius=12, padx=14, pady=8,
            font=ctk.CTkFont(size=13), justify="left"
        )
        if is_outgoing:
            bubble.pack(side="right")
            # doar când trimiți tu – coboară bara
            self._stick_to_bottom = True
            self._schedule_scroll_bottom(force=True)
        else:
            bubble.pack(side="left")
            # mesaj primit: coboară doar dacă erai deja jos
            self._schedule_scroll_bottom(force=False)

    def clear_messages(self):
        for w in self.messages_frame.winfo_children():
            w.destroy()

    def show_info(self, text: str):
        text = (text or "").strip()
        if not text:
            return
        # Nu repeta același mesaj de sistem consecutiv (ex. Contact negăsit în buclă)
        if getattr(self, "_last_info_text", None) == text:
            return
        self._last_info_text = text
        frame = ctk.CTkFrame(self.messages_frame, fg_color="transparent")
        frame.pack(fill="x", pady=6)
        ctk.CTkLabel(frame, text=text, text_color=COLORS["text_secondary"],
                     font=ctk.CTkFont(size=11, slant="italic")).pack()
        self._schedule_scroll_bottom()
