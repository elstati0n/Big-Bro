"""
setup_window.py – Big Bro configuration window (premium redesign).
"""
import os, sys
import tkinter as tk
from tkinter import ttk, messagebox

import psutil

from config import (ICON_PATH, THEME, APP_DIR, LIST_DIR,
                    VIRUSTOTAL_API_KEY_FILE, ABUSEIPDB_API_KEY_FILE,
                    TELEGRAM_BOT_TOKEN_FILE, TELEGRAM_BOT_CHAT_ID_FILE)
from api_manager import load_key, save_key, delete_key

_MASK = "●" * 30




import platform as _platform

def _set_icon(win):
    """Set window icon cross-platform."""
    if not os.path.exists(ICON_PATH):
        return
    try:
        if _platform.system() == "Windows":
            win.iconbitmap(ICON_PATH)
        else:
            from PIL import Image as _I, ImageTk as _IT
            img = _I.open(ICON_PATH).convert("RGBA").resize((32, 32))
            _ph  = _IT.PhotoImage(img)
            win._icon_ref = _ph
            win.iconphoto(True, _ph)
    except Exception:
        pass

class SetupWindow:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Big Bro")
        _set_icon(self.root)
        w, h = 540, 690
        sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
        root.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")
        root.configure(bg=THEME["bg"])
        root.resizable(False, False)
        root.protocol("WM_DELETE_WINDOW", self._close)
        self._build()

    def _build(self):
        T = THEME
        tk.Frame(self.root, bg=T["accent"], height=3).pack(fill="x")

        # Logo row
        top = tk.Frame(self.root, bg=T["bg"])
        top.pack(fill="x", padx=28, pady=(22, 4))
        try:
            from PIL import Image as _Img, ImageTk as _ITk
            _ico = _Img.open(ICON_PATH).resize((48, 48), _Img.LANCZOS)
            self._logo_img = _ITk.PhotoImage(_ico)
            tk.Label(top, image=self._logo_img, bg=T["bg"]).pack(side="left")
        except Exception:
            tk.Label(top, text="👁", font=("Segoe UI Emoji", 30),
                     bg=T["bg"], fg=T["accent"]).pack(side="left")
        tf = tk.Frame(top, bg=T["bg"])
        tf.pack(side="left", padx=12)
        tk.Label(tf, text="BIG BRO", font=("Segoe UI", 22, "bold"),
                 bg=T["bg"], fg=T["text"]).pack(anchor="w")
        tk.Label(tf, text="Network Connection Monitor",
                 font=("Segoe UI", 9), bg=T["bg"],
                 fg=T["dim"]).pack(anchor="w")

        tk.Frame(self.root, bg=T["bg3"], height=1).pack(fill="x", padx=28, pady=(12, 16))

        # ── Scrollable content ───────────────────────────────────────────
        cvs = tk.Canvas(self.root, bg=T["bg"], highlightthickness=0, bd=0)
        sb  = tk.Scrollbar(self.root, orient="vertical", command=cvs.yview)
        cvs.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        cvs.pack(fill="both", expand=True, padx=(28, 0))

        card = tk.Frame(cvs, bg=T["bg"])
        cw   = cvs.create_window((0, 0), window=card, anchor="nw")
        cvs.bind("<Configure>",   lambda e: cvs.itemconfig(cw, width=e.width))
        card.bind("<Configure>",  lambda e: cvs.configure(scrollregion=cvs.bbox("all")))

        # mouse-wheel scroll
        def _scroll(e): cvs.yview_scroll(int(-1*(e.delta/120)), "units")
        cvs.bind_all("<MouseWheel>", _scroll)

        # ── Adapter selector ────────────────────────────────────────────
        self._section(card, "NETWORK INTERFACE")
        af = tk.Frame(card, bg=T["bg2"], padx=14, pady=12)
        af.pack(fill="x", pady=(4, 16))
        self.adapters    = list(psutil.net_if_addrs().keys())
        self.adapter_var = tk.StringVar(value=self.adapters[0] if self.adapters else "")
        sty = ttk.Style(); sty.theme_use("clam")
        sty.configure("P.TCombobox",
                       fieldbackground=T["bg3"],
                       background=T["bg3"],
                       foreground=T["text"],
                       arrowcolor=T["accent"],
                       borderwidth=0, selectbackground=T["bg3"],
                       selectforeground=T["text"])
        sty.map("P.TCombobox",
                fieldbackground=[("readonly", T["bg3"])],
                foreground=[("readonly", T["text"])],
                selectbackground=[("readonly", T["bg3"])],
                selectforeground=[("readonly", T["text"])])
        ttk.Combobox(af, textvariable=self.adapter_var, values=self.adapters,
                     font=("Segoe UI", 11), state="readonly",
                     style="P.TCombobox").pack(fill="x", ipady=7)

        # ── API key entries ──────────────────────────────────────────────
        self.vt_ent     = self._key_row(card, "VIRUSTOTAL API KEY",
                                         VIRUSTOTAL_API_KEY_FILE, self._sv_vt, self._dv_vt)
        self.abuse_ent  = self._key_row(card, "ABUSEIPDB API KEY",
                                         ABUSEIPDB_API_KEY_FILE, self._sv_ab, self._dv_ab)
        self.tgt_ent    = self._key_row(card, "TELEGRAM BOT TOKEN",
                                         TELEGRAM_BOT_TOKEN_FILE, self._sv_tt, self._dv_tt)
        self.cid_ent    = self._key_row(card, "TELEGRAM CHAT ID",
                                         TELEGRAM_BOT_CHAT_ID_FILE, self._sv_ci, self._dv_ci)

        # ── Start button (fixed at bottom, outside canvas) ───────────────
        tk.Frame(self.root, bg=T["bg3"], height=1).pack(fill="x", padx=0)
        bot = tk.Frame(self.root, bg=T["bg"])
        bot.pack(fill="x", padx=28, pady=16)
        tk.Button(bot, text="▶   START MONITORING",
                  font=("Segoe UI", 12, "bold"),
                  bg=T["accent"], fg="#000000",
                  activebackground=T["accent2"], activeforeground="#000",
                  relief="flat", cursor="hand2",
                  padx=20, pady=13,
                  command=self._start).pack(fill="x")

    def _section(self, parent, text):
        T = THEME
        f = tk.Frame(parent, bg=T["bg"])
        f.pack(fill="x", pady=(0, 0))
        tk.Label(f, text=text, font=("Segoe UI", 7, "bold"),
                 bg=T["bg"], fg=T["dim"], padx=2).pack(side="left")
        tk.Frame(f, bg=T["bg3"], height=1).pack(side="left", fill="x",
                                                       expand=True, padx=(8, 0))

    def _key_row(self, parent, label, path, save_cb, del_cb):
        T = THEME
        self._section(parent, label)
        c = tk.Frame(parent, bg=T["bg2"], padx=14, pady=12)
        c.pack(fill="x", pady=(4, 16))

        e = tk.Entry(c, font=("Consolas", 11),
                     bg=T["bg3"], fg=T["text"],
                     insertbackground=T["accent"],
                     relief="flat", bd=0,
                     highlightthickness=1,
                     highlightbackground=T["bg3"],
                     highlightcolor=T["accent"])
        e.pack(fill="x", ipady=7)
        if load_key(path): e.insert(0, _MASK)

        tk.Frame(c, bg=T["accent"], height=1).pack(fill="x")

        bf = tk.Frame(c, bg=T["bg2"])
        bf.pack(fill="x", pady=(8, 0))
        self._btn(bf, "💾  Save",   save_cb, T["green"]).pack(side="left", padx=(0,8))
        self._btn(bf, "🗑  Delete", del_cb,  "#3a0a0a"  ).pack(side="left")
        return e

    def _btn(self, parent, text, cmd, bg):
        T = THEME
        return tk.Button(parent, text=text, font=("Segoe UI", 9),
                         bg=bg, fg=T["text"],
                         activebackground=bg, activeforeground=T["text"],
                         relief="flat", cursor="hand2",
                         padx=12, pady=5, command=cmd)

    def _do_save(self, e, path, label):
        v = e.get().strip()
        if not v or v == _MASK:
            messagebox.showwarning("Warning", f"{label} cannot be empty."); return
        save_key(v, path)
        e.delete(0, tk.END); e.insert(0, _MASK)
        messagebox.showinfo("Saved", f"{label} saved.")

    def _do_del(self, e, path, label):
        delete_key(path); e.delete(0, tk.END)
        messagebox.showinfo("Deleted", f"{label} deleted.")

    def _sv_vt(self):  self._do_save(self.vt_ent,    VIRUSTOTAL_API_KEY_FILE,   "VirusTotal API Key")
    def _dv_vt(self):  self._do_del(self.vt_ent,     VIRUSTOTAL_API_KEY_FILE,   "VirusTotal API Key")
    def _sv_ab(self):  self._do_save(self.abuse_ent,  ABUSEIPDB_API_KEY_FILE,    "AbuseIPDB API Key")
    def _dv_ab(self):  self._do_del(self.abuse_ent,   ABUSEIPDB_API_KEY_FILE,    "AbuseIPDB API Key")
    def _sv_tt(self):  self._do_save(self.tgt_ent,    TELEGRAM_BOT_TOKEN_FILE,   "Telegram Bot Token")
    def _dv_tt(self):  self._do_del(self.tgt_ent,     TELEGRAM_BOT_TOKEN_FILE,   "Telegram Bot Token")
    def _sv_ci(self):  self._do_save(self.cid_ent,    TELEGRAM_BOT_CHAT_ID_FILE, "Telegram Chat ID")
    def _dv_ci(self):  self._do_del(self.cid_ent,     TELEGRAM_BOT_CHAT_ID_FILE, "Telegram Chat ID")

    def _start(self):
        adapter = self.adapter_var.get()
        if not adapter or adapter not in self.adapters:
            messagebox.showerror("Error", "Select a valid network interface."); return
        self.root.withdraw()
        from monitor_window import ConnectionMonitorApp
        win = tk.Toplevel(self.root)
        ConnectionMonitorApp(win, adapter, back_cb=self.root.deiconify)

    def _close(self):
        self.root.destroy(); sys.exit(0)
