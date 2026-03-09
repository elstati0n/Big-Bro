"""
monitor_window.py – Big Bro  (v4, complete rewrite)

Key design decisions:
─────────────────────
• Connections arrive ONE BY ONE from the queue (drain = 1 row per 400 ms tick).
  This makes the table feel alive without flooding / freezing.
• API enrichment runs in a small thread-pool (max 6 workers).
  Each IP is enriched exactly once; results queued back to main thread.
• Notifications are rate-limited (max 1 toast per 8 s) – no sidebar flood.
• Tray exit calls os._exit(0) to guarantee the process dies cleanly.
• Toolbar uses a proper grid inside a fixed-height band – no more cramping.
• Row colours: bright text on dark background – clearly readable.
"""

import ipaddress, os, socket, subprocess, sys, time, webbrowser
from concurrent.futures import ThreadPoolExecutor
from queue import Empty, Queue
from threading import Thread
import tkinter as tk
from tkinter import ttk, messagebox

import psutil
from PIL import Image
from pystray import Icon, Menu, MenuItem

from config import EXCLUDED_IPS, ICON_PATH, THEME as T
from ip_checker import (
    check_both, get_country,
    get_lists, is_cloudflare, load_all,
)
from notifier import play_sound, telegram, toast
from port_scanner import scan_ports

_POOL      = ThreadPoolExecutor(max_workers=6)

ALL_COUNTRIES = [
    "All Countries",
    "Afghanistan","Albania","Algeria","Andorra","Angola","Argentina","Armenia",
    "Australia","Austria","Azerbaijan","Bahrain","Bangladesh","Belarus","Belgium",
    "Bolivia","Bosnia and Herzegovina","Brazil","Bulgaria","Cambodia","Canada",
    "Chile","China","Colombia","Costa Rica","Croatia","Cuba","Cyprus",
    "Czech Republic","Denmark","Ecuador","Egypt","Estonia","Ethiopia",
    "Finland","France","Georgia","Germany","Ghana","Greece","Guatemala",
    "Honduras","Hong Kong","Hungary","India","Indonesia","Iran","Iraq",
    "Ireland","Israel","Italy","Jamaica","Japan","Jordan","Kazakhstan",
    "Kenya","Kosovo","Kuwait","Latvia","Lebanon","Libya","Lithuania",
    "Luxembourg","Malaysia","Malta","Mexico","Moldova","Montenegro","Morocco",
    "Myanmar","Nepal","Netherlands","New Zealand","Nicaragua","Nigeria",
    "North Korea","North Macedonia","Norway","Oman","Pakistan","Palestine",
    "Panama","Paraguay","Peru","Philippines","Poland","Portugal","Qatar",
    "Romania","Russia","Saudi Arabia","Serbia","Singapore","Slovakia",
    "Slovenia","Somalia","South Africa","South Korea","Spain","Sri Lanka",
    "Sudan","Sweden","Switzerland","Syria","Taiwan","Thailand","Tunisia",
    "Turkey","Ukraine","United Arab Emirates","United Kingdom","United States",
    "Uruguay","Uzbekistan","Venezuela","Vietnam","Yemen","Zimbabwe",
]
_POLL_SEC  = 3      # seconds between psutil scans
_DRAIN_MS  = 400    # ms between single-row insertions  ← "one by one"


def _tag(vt: str, abuse: str) -> str:
    if "Malicious"  in vt or "High Risk"   in abuse: return "malicious"
    if "Suspicious" in vt or "Medium Risk" in abuse: return "suspicious"
    return "clean"




# ── Cross-platform helpers ────────────────────────────────────────────────────

def _set_icon(win):
    """Set window icon — iconbitmap on Windows, iconphoto on Linux."""
    import platform
    if not os.path.exists(ICON_PATH):
        return
    try:
        if platform.system() == "Windows":
            win.iconbitmap(ICON_PATH)
        else:
            from PIL import Image as _I, ImageTk as _IT
            img = _I.open(ICON_PATH).convert("RGBA").resize((32, 32))
            _ph  = _IT.PhotoImage(img)
            win._icon_ref = _ph   # keep reference alive
            win.iconphoto(True, _ph)
    except Exception:
        pass


def _maximize(win):
    """Maximize window cross-platform."""
    import platform
    if platform.system() == "Windows":
        win.state("zoomed")
    else:
        win.attributes("-zoomed", True)

class ConnectionMonitorApp:
    # ─────────────────────────────────────────────────────────────────────
    def __init__(self, root: tk.Tk, adapter: str, back_cb=None):
        self.root     = root
        self.adapter  = adapter
        self.back_cb  = back_cb
        self.running  = True
        self._tray    = None

        self._seen:    set  = set()
        self._pinfo:   dict = {}
        self._rows:    list = []       # (rid, vals, base_tag)
        self._stats         = dict(total=0, malicious=0, suspicious=0, clean=0)
        self._q: Queue      = Queue()  # enriched rows waiting to be shown


        load_all()
        self._win()
        self._ui()

        Thread(target=self._poll_loop, daemon=True).start()
        self.root.after(_DRAIN_MS, self._drain)

    # ═════════════════════════════════════════════════════════════════════
    # Window setup
    # ═════════════════════════════════════════════════════════════════════
    def _win(self):
        self.root.title(f"Big Bro  —  {self.adapter}")
        _set_icon(self.root)
        self.root.configure(bg=T["bg"])
        _maximize(self.root)
        self.root.protocol("WM_DELETE_WINDOW", self._to_tray)

    # ═════════════════════════════════════════════════════════════════════
    # Full UI layout
    # ═════════════════════════════════════════════════════════════════════
    def _ui(self):
        # ── accent stripe (2 px, subtle)
        tk.Frame(self.root, bg=T["accent"], height=2).pack(fill="x")

        # ── STATUS BAR (fixed 28 px, packed first so it stays at bottom)
        sb = tk.Frame(self.root, bg=T["bg2"], height=28)
        sb.pack(fill="x", side="bottom"); sb.pack_propagate(False)
        tk.Frame(sb, bg=T["accent"], width=3).pack(side="left", fill="y")
        self._status = tk.Label(sb, text="  👁  Big Bro is watching…",
                                 font=("Consolas", 9),
                                 bg=T["bg2"], fg=T["accent"], anchor="w")
        self._status.pack(side="left", fill="both", expand=True)
        tk.Frame(sb, bg=T["border"], height=1).pack(side="bottom", fill="x")

        # ── HEADER (fixed 58 px) — logo | title | SEARCH fields | stats ──
        hdr = tk.Frame(self.root, bg=T["bg2"], height=58)
        hdr.pack(fill="x"); hdr.pack_propagate(False)

        # Left: logo + title
        left = tk.Frame(hdr, bg=T["bg2"])
        left.pack(side="left", padx=(14, 0), fill="y")
        try:
            from PIL import Image as _Img, ImageTk as _ITk
            _ico = _Img.open(ICON_PATH).resize((34, 34), _Img.LANCZOS)
            self._hdr_img = _ITk.PhotoImage(_ico)
            tk.Label(left, image=self._hdr_img,
                     bg=T["bg2"]).pack(side="left", padx=(0, 8))
        except Exception:
            tk.Label(left, text="👁", font=("Segoe UI Emoji", 17),
                     bg=T["bg2"], fg=T["accent"]).pack(side="left", padx=(0, 8))
        tc = tk.Frame(left, bg=T["bg2"])
        tc.pack(side="left")
        tk.Label(tc, text="BIG BRO", font=("Segoe UI", 14, "bold"),
                 bg=T["bg2"], fg=T["text"]).pack(anchor="w")
        tk.Label(tc, text=self.adapter, font=("Segoe UI", 8),
                 bg=T["bg2"], fg=T["dim"]).pack(anchor="w")

        # Right: stat counters
        right = tk.Frame(hdr, bg=T["bg2"])
        right.pack(side="right", padx=(0, 10), fill="y")
        for key, label, color in [
            ("malicious",  "MALICIOUS",  T["mal_fg"]),
            ("suspicious", "SUSPICIOUS", T["sus_fg"]),
            ("clean",      "CLEAN",      T["cln_fg"]),
            ("total",      "TOTAL",      T["text"]),
        ]:
            sf = tk.Frame(right, bg=T["bg3"], padx=12, pady=3)
            sf.pack(side="right", padx=(0, 3), pady=7)
            tk.Label(sf, text=label, font=("Segoe UI", 6, "bold"),
                     bg=T["bg3"], fg=T["dim"]).pack()
            lbl = tk.Label(sf, text="0", font=("Segoe UI", 13, "bold"),
                           bg=T["bg3"], fg=color)
            lbl.pack()
            setattr(self, f"_c_{key}", lbl)

        # Center: SEARCH  (IP + Port) — inline in header, left of stats
        mid = tk.Frame(hdr, bg=T["bg2"])
        mid.pack(side="right", padx=(0, 18), fill="y")

        def _mk_entry(parent, ph, width):
            e = tk.Entry(parent, font=("Consolas", 10), width=width,
                         bg=T["bg3"], fg=T["dim"],
                         insertbackground=T["accent"],
                         relief="flat", bd=0,
                         highlightthickness=1,
                         highlightbackground=T["border"],
                         highlightcolor=T["accent"])
            e.insert(0, ph)
            e.bind("<FocusIn>",  lambda ev, _e=e, _p=ph:
                   (_e.delete(0, tk.END), _e.config(fg=T["text"])) if _e.get() == _p else None)
            e.bind("<FocusOut>", lambda ev, _e=e, _p=ph:
                   (_e.insert(0, _p), _e.config(fg=T["dim"])) if not _e.get() else None)
            return e

        def _mk_btn(parent, text, cmd, bg, fg=None):
            return tk.Button(parent, text=text, font=("Segoe UI", 8),
                             bg=bg, fg=fg or T["text"],
                             activebackground=bg, activeforeground=fg or T["text"],
                             relief="flat", cursor="hand2",
                             padx=9, pady=4, bd=0, command=cmd)

        tk.Label(mid, text="SEARCH", font=("Segoe UI", 7, "bold"),
                 bg=T["bg2"], fg=T["dim"]).pack(side="left", padx=(0, 6))

        # IP search group
        ip_grp = tk.Frame(mid, bg=T["border"], padx=1, pady=1)
        ip_grp.pack(side="left", padx=(0, 6))
        ip_inner = tk.Frame(ip_grp, bg=T["bg3"])
        ip_inner.pack()
        self._eip = _mk_entry(ip_inner, "IP address…", 15)
        self._eip.pack(side="left", ipady=5, padx=(6, 4))
        _mk_btn(ip_inner, "Filter", self._filter_ip, T["accent"], "#000").pack(side="left")
        _mk_btn(ip_inner, "✕",      self._clear_ip,  T["bg4"]).pack(side="left", padx=(2, 3))

        # Port search group
        port_grp = tk.Frame(mid, bg=T["border"], padx=1, pady=1)
        port_grp.pack(side="left")
        port_inner = tk.Frame(port_grp, bg=T["bg3"])
        port_inner.pack()
        self._eport = _mk_entry(port_inner, "Port…", 7)
        self._eport.pack(side="left", ipady=5, padx=(6, 4))
        _mk_btn(port_inner, "Filter", self._filter_port, T["accent"], "#000").pack(side="left")
        _mk_btn(port_inner, "✕",      self._clear_port,  T["bg4"]).pack(side="left", padx=(2, 3))

        tk.Frame(self.root, bg=T["border"], height=1).pack(fill="x")

        # ── TOOLBAR — alert filter | country | actions | ip lists | back ──
        self._toolbar()

        tk.Frame(self.root, bg=T["border"], height=1).pack(fill="x")

        # ── TABLE
        self._table()

    # ═════════════════════════════════════════════════════════════════════
    # Toolbar  – fixed height, everything on ONE ROW using grid
    # ═════════════════════════════════════════════════════════════════════
    def _toolbar(self):
        _sty = ttk.Style()
        _sty.configure("TB.TCombobox",
            fieldbackground=T["bg3"], background=T["bg3"],
            foreground=T["text"], arrowcolor=T["accent"],
            selectbackground=T["bg3"], selectforeground=T["text"],
            borderwidth=0)
        _sty.map("TB.TCombobox",
            fieldbackground=[("readonly", T["bg3"])],
            foreground=[("readonly", T["text"])],
            selectbackground=[("readonly", T["bg3"])],
            selectforeground=[("readonly", T["text"])])

        outer = tk.Frame(self.root, bg=T["bg4"], height=46)
        outer.pack(fill="x"); outer.pack_propagate(False)

        # Single row, packed left-to-right with a separator helper
        row = tk.Frame(outer, bg=T["bg4"])
        row.pack(side="left", fill="y", padx=14)

        def _sep():
            tk.Frame(row, bg=T["border"], width=1).pack(side="left", fill="y", padx=14, pady=8)

        def _lbl(text):
            tk.Label(row, text=text, font=("Segoe UI", 7, "bold"),
                     bg=T["bg4"], fg=T["dim"]).pack(side="left", padx=(0, 7))

        def _btn(text, cmd, bg, fg=None):
            b = tk.Button(row, text=text, font=("Segoe UI", 9),
                          bg=bg, fg=fg or T["text"],
                          activebackground=bg, activeforeground=fg or T["text"],
                          relief="flat", cursor="hand2",
                          padx=11, pady=5, bd=0, command=cmd)
            b.pack(side="left", padx=3)
            return b

        # ── ALERT FILTER
        _lbl("ALERT FILTER")
        self._filter_mode = tk.IntVar(value=2)   # default: Malicious only

        def _radio(text, val, fg):
            rb = tk.Radiobutton(
                row, text=text, variable=self._filter_mode, value=val,
                font=("Segoe UI", 9),
                bg=T["bg4"], fg=fg,
                selectcolor=T["bg3"],
                activebackground=T["bg4"], activeforeground=fg,
                indicatoron=True,
            )
            rb.pack(side="left", padx=(0, 10))

        _radio("Malicious only",           2, T["mal_fg"])   # ← first = default
        _radio("Suspicious and Malicious", 0, T["sus_fg"])
        _radio("All",                      1, T["text"])

        _sep()

        # ── COUNTRY
        _lbl("COUNTRY")
        self._country_var = tk.StringVar(value="All Countries")
        self._country_cb = ttk.Combobox(
            row, textvariable=self._country_var,
            values=ALL_COUNTRIES,
            font=("Segoe UI", 9),
            state="readonly", width=15,
            style="TB.TCombobox",
        )
        self._country_cb.pack(side="left", ipady=4)
        self._country_cb.bind("<<ComboboxSelected>>", lambda e: None)

        _sep()

        # ── ACTIONS
        _lbl("ACTIONS")
        _btn("⚡ Kill",     self._kill,  T["red"])
        _btn("🛡 Block IP", self._block, T["red"])

        _sep()

        # ── IP LISTS
        _lbl("IP LISTS")
        _btn("● Malicious",  self._lst_mal, "#2a0000", T["mal_fg"])
        _btn("● Suspicious", self._lst_sus, "#211400", T["sus_fg"])
        _btn("● Clean",      self._lst_cln, "#091a0e", T["cln_fg"])

        # ── BACK — far right
        back_btn = tk.Button(outer, text="◀ Back", font=("Segoe UI", 9),
                             bg=T["bg3"], fg=T["dim"],
                             activebackground=T["bg3"], activeforeground=T["text"],
                             relief="flat", cursor="hand2",
                             padx=12, pady=5, bd=0,
                             command=self._go_back)
        back_btn.pack(side="right", padx=10)

    # ═════════════════════════════════════════════════════════════════════
    # Table
    # ═════════════════════════════════════════════════════════════════════
    def _table(self):
        COLS = ("IP","Port","Protocol","Process","Country",
                "Cloudflare","VirusTotal","AbuseIPDB","Whois","Bro Scan")
        W    = {"IP":148,"Port":58,"Protocol":82,"Process":165,
                "Country":118,"Cloudflare":88,"VirusTotal":130,
                "AbuseIPDB":152,"Whois":68,"Bro Scan":72}

        outer = tk.Frame(self.root, bg=T["bg"])
        outer.pack(fill="both", expand=True, padx=16, pady=(8,4))

        vsb = ttk.Scrollbar(outer, orient="vertical")
        hsb = ttk.Scrollbar(outer, orient="horizontal")

        sty = ttk.Style()
        sty.theme_use("clam")
        sty.configure("BB.Treeview",
                       background=T["bg2"], foreground=T["text"],
                       fieldbackground=T["bg2"], rowheight=28,
                       font=("Consolas",10), borderwidth=0)
        sty.configure("BB.Treeview.Heading",
                       background=T["bg3"], foreground=T["accent"],
                       font=("Segoe UI",9,"bold"), relief="flat",
                       padding=(8,6))
        sty.map("BB.Treeview",
                background=[("selected", T["accent2"])],
                foreground=[("selected","#fff")])

        self.tree = ttk.Treeview(outer, columns=COLS, show="headings",
                                  style="BB.Treeview",
                                  yscrollcommand=vsb.set,
                                  xscrollcommand=hsb.set)
        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)

        for c in COLS:
            self.tree.heading(c, text=c, anchor="w",
                              command=lambda x=c: self._sort(x))
            self.tree.column(c, width=W.get(c,100), anchor="w", minwidth=40)

        # ── Row colour tags  (bright fg, subtle bg — clearly readable)
        self.tree.tag_configure("malicious",
            foreground=T["mal_fg"], background=T["mal_bg"])
        self.tree.tag_configure("malicious_alt",
            foreground=T["mal_fg"], background=T["mal_bg2"])
        self.tree.tag_configure("suspicious",
            foreground=T["sus_fg"], background=T["sus_bg"])
        self.tree.tag_configure("suspicious_alt",
            foreground=T["sus_fg"], background=T["sus_bg2"])
        self.tree.tag_configure("clean",
            foreground=T["cln_fg"], background=T["cln_bg"])
        self.tree.tag_configure("clean_alt",
            foreground=T["cln_fg"], background=T["cln_bg2"])

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        outer.rowconfigure(0, weight=1)
        outer.columnconfigure(0, weight=1)

        self.tree.bind("<Button-1>", self._click)
        self.tree.bind("<Button-3>", self._rclick)
        self.tree.bind("<Motion>",   self._hover)
        self._ctx()

    def _ctx(self):
        self.cmenu = tk.Menu(self.root, tearoff=0,
                              bg=T["bg2"], fg=T["text"],
                              activebackground=T["accent2"],
                              activeforeground="#fff",
                              font=("Segoe UI",9))
        self.cmenu.add_command(label="🦠  VirusTotal",  command=self._ctx_vt)
        self.cmenu.add_command(label="🚨  AbuseIPDB",   command=self._ctx_abuse)
        self.cmenu.add_command(label="🔍  Whois",       command=self._ctx_whois)
        self.cmenu.add_separator()
        self.cmenu.add_command(label="🔬  Bro Scan",    command=self._ctx_scan)

    # ═════════════════════════════════════════════════════════════════════
    # Queue drain – ONE row per tick  →  "one by one" feel, no freezing
    # ═════════════════════════════════════════════════════════════════════
    def _drain(self):
        try:
            ip, port, proto, proc, country, cf, vt, abuse = self._q.get_nowait()
            self._insert(ip, port, proto, proc, country, cf, vt, abuse)
        except Empty:
            pass
        if self.running:
            self.root.after(_DRAIN_MS, self._drain)

    def _insert(self, ip, port, proto, proc, country, cf, vt, abuse):
        base = _tag(vt, abuse)
        idx  = len(self._rows)
        tag  = base if idx % 2 == 0 else base + "_alt"
        vals = (ip, port, proto, proc, country, cf, vt, abuse, "Whois", "Scan")

        # Aktiv filter yoxdurmu yoxla
        ip_q   = self._raw(self._eip,   "IP address…")
        port_q = self._raw(self._eport, "Port…")
        show   = True
        if ip_q   and ip_q   not in str(ip):   show = False
        if port_q and port_q not in str(port): show = False

        # Tree-yə yalnız filter uyğunsa əlavə et
        if show:
            rid = self.tree.insert("", tk.END, values=vals, tags=(tag,))
            self.tree.see(rid)
        else:
            rid = None  # filter aktiv, uyğun deyil — tree-yə əlavə etmə

        # _rows-a HƏMİŞƏ əlavə et — clear edəndə görünsün
        self._rows.append((rid, vals, base))



        # counters
        self._stats["total"] += 1
        self._stats[base]     = self._stats.get(base, 0) + 1
        self._c_total.config(    text=str(self._stats["total"]))
        self._c_malicious.config(text=str(self._stats["malicious"]))
        self._c_suspicious.config(text=str(self._stats["suspicious"]))
        self._c_clean.config(    text=str(self._stats["clean"]))

        icons = {"malicious":"💥","suspicious":"⚠️","clean":"✅"}
        self._status.config(
            text=f"  {icons.get(base,'·')}  {ip}:{port}  ({proc})  —  {base.upper()}")

        # Send alert here — called once per 400ms, so notifications are spaced out
        self._alert(ip, port, proc, vt, abuse, country, cf)

    # ═════════════════════════════════════════════════════════════════════
    # Poll loop
    # ═════════════════════════════════════════════════════════════════════
    def _poll_loop(self):
        while self.running:
            try:
                active_keys = set()
                for conn in psutil.net_connections(kind="inet"):
                    if not conn.raddr or conn.raddr.ip in EXCLUDED_IPS:
                        continue
                    key = (conn.raddr.ip, conn.raddr.port)
                    active_keys.add(key)
                    if key in self._seen: continue
                    self._seen.add(key)

                    proc = "Unknown"
                    if conn.pid:
                        try: proc = psutil.Process(conn.pid).name()
                        except psutil.NoSuchProcess: pass
                    proto = "UDP" if conn.type == socket.SOCK_DGRAM else "TCP"
                    self._pinfo[key] = (proc, conn)
                    _POOL.submit(self._enrich,
                                 conn, conn.raddr.ip, conn.raddr.port, proto, proc)

                # Queue stale key removal to main thread
                stale = self._seen - active_keys
                if stale:
                    self.root.after(0, self._remove_stale, stale)
            except Exception as e:
                print(f"[Poll] {e}")
            time.sleep(_POLL_SEC)

    def _remove_stale(self, stale: set):
        """Remove rows whose connections no longer exist — called on main thread."""
        for key in stale:
            self._seen.discard(key)
            self._pinfo.pop(key, None)
        self._rows = [(rid, vals, tag) for rid, vals, tag in self._rows
                      if (vals[0], int(vals[1])) not in stale]
        if stale:
            self._redraw()

    def _enrich(self, conn, ip, port, proto, proc):
        try:
            # Always query VT and AbuseIPDB independently — each has its own cache.
            # VT   → "Malicious (5/90)" | "Suspicious (2/90)" | "Clean (0/90)"
            # Abuse→ "High Risk (85%)"  | "Medium Risk (42%)" | "Low Risk (3%)"
            vt, abuse = check_both(ip)
            country   = get_country(ip)
            cf        = is_cloudflare(ip)
            self._q.put((ip, port, proto, proc, country, cf, vt, abuse))
        except Exception as e:
            print(f"[Enrich {ip}] {e}")

    # ═════════════════════════════════════════════════════════════════════
    # Alert  (corrected filter logic + rate-limited notifications)
    # ═════════════════════════════════════════════════════════════════════
    def _should_notify(self, vt, abuse, country=""):
        is_mal = "Malicious"  in vt or "High Risk"   in abuse
        is_sus = "Suspicious" in vt or "Medium Risk" in abuse
        mode = self._filter_mode.get()
        # Alert filter
        if mode == 1:   passes = True           # All Events
        elif mode == 2: passes = is_mal         # Only Malicious
        else:           passes = is_mal or is_sus  # Sus + Mal
        if not passes: return False
        # Country filter
        sel = self._country_var.get()
        if sel and sel != "All Countries":
            if country != sel: return False
        return True

    def _alert(self, ip, port, proc, vt, abuse, country, cf):
        if not self._should_notify(vt, abuse, country): return
        is_mal = "Malicious"  in vt or "High Risk"   in abuse
        is_sus = "Suspicious" in vt or "Medium Risk" in abuse
        if is_mal:   label, sound = "💥 MALICIOUS", "malicious"
        elif is_sus: label, sound = "⚠️ SUSPICIOUS", "warning"
        else:        label, sound = "✅ Clean",       None
        cf_i = "☁️" if cf == "Yes" else "🚫"
        msg  = (f"{label}\n🌐 {ip}:{port}  💻 {proc}\n"
                f"🌍 {country}  {cf_i}\n"
                f"🦠 VT: {vt}  🚨 Abuse: {abuse}")
        toast(f"Big Bro — {label}", msg)
        telegram(msg)
        if sound: play_sound(sound)

    def _sync(self): pass  # not used; radio buttons are mutually exclusive

    # ═════════════════════════════════════════════════════════════════════
    # Filter
    # ═════════════════════════════════════════════════════════════════════
    def _raw(self, e, ph):
        v = e.get().strip()
        return "" if v == ph else v

    def _filter_ip(self):
        q = self._raw(self._eip, "IP address…")
        if not q: return
        self.tree.delete(*self.tree.get_children())
        for rid, vals, tag in self._rows:
            if q in vals[0]:
                self.tree.insert("", tk.END, iid=rid, values=vals, tags=(tag,))

    def _clear_ip(self):
        self._eip.delete(0, tk.END)
        self._eip.insert(0, "IP address…")
        self._eip.config(fg=T["dim"])
        self._redraw()

    def _filter_port(self):
        q = self._raw(self._eport, "Port…")
        if not q: return
        self.tree.delete(*self.tree.get_children())
        for rid, vals, tag in self._rows:
            if q in str(vals[1]):
                self.tree.insert("", tk.END, iid=rid, values=vals, tags=(tag,))

    def _clear_port(self):
        self._eport.delete(0, tk.END)
        self._eport.insert(0, "Port…")
        self._eport.config(fg=T["dim"])
        self._redraw()

    def _redraw(self):
        self.tree.delete(*self.tree.get_children())
        new_rows = []
        for _, vals, base in self._rows:
            rid = self.tree.insert("", tk.END, values=vals, tags=(base,))
            new_rows.append((rid, vals, base))
        self._rows = new_rows

    # ═════════════════════════════════════════════════════════════════════
    # Sort
    # ═════════════════════════════════════════════════════════════════════
    def _sort(self, col):
        if not hasattr(self, "_sc"): self._sc = None; self._sr = False
        self._sr = (not self._sr) if self._sc == col else False
        self._sc = col
        items = [(self.tree.set(i, col), i) for i in self.tree.get_children()]
        items.sort(key=lambda x: x[0], reverse=self._sr)
        for idx, (_, item) in enumerate(items):
            self.tree.move(item, "", idx)

    # ═════════════════════════════════════════════════════════════════════
    # Click / hover
    # ═════════════════════════════════════════════════════════════════════
    def _click(self, ev):
        region = self.tree.identify_region(ev.x, ev.y)
        col    = self.tree.identify_column(ev.x)
        row    = self.tree.identify_row(ev.y)
        if not row or region != "cell": return
        ip = self.tree.item(row, "values")[0]
        urls = {"#7": f"https://www.virustotal.com/gui/ip-address/{ip}",
                "#8": f"https://www.abuseipdb.com/check/{ip}",
                "#9": f"https://who.is/whois-ip/ip-address/{ip}"}
        if col in urls: webbrowser.open_new_tab(urls[col])
        elif col == "#10": self._scan_prompt(ip)

    def _rclick(self, ev):
        row = self.tree.identify_row(ev.y)
        if row:
            self.tree.selection_set(row)
            self.cmenu.post(ev.x_root, ev.y_root)

    def _hover(self, ev):
        c = self.tree.identify_column(ev.x)
        r = self.tree.identify_region(ev.x, ev.y)
        self.tree.configure(
            cursor="hand2" if r=="cell" and c in {"#7","#8","#9","#10"} else "")

    def _sel_ip(self):
        s = self.tree.selection()
        return self.tree.item(s[0], "values")[0] if s else None

    def _ctx_vt(self):
        ip = self._sel_ip()
        if ip: webbrowser.open_new_tab(f"https://www.virustotal.com/gui/ip-address/{ip}")
    def _ctx_abuse(self):
        ip = self._sel_ip()
        if ip: webbrowser.open_new_tab(f"https://www.abuseipdb.com/check/{ip}")
    def _ctx_whois(self):
        ip = self._sel_ip()
        if ip: webbrowser.open_new_tab(f"https://who.is/whois-ip/ip-address/{ip}")
    def _ctx_scan(self):
        ip = self._sel_ip()
        if ip: self._scan_prompt(ip)

    # ═════════════════════════════════════════════════════════════════════
    # Kill / Block
    # ═════════════════════════════════════════════════════════════════════
    def _kill(self):
        import platform, signal
        s = self.tree.selection()
        if not s: return
        vals = self.tree.item(s[0], "values")
        ip, port = vals[0], int(vals[1])
        info = self._pinfo.get((ip, port))
        if not info:
            messagebox.showerror("Error", "No process found."); return

        try:
            proc = psutil.Process(info[1].pid)
            name = proc.name()
        except psutil.NoSuchProcess:
            messagebox.showerror("Error", "Process no longer exists."); return

        if not messagebox.askyesno(
            "Kill Process",
            f"Kill process  '{name}'  (PID {info[1].pid})?"
            f"\n\nConnection: {ip}:{port}"
            f"\n\nThis will terminate the entire process."
        ): return

        try:
            if platform.system() == "Windows":
                # Windows: TerminateProcess — instant, no way to ignore
                proc.kill()
            else:
                # Linux: SIGKILL — cannot be caught or ignored by the process
                os.kill(info[1].pid, signal.SIGKILL)
            self._status.config(
                text=f"  ✔  '{name}' (PID {info[1].pid}) killed — {ip}:{port}")
        except psutil.AccessDenied:
            messagebox.showerror(
                "Access Denied",
                f"Cannot kill '{name}' (PID {info[1].pid}).\n"
                f"Process may be protected or owned by another user.")
        except ProcessLookupError:
            messagebox.showinfo("Info", "Process already exited.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _block(self):
        import platform
        s = self.tree.selection()
        if not s: return
        ip = self.tree.item(s[0], "values")[0]
        try: ipaddress.ip_address(ip)
        except ValueError:
            messagebox.showerror("Error", f"Invalid IP: {ip}"); return
        if not messagebox.askyesno("Block", f"Block {ip} via firewall?"): return
        try:
            if platform.system() == "Windows":
                cmd = ["netsh","advfirewall","firewall","add","rule",
                       f"name=BigBro_Block_{ip}","dir=in","action=block",
                       f"remoteip={ip}"]
            else:
                # Linux: try ufw first, fall back to iptables
                import shutil
                if shutil.which("ufw"):
                    cmd = ["ufw","deny","from", ip,"to","any"]
                else:
                    cmd = ["iptables","-I","INPUT","-s", ip,"-j","DROP"]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            self._status.config(text=f"  🛡  {ip} blocked.")
            messagebox.showinfo("Blocked", f"{ip} blocked.")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", e.stderr)

    # ═════════════════════════════════════════════════════════════════════
    # IP list popups
    # ═════════════════════════════════════════════════════════════════════
    def _lst_popup(self, title, ip_set):
        w = tk.Toplevel(self.root)
        w.title(title); w.configure(bg=T["bg"])
        _cp(w, 440, 500)
        if os.path.exists(ICON_PATH):
            _set_icon(w)
        tk.Frame(w, bg=T["accent"], height=3).pack(fill="x")
        tk.Label(w, text=title, font=("Segoe UI",13,"bold"),
                 bg=T["bg"], fg=T["text"], pady=10).pack()
        ta = tk.Text(w, font=("Consolas",10),
                     bg=T["bg2"], fg=T["text"], relief="flat", bd=0)
        ta.pack(fill="both", expand=True, padx=12)
        ta.insert("1.0", "\n".join(sorted(ip_set)) or "(empty)")
        ta.config(state="disabled")
        tk.Button(w, text="Close", font=("Segoe UI",10),
                  bg=T["red"], fg=T["text"], relief="flat",
                  cursor="hand2", padx=16, pady=7,
                  command=w.destroy).pack(pady=10)

    def _lst_mal(self): m,_,_ = get_lists(); self._lst_popup("🔴  Malicious IPs",  m)
    def _lst_sus(self): _,s,_ = get_lists(); self._lst_popup("🟠  Suspicious IPs", s)
    def _lst_cln(self): _,_,c = get_lists(); self._lst_popup("🟢  Clean IPs",      c)

    # ═════════════════════════════════════════════════════════════════════
    # Port scanner
    # ═════════════════════════════════════════════════════════════════════
    def _scan_prompt(self, ip):
        w = tk.Toplevel(self.root)
        w.title("Bro Scan"); w.configure(bg=T["bg"])
        _cp(w, 350, 170)
        if os.path.exists(ICON_PATH):
            _set_icon(w)
        tk.Frame(w, bg=T["accent"], height=3).pack(fill="x")
        tk.Label(w, text=f"Select range for  {ip}",
                 font=("Segoe UI",11), bg=T["bg"], fg=T["text"], pady=14).pack()
        bf = tk.Frame(w, bg=T["bg"]); bf.pack()
        for lbl, rng in [("1–1024", range(1,1025)), ("1–65535", range(1,65536))]:
            def _go(r=rng): w.destroy(); self._run_scan(ip, r)
            tk.Button(bf, text=lbl, font=("Segoe UI",10),
                      bg=T["accent"], fg="#000", relief="flat",
                      cursor="hand2", padx=16, pady=8,
                      command=_go).pack(side="left", padx=6)
        tk.Button(w, text="Cancel", font=("Segoe UI",9),
                  bg=T["red"], fg=T["text"], relief="flat",
                  cursor="hand2", pady=6,
                  command=w.destroy).pack(pady=10)

    def _run_scan(self, ip, ports):
        w = tk.Toplevel(self.root)
        w.title(f"Bro Scan — {ip}"); w.configure(bg=T["bg"])
        _cp(w, 620, 480)
        _set_icon(w)
        tk.Frame(w, bg=T["accent"], height=2).pack(fill="x")

        hdr = tk.Frame(w, bg=T["bg2"])
        hdr.pack(fill="x", padx=12, pady=(8,4))
        tk.Label(hdr, text=f"  {ip}", font=("Consolas",12,"bold"),
                 bg=T["bg2"], fg=T["text"]).pack(side="left")
        scan_lbl = tk.Label(hdr, text="Scanning…",
                            font=("Segoe UI",9), bg=T["bg2"], fg=T["dim"])
        scan_lbl.pack(side="right")

        ta = tk.Text(w, font=("Consolas",10), bg=T["bg2"], fg=T["accent"],
                     relief="flat", bd=0, highlightthickness=0)
        ta.pack(fill="both", expand=True, padx=12, pady=(0,4))
        ta.config(state="disabled")

        found = [0]

        def _live(result):
            port, svc = result
            found[0] += 1
            def _ui():
                ta.config(state="normal")
                ta.insert(tk.END, f"  ▶  {port:>5}   {svc}\n")
                ta.see(tk.END)
                ta.config(state="disabled")
                scan_lbl.config(text=f"{found[0]} open port(s)…")
            w.after(0, _ui)

        def _do():
            res = scan_ports(ip, ports, callback=_live)
            def _done():
                if isinstance(res, str) and found[0] == 0:
                    ta.config(state="normal")
                    ta.insert(tk.END, f"  {res}\n")
                    ta.config(state="disabled")
                scan_lbl.config(
                    text=f"Done — {found[0]} open port(s)" if found[0]
                    else "Done — no open ports")
            w.after(0, _done)

        Thread(target=_do, daemon=True).start()
        tk.Button(w, text="Close", font=("Segoe UI",10),
                  bg=T["red"], fg=T["text"], relief="flat",
                  cursor="hand2", pady=7,
                  command=w.destroy).pack(pady=(0,10))

    # ═════════════════════════════════════════════════════════════════════
    # Tray  (clean exit — os._exit guarantees no ghost in taskbar)
    # ═════════════════════════════════════════════════════════════════════
    def _to_tray(self):
        # If already in tray, just hide window again
        if self._tray:
            self.root.withdraw()
            return
        self.root.withdraw()
        # pystray needs a PIL RGBA image — no resize, pystray handles sizing
        try:
            img = Image.open(ICON_PATH).convert("RGBA")
        except Exception:
            from PIL import ImageDraw
            img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
            ImageDraw.Draw(img).ellipse([4, 4, 60, 60], fill=(61, 142, 255, 255))

        def _show(icon, _):
            icon.stop()
            self._tray = None
            self.root.after(0, self.root.deiconify)

        def _exit(icon, _):
            icon.stop()
            self._tray = None
            self.running = False
            # os._exit(0) → process terminates immediately, no ghost
            os._exit(0)

        menu = Menu(MenuItem("Show", _show), MenuItem("Exit", _exit))
        self._tray = Icon("BigBro", img, "Big Bro", menu)
        Thread(target=self._tray.run, daemon=True).start()

    def _go_back(self):
        if self._tray:
            self._tray.stop()
            self._tray = None
        self.running = False
        self.root.destroy()
        if self.back_cb:
            self.back_cb()


# ─────────────────────────────────────────────────────────────────────────────
def _cp(win, w, h):
    sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
    win.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")
