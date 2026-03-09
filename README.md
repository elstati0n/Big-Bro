#  Big Bro — Network Connection Monitor

> Real-time network connection monitor with IP reputation checking, port scanning, firewall blocking, and Telegram alerts. Runs on **Windows** and **Linux**.

---

## 📸 Overview

Big Bro watches every outbound TCP/UDP connection on your machine in real time. Each new IP is automatically checked against **VirusTotal** and **AbuseIPDB**, colour-coded by threat level, and optionally sends a **Telegram alert** to your phone.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔴 **Live connection table** | Shows IP, Port, Protocol, Process, Country, Cloudflare status |
| 🦠 **VirusTotal** | Engine count per IP — `Malicious (5/90)`, `Suspicious (2/90)`, `Clean (0/90)` |
| 🚨 **AbuseIPDB** | Confidence score per IP — `High Risk (85%)`, `Medium Risk (42%)`, `Low Risk (3%)` |
| 🌍 **Geolocation** | Country per IP via ip-api.com |
| ☁️ **Cloudflare detection** | Flags IPs inside Cloudflare CIDR ranges |
| 🔔 **Toast notifications** | Desktop popup for malicious/suspicious connections |
| 📲 **Telegram alerts** | Sends alert message to your Telegram bot |
| 🔇 **Alert filter** | Malicious only / Suspicious+Malicious / All |
| 🌐 **Country filter** | Show alerts only from a specific country |
| 🔍 **IP & Port search** | Filter table by IP or port; new connections respect active filter |
| 🔬 **Bro Scan** | Built-in multithreaded TCP port scanner (1–1024 or 1–65535) |
| ⚡ **Kill process** | Kill the process behind a connection |
| 🛡 **Block IP** | Add firewall rule via `netsh` (Windows) or `ufw`/`iptables` (Linux) |
| 📋 **IP Lists** | View cached Malicious / Suspicious / Clean IPs in popup |
| 🔐 **Encrypted key storage** | API keys encrypted with Fernet + machine-derived key (PBKDF2-SHA256) |
| 💾 **Smart cache** | 14-day TTL per IP, RAM-first with background disk flush every 30s, 5000 IP limit |
| 🖥 **System tray** | Minimize to tray, restore or exit from tray menu |

---

## 🗂 File Structure

```
BigBro/
├── BigBro.py              # Entry point — auto-elevates to admin/root
├── BigBro.pyw             # Silent entry point (no console window, Windows)
├── setup_window.py        # Configuration window (API keys, adapter selection)
├── monitor_window.py      # Main monitor UI — table, toolbar, alerts
├── ip_checker.py          # VT + AbuseIPDB reputation, cache engine
├── api_manager.py         # Encrypted API key read/write (Fernet)
├── notifier.py            # Toast notifications + Telegram sender
├── port_scanner.py        # Multithreaded TCP port scanner
├── config.py              # Paths, constants, colour theme
├── requirements.txt       # Python dependencies
└── archer_circle_icon__1_.ico  # App icon
```

---

## ⚙️ Setup

### Requirements

- Python **3.9+**
- pip packages:

```bash
pip install -r requirements.txt
```

---

### 🪟 Windows

```bash
pip install -r requirements.txt
```

Then **double-click `BigBro.pyw`** — UAC prompt will appear, accept it, app launches. No console window.

---

### 🐧 Linux

```bash
pip install -r requirements.txt

sudo apt install libnotify-bin      # toast notifications
sudo apt install pulseaudio-utils   # alert sounds
sudo apt install ufw                # firewall block (optional)

python3 BigBro.py
```

---

## 🔑 Optional API Keys

All keys are **optional** — Big Bro works without them but reputation checks will be skipped.

| Key | Where to get | Purpose |
|---|---|---|
| **VirusTotal** | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) | IP engine scan count |
| **AbuseIPDB** | [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api) | IP abuse confidence % |
| **Telegram Bot Token** | [@BotFather](https://t.me/BotFather) on Telegram | Send alerts to your phone |
| **Telegram Chat ID** | [@userinfobot](https://t.me/userinfobot) on Telegram | Your chat ID for the bot |

Keys are entered in the **Setup window** and stored **encrypted on disk** — tied to your machine's hardware ID, unreadable on any other machine.

---

## 🎛 Alert Filter

Located in the toolbar — controls which connections trigger **sound + toast + Telegram**:

| Mode | Behaviour |
|---|---|
| **Malicious only** *(default)* | Alert only on VT Malicious or AbuseIPDB High Risk |
| **Suspicious and Malicious** | Alert on anything flagged |
| **All** | Alert on every new connection including clean |

---

## 🔍 Search & Filter

- **IP filter** — type partial or full IP, click Filter. New connections arriving while filter is active are stored in memory but hidden. Click **✕** to clear — all connections appear.
- **Port filter** — same behaviour for port numbers.
- **Country filter** — dropdown in toolbar, filters which countries trigger alerts.

---

## 💾 Cache

- Each IP is cached separately for **VirusTotal** (`vt:<ip>`) and **AbuseIPDB** (`abuse:<ip>`)
- TTL: **14 days** per entry (configurable in `config.py` → `CACHE_TTL_DAYS`)
- Max size: **5000 entries** — oldest evicted automatically (LRU)
- Stored in: `./data/ip_lists/ip_cache.json`
- Flushed to disk every **30 seconds** in background — UI never blocks

---

## 🔬 Bro Scan (Port Scanner)

Right-click any row → **Bro Scan**, or click the **Scan** cell. Choose range:

- `1–1024` — common ports, fast (~2–3 seconds)
- `1–65535` — full scan, ~10–20 seconds

Uses **256 concurrent threads** with 0.15s timeout per port. Results stream live into the popup window.

---

## 🛡 Blocking an IP

1. Select a row in the table
2. Click **🛡 Block IP** in toolbar
3. Confirm the dialog

**Windows** — adds inbound block rule via `netsh advfirewall`
**Linux** — blocks via `ufw deny from <ip>` or `iptables -I INPUT -s <ip> -j DROP`

Requires admin/root (already elevated at launch).

---

## ⚡ Killing a Process

1. Select a row
2. Click **⚡ Kill** in toolbar
3. Confirm — the entire process is terminated immediately

**Windows** — `TerminateProcess` (cannot be ignored)
**Linux** — `SIGKILL` (cannot be caught or ignored)

---

## 🚫 Excluded IPs

The following IPs are never checked or shown (hardcoded in `config.py`):

```
127.0.0.1, 0.0.0.0, ::1, 8.8.8.8, 8.8.4.4, 4.4.4.4
```

---

## 📁 Data Directory

All data is stored **next to the script** — no hardcoded system paths:

```
./data/
├── virustotal_api_key.txt      # encrypted
├── abuseipdb_api_key.txt       # encrypted
├── telegram_bot_token.txt      # encrypted
├── telegram_bot_chat_id.txt    # encrypted
└── ip_lists/
    └── ip_cache.json           # reputation cache
```

---

## 📜 License

MIT
