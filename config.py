"""config.py – constants, paths, theme."""
import os, sys

# All data is stored NEXT TO the script — cross-platform, no hardcoded C:\
BASE_DIR  = os.path.dirname(os.path.abspath(sys.argv[0]))
APP_DIR   = os.path.join(BASE_DIR, "data")          # ./data/
LIST_DIR  = os.path.join(APP_DIR,  "ip_lists")      # ./data/ip_lists/

# Try both possible icon filenames (spaces vs underscores)
_ico1 = os.path.join(BASE_DIR, "archer_circle_icon (1).ico")
_ico2 = os.path.join(BASE_DIR, "archer_circle_icon__1_.ico")
ICON_PATH = _ico1 if os.path.exists(_ico1) else _ico2

VIRUSTOTAL_API_KEY_FILE   = os.path.join(APP_DIR, "virustotal_api_key.txt")
ABUSEIPDB_API_KEY_FILE    = os.path.join(APP_DIR, "abuseipdb_api_key.txt")
TELEGRAM_BOT_TOKEN_FILE   = os.path.join(APP_DIR, "telegram_bot_token.txt")
TELEGRAM_BOT_CHAT_ID_FILE = os.path.join(APP_DIR, "telegram_bot_chat_id.txt")

# Legacy txt files (kept for reference / manual inspection)
MALICIOUS_FILE  = os.path.join(LIST_DIR, "malicious_ips.txt")
SUSPICIOUS_FILE = os.path.join(LIST_DIR, "suspicious_ips.txt")
CLEAN_FILE      = os.path.join(LIST_DIR, "clean_ips.txt")

# JSON cache — single file, one entry per IP with timestamp
# Each IP expires individually after CACHE_TTL_DAYS days
IP_CACHE_FILE   = os.path.join(LIST_DIR, "ip_cache.json")
CACHE_TTL_DAYS  = 14   # days until a single IP entry is re-checked

EXCLUDED_IPS = frozenset({
    "127.0.0.1", "0.0.0.0", "::1",
    "8.8.8.8", "8.8.4.4", "4.4.4.4",
})

CLOUDFLARE_RANGES = [
    "173.245.48.0/20","103.21.244.0/22","103.22.200.0/22",
    "103.31.4.0/22","141.101.64.0/18","108.162.192.0/18",
    "190.93.240.0/20","188.114.96.0/20","197.234.240.0/22",
    "198.41.128.0/17","162.158.0.0/15","104.16.0.0/13",
    "104.24.0.0/14","172.64.0.0/13","131.0.72.0/22",
]

# ── True black premium theme — OLED-friendly, zero eye strain ─────────────────
T = {
    "bg":          "#0a0a0a",
    "bg2":         "#111111",
    "bg3":         "#1a1a1a",
    "bg4":         "#141414",
    "border":      "#2a2a2a",
    "accent":      "#3d8eff",
    "accent2":     "#1a5fcc",
    "text":        "#c8c8c8",
    "dim":         "#555555",
    "mal_fg":      "#FFFFFF",
    "mal_bg":      "#140606",
    "mal_bg2":     "#140606",
    "sus_fg":      "#FFFFFF",
    "sus_bg":      "#130d00",
    "sus_bg2":     "#130d00",
    "cln_fg":      "#FFFFFF",
    "cln_bg":      "#061008",
    "cln_bg2":     "#061008",
    "red":         "#991c1c",
    "green":       "#1a4d28",
}
THEME = T
