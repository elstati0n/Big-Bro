"""
ip_checker.py – IP reputation with optimized RAM cache + background flush.

Architecture:
  RAM dict  ← loaded once at startup (O(1) lookups, no disk I/O per query)
      ↓ flushed to disk every 30 s (background thread, UI never blocks)
  ip_cache.json  ← persistent storage

Cache keys are namespaced:
  "vt:<ip>"    → VirusTotal result  e.g. "Malicious (5/90)", "Clean (0/90)"
  "abuse:<ip>" → AbuseIPDB result   e.g. "High Risk (85%)", "Low Risk (2%)"

Both APIs are queried independently and stored separately so each column
in the UI always shows its own accurate data.
"""
import ipaddress, json, os, tempfile, time
from threading import Lock, Thread

import requests

from config import CLOUDFLARE_RANGES, IP_CACHE_FILE, CACHE_TTL_DAYS
from api_manager import get_vt_key, get_abuse_key

REQUEST_TIMEOUT = 10
_TTL            = CACHE_TTL_DAYS * 86_400
_FLUSH_INTERVAL = 30
_dirty          = False
_lock           = Lock()
_cache: dict    = {}   # keys: "vt:<ip>" or "abuse:<ip>"
_MAX_CACHE      = 5_000  # max entries (~2 MB RAM), LRU eviction


# ── Startup ───────────────────────────────────────────────────────────────────

def load_all() -> None:
    global _cache
    raw = _read_disk()
    now = time.time()
    with _lock:
        _cache = {k: v for k, v in raw.items()
                  if now - v.get("ts", 0) < _TTL}
    removed = len(raw) - len(_cache)
    if removed:
        print(f"[cache] purged {removed} expired entries")
        _mark_dirty()
    Thread(target=_flush_loop, daemon=True, name="BigBro-Flush").start()


# ── Background flush ──────────────────────────────────────────────────────────

def _flush_loop():
    global _dirty
    while True:
        time.sleep(_FLUSH_INTERVAL)
        if _dirty:
            _flush_now()

def _flush_now():
    global _dirty
    with _lock:
        snap = dict(_cache)
    _write_disk(snap)
    _dirty = False

def _mark_dirty():
    global _dirty
    _dirty = True


# ── Disk I/O ──────────────────────────────────────────────────────────────────

def _read_disk() -> dict:
    try:
        with open(IP_CACHE_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}

def _write_disk(data: dict) -> None:
    os.makedirs(os.path.dirname(IP_CACHE_FILE), exist_ok=True)
    try:
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(IP_CACHE_FILE), suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, IP_CACHE_FILE)
    except OSError as exc:
        print(f"[cache] write error: {exc}")


# ── RAM cache ops (namespaced) ────────────────────────────────────────────────

def _cache_get(key: str):
    """Get cached result by namespaced key (e.g. 'vt:1.2.3.4')."""
    with _lock:
        entry = _cache.get(key)
    if not entry:
        return None
    if time.time() - entry.get("ts", 0) > _TTL:
        with _lock:
            _cache.pop(key, None)
        _mark_dirty()
        return None
    return entry["result"]

def _cache_set(key: str, result: str) -> None:
    """Store result by namespaced key. Evicts oldest entry if limit reached."""
    with _lock:
        if len(_cache) >= _MAX_CACHE:
            oldest = min(_cache, key=lambda k: _cache[k].get("ts", 0))
            del _cache[oldest]
        _cache[key] = {"result": result, "ts": int(time.time())}
    _mark_dirty()


# ── Public: IP list categorization ───────────────────────────────────────────

def get_lists() -> tuple:
    """Return (malicious_set, suspicious_set, clean_set) from cache."""
    now = time.time()
    with _lock:
        snap = dict(_cache)

    # Collect per-IP results (vt + abuse separately)
    ip_results: dict = {}
    for key, v in snap.items():
        if now - v.get("ts", 0) > _TTL:
            continue
        r = v.get("result", "")
        if key.startswith("vt:"):
            ip_results.setdefault(key[3:], {})["vt"] = r
        elif key.startswith("abuse:"):
            ip_results.setdefault(key[6:], {})["abuse"] = r

    mal, sus, cln = set(), set(), set()
    for ip, res in ip_results.items():
        vt    = res.get("vt", "")
        abuse = res.get("abuse", "")
        if "Malicious" in vt or "High Risk" in abuse:
            mal.add(ip)
        elif "Suspicious" in vt or "Medium Risk" in abuse:
            sus.add(ip)
        else:
            cln.add(ip)
    return mal, sus, cln


# ── Validation ────────────────────────────────────────────────────────────────

def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


# ── Cloudflare ────────────────────────────────────────────────────────────────

def is_cloudflare(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
        for cidr in CLOUDFLARE_RANGES:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return "Yes"
    except ValueError:
        pass
    return "No"


# ── VirusTotal — with detailed engine counts ──────────────────────────────────

def check_virustotal(ip: str) -> str:
    """
    Returns a human-readable VT result with engine counts.
      "Malicious (5/90)"  — 5+ engines flagged malicious
      "Suspicious (2/90)" — 1-2 engines flagged
      "Clean (0/90)"      — no engines flagged
    Checks RAM cache first (key: "vt:<ip>").
    Cache miss → real API call → store result.
    """
    if not validate_ip(ip):
        return "Invalid IP"

    cached = _cache_get(f"vt:{ip}")
    if cached:
        return cached

    key = get_vt_key()
    if not key:
        return "No VT Key"

    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": key},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 200:
            stats  = resp.json()["data"]["attributes"]["last_analysis_stats"]
            mal    = stats.get("malicious", 0)
            total  = sum(stats.values())
            if mal >= 3:
                result = f"Malicious ({mal}/{total})"
            elif mal >= 1:
                result = f"Suspicious ({mal}/{total})"
            else:
                result = f"Clean (0/{total})"
            _cache_set(f"vt:{ip}", result)
            return result
        return f"VT Err {resp.status_code}"
    except requests.RequestException as exc:
        print(f"[VT] {exc}")
        return "VT Error"


# ── AbuseIPDB — with percentage score ────────────────────────────────────────

def _abuse_raw(ip: str) -> str:
    """Direct AbuseIPDB API call — returns percentage string. No cache."""
    key = get_abuse_key()
    if not key:
        return "No Abuse Key"
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 200:
            score = resp.json()["data"]["abuseConfidenceScore"]
            if   score >= 80: return f"High Risk ({score}%)"
            elif score >= 40: return f"Medium Risk ({score}%)"
            else:             return f"Low Risk ({score}%)"
        return f"Abuse Err {resp.status_code}"
    except requests.RequestException as exc:
        print(f"[AbuseIPDB] {exc}")
        return "Abuse Error"

def check_abuseipdb(ip: str) -> str:
    """
    Cache-aware AbuseIPDB check.
    Returns e.g. "High Risk (85%)", "Medium Risk (42%)", "Low Risk (3%)"
    Cache key: "abuse:<ip>"
    """
    if not validate_ip(ip):
        return "Invalid IP"

    cached = _cache_get(f"abuse:{ip}")
    if cached:
        return cached

    result = _abuse_raw(ip)
    if "Error" not in result and "No " not in result:
        _cache_set(f"abuse:{ip}", result)
    return result


# ── Main path: both VT + AbuseIPDB independently ─────────────────────────────

def check_both(ip: str) -> tuple:
    """
    Returns (vt_result, abuse_result) — always queries both independently,
    each with its own cache namespace.
    Use this in _enrich() so VT and AbuseIPDB columns are always accurate.

    VT   →  "Malicious (5/90)" | "Suspicious (2/90)" | "Clean (0/90)"
    Abuse → "High Risk (85%)"  | "Medium Risk (42%)" | "Low Risk (3%)"
    """
    vt    = check_virustotal(ip)
    abuse = check_abuseipdb(ip)
    return vt, abuse


# ── Backward-compat: single reputation string (tag logic) ────────────────────

def check_reputation(ip: str) -> str:
    """Simple tag string — kept for backward compat. Prefer check_both()."""
    vt = check_virustotal(ip)
    if "Malicious"  in vt: return "Malicious"
    if "Suspicious" in vt: return "Suspicious"
    if "Clean"      in vt: return "Clean"
    abuse = check_abuseipdb(ip)
    return abuse


# ── Geolocation — ip-api.com (reliable, no key needed) ───────────────────────

def get_country(ip: str) -> str:
    if not validate_ip(ip):
        return "Unknown"
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=country,status",
            timeout=REQUEST_TIMEOUT,
        )
        data = resp.json()
        if data.get("status") == "success":
            return data.get("country", "Unknown")
        return "Unknown"
    except requests.RequestException:
        return "Unknown"
