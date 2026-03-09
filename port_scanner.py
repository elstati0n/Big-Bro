"""
port_scanner.py – Fast multithreaded TCP port scanner.

Tuning:
  • CONNECT_TIMEOUT 0.15 s  (was 0.2)
  • MAX_WORKERS     256     (was 100) — sweet spot, diminishing returns above ~300
  • Results streamed back via callback so UI can update in real time
"""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

CONNECT_TIMEOUT = 0.15
MAX_WORKERS     = 256


def _probe(ip: str, port: int):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(CONNECT_TIMEOUT)
            if s.connect_ex((ip, port)) == 0:
                try:    svc = socket.getservbyport(port, "tcp")
                except: svc = "unknown"
                return (port, svc)
    except OSError:
        pass
    return None


def scan_ports(ip: str, port_range: range, callback=None):
    """
    Scan *port_range* on *ip*.

    If *callback* is provided it is called with (port, service) for each
    open port as soon as it is found — useful for live UI updates.

    Returns sorted list of (port, service) tuples,
    or the string "No open ports found." when nothing is open.
    """
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(_probe, ip, p): p for p in port_range}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                results.append(res)
                if callback:
                    try: callback(res)
                    except Exception: pass

    if not results:
        return "No open ports found."
    return sorted(results)
