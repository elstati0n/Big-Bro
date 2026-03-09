"""
api_manager.py – Encrypted API key storage using Fernet symmetric encryption.

Keys are encrypted with a machine-derived secret before writing to disk.
The secret is derived from machine UUID + a fixed app salt via PBKDF2-SHA256.
Even if the key files are copied to another machine they are unreadable.
"""
import base64, hashlib, os, platform, stat, uuid
from cryptography.fernet import Fernet, InvalidToken

from config import (
    VIRUSTOTAL_API_KEY_FILE,
    ABUSEIPDB_API_KEY_FILE,
    TELEGRAM_BOT_TOKEN_FILE,
    TELEGRAM_BOT_CHAT_ID_FILE,
)

_APP_SALT = b"BigBro-v1-salt-2024"


def _machine_key() -> bytes:
    """Derive a Fernet key from machine UUID — stable across reboots."""
    try:
        node = str(uuid.getnode()).encode()
    except Exception:
        node = platform.node().encode()
    raw = hashlib.pbkdf2_hmac("sha256", node, _APP_SALT, iterations=200_000)
    return base64.urlsafe_b64encode(raw)


_FERNET = Fernet(_machine_key())


def load_key(path: str) -> str:
    """Read and decrypt key from *path*. Returns '' on any error."""
    try:
        with open(path, "rb") as fh:
            token = fh.read().strip()
        return _FERNET.decrypt(token).decode("utf-8")
    except (FileNotFoundError, PermissionError, InvalidToken, Exception):
        return ""


def save_key(value: str, path: str) -> None:
    """Encrypt *value* and write to *path* with owner-only permissions."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    token = _FERNET.encrypt(value.encode("utf-8"))
    with open(path, "wb") as fh:
        fh.write(token)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def delete_key(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def get_vt_key()    -> str: return load_key(VIRUSTOTAL_API_KEY_FILE)
def get_abuse_key() -> str: return load_key(ABUSEIPDB_API_KEY_FILE)
def get_tg_token()  -> str: return load_key(TELEGRAM_BOT_TOKEN_FILE)
def get_tg_chat()   -> str: return load_key(TELEGRAM_BOT_CHAT_ID_FILE)
