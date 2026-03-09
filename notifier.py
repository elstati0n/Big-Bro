"""
notifier.py – Cross-platform notifications and sounds.

Windows : plyer toast  +  winsound
Linux   : notify-send (libnotify)  +  paplay / aplay / pacat
"""
import os, time, platform
from threading import Thread
from queue import Queue

import requests
from config import ICON_PATH
from api_manager import get_tg_token, get_tg_chat

_DURATION = 5
_q: Queue = Queue(maxsize=50)   # max 50 pending — flood zamanı yenisi atılır
_OS = platform.system()   # "Windows" | "Linux" | "Darwin"


# ── Sound ─────────────────────────────────────────────────────────────────────

def play_sound(level: str) -> None:
    def _do():
        try:
            if _OS == "Windows":
                import winsound
                if level == "malicious":
                    winsound.MessageBeep(winsound.MB_ICONHAND)
                elif level == "warning":
                    winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
            else:
                # Linux: use paplay with system sounds, fall back to aplay beep
                sounds = {
                    "malicious": [
                        "/usr/share/sounds/freedesktop/stereo/dialog-error.oga",
                        "/usr/share/sounds/ubuntu/stereo/dialog-error.ogg",
                    ],
                    "warning": [
                        "/usr/share/sounds/freedesktop/stereo/dialog-warning.oga",
                        "/usr/share/sounds/ubuntu/stereo/dialog-warning.ogg",
                    ],
                }
                import subprocess
                for path in sounds.get(level, []):
                    if os.path.exists(path):
                        # try paplay first, then aplay
                        for player in ("paplay", "aplay"):
                            try:
                                subprocess.Popen(
                                    [player, path],
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
                                break
                            except FileNotFoundError:
                                continue
                        break
        except Exception as e:
            print(f"[Sound] {e}")
    Thread(target=_do, daemon=True).start()


# ── Toast worker ──────────────────────────────────────────────────────────────

def _show_toast(title: str, msg: str) -> None:
    """Show one notification — platform-specific."""
    try:
        if _OS == "Windows":
            from plyer import notification
            notification.notify(
                title=title,
                message=msg,
                app_name="Big Bro",
                app_icon=None,
                timeout=_DURATION,
            )
        else:
            # Linux: notify-send (libnotify)
            import subprocess
            cmd = ["notify-send", "--app-name=Big Bro",
                   f"--expire-time={_DURATION * 1000}", title, msg]
            if os.path.exists(ICON_PATH):
                cmd += [f"--icon={ICON_PATH}"]
            subprocess.Popen(cmd,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"[Toast] {e}")


def _worker():
    while True:
        title, msg = _q.get()
        _show_toast(title, msg)
        time.sleep(_DURATION + 0.3)

Thread(target=_worker, daemon=True, name="BigBro-Toast").start()


def toast(title: str, message: str) -> None:
    try:
        _q.put_nowait((title, message))   # queue dolubsa notification atılır
    except Exception:
        pass   # flood zamanı program donmur, sadəcə skip edilir


# ── Telegram ──────────────────────────────────────────────────────────────────

def telegram(message: str) -> None:
    def _do():
        token, chat_id = get_tg_token(), get_tg_chat()
        if not token or not chat_id:
            return
        try:
            r = requests.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": chat_id, "text": message},
                timeout=10,
            )
            if r.status_code != 200:
                print(f"[Telegram] {r.status_code}")
        except Exception as e:
            print(f"[Telegram] {e}")
    Thread(target=_do, daemon=True).start()
