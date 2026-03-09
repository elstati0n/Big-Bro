"""
BigBro.pyw – Silent launcher (no console window).
On Linux this is just a regular .py — rename to BigBro.py if needed.
Errors → <script_dir>/data/bigbro_error.log
"""
import os, sys, platform

_HERE     = os.path.dirname(os.path.abspath(__file__))
_DATA_DIR = os.path.join(_HERE, "data")
LOG       = os.path.join(_DATA_DIR, "bigbro_error.log")

if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

def _log(msg):
    try:
        os.makedirs(_DATA_DIR, exist_ok=True)
        with open(LOG, "a", encoding="utf-8") as f:
            import datetime
            f.write(f"[{datetime.datetime.now()}] {msg}\n")
    except Exception:
        pass

def _is_admin() -> bool:
    if platform.system() == "Windows":
        import ctypes
        try: return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except: return False
    else:
        return os.geteuid() == 0

def _elevate() -> None:
    if platform.system() == "Windows":
        import ctypes
        pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
        if not os.path.exists(pythonw):
            pythonw = sys.executable
        script = os.path.abspath(__file__)
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", pythonw, f'"{script}"', _HERE, 1)
        if ret <= 32:
            _log(f"ShellExecuteW failed: {ret}")
    else:
        args = ["pkexec", sys.executable, os.path.abspath(__file__)]
        os.execvp("pkexec", args)
    sys.exit(0)

try:
    if not _is_admin():
        _elevate()

    from config import APP_DIR, LIST_DIR
    os.makedirs(APP_DIR,  exist_ok=True)
    os.makedirs(LIST_DIR, exist_ok=True)

    import tkinter as tk
    from setup_window import SetupWindow
    root = tk.Tk()
    SetupWindow(root)
    root.mainloop()

except Exception as e:
    import traceback
    _log(traceback.format_exc())
    try:
        import tkinter as tk, tkinter.messagebox as mb
        tk.Tk().withdraw()
        mb.showerror("Big Bro – Startup Error",
                     f"{e}\n\nFull error saved to:\n{LOG}")
    except Exception:
        pass
