"""
BigBro.py – Entry point. Auto-elevates to admin/root on both Windows and Linux.
"""
import os, sys, platform

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
        script = os.path.abspath(sys.argv[0])
        params = " ".join(f'"{a}"' for a in sys.argv[1:])
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}" {params}', None, 1)
    else:
        # Re-launch with pkexec (GUI sudo) or sudo
        args = ["pkexec", sys.executable] + sys.argv
        os.execvp("pkexec", args)
    sys.exit(0)

if __name__ == "__main__":
    if not _is_admin():
        _elevate()

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    from config import APP_DIR, LIST_DIR
    os.makedirs(APP_DIR,  exist_ok=True)
    os.makedirs(LIST_DIR, exist_ok=True)

    import tkinter as tk
    from setup_window import SetupWindow
    root = tk.Tk()
    SetupWindow(root)
    root.mainloop()
