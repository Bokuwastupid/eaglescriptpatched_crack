"""Standalone launcher: start the target, find its child, inject bypass.js.
Designed to be frozen with PyInstaller into a single self-contained EXE.

Build:
    pyinstaller --onefile --noconsole --name LicenseBypass ^
        --add-data "bypass.js;." --add-data "8V453l0SdS.exe;." launcher.py

Run the resulting dist/LicenseBypass.exe — it launches 8V453l0SdS.exe and
silently bypasses the server check.
"""
import frida
import sys
import time
import subprocess
from pathlib import Path


def resource_path(name):
    """Resolve files both in dev mode and inside a PyInstaller onefile bundle."""
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return str(Path(base) / name)
    return str(Path(__file__).parent / name)


TARGET_EXE = resource_path("8V453l0SdS.exe")
BYPASS_JS = Path(resource_path("bypass.js")).read_text(encoding="utf-8")
TARGET_NAME = "8v453l0sds.exe"


def pid_has_libssl(dev, pid):
    try:
        s = dev.attach(pid)
        sc = s.create_script(
            "rpc.exports.check = () => Process.enumerateModules()"
            ".some(m => /^libssl-3\\.dll$/i.test(m.name));"
        )
        sc.load()
        ok = sc.exports_sync.check()
        s.detach()
        return ok
    except Exception:
        return False


def wait_for_child(dev, timeout=30.0):
    start = time.time()
    while time.time() - start < timeout:
        procs = [p for p in dev.enumerate_processes() if TARGET_NAME in p.name.lower()]
        for p in procs:
            if pid_has_libssl(dev, p.pid):
                return p.pid
        time.sleep(0.3)
    return None


def main():
    # Launch the target detached so we don't block on it.
    CREATE_NO_WINDOW = 0x08000000
    subprocess.Popen(
        [TARGET_EXE],
        creationflags=CREATE_NO_WINDOW,
        close_fds=True,
    )

    dev = frida.get_local_device()
    child = wait_for_child(dev, timeout=30.0)
    if child is None:
        return  # give up silently

    try:
        session = dev.attach(child)
        script = session.create_script(BYPASS_JS)
        script.load()
    except Exception:
        return

    # Keep the script alive as long as the target runs.
    try:
        while True:
            if not any(p.pid == child for p in dev.enumerate_processes()):
                return
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
