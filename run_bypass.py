"""Autobypass: launch the exe, wait for the PyInstaller child with libssl-3.dll,
attach bypass.js, rewrite the /verify response.

Usage: python run_bypass.py
"""
import frida, sys, time, subprocess, os
from pathlib import Path

HERE = Path(__file__).parent
TARGET = str(HERE / "8V453l0SdS.exe")
TARGET_NAME = "8v453l0sds.exe"
SCRIPT = (HERE / "bypass.js").read_text(encoding="utf-8")


def on_msg(msg, data):
    t = msg.get("type")
    if t == "send":
        print(msg["payload"])
    elif t == "log":
        print("[js]", msg.get("payload"))
    elif t == "error":
        print("[frida-error]", msg.get("stack") or msg.get("description"))


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


def wait_for_child(dev, parent_pid, timeout=20.0):
    """Poll process list until we find a child with libssl-3.dll loaded."""
    start = time.time()
    while time.time() - start < timeout:
        procs = [p for p in dev.enumerate_processes() if TARGET_NAME in p.name.lower()]
        for p in procs:
            if p.pid == parent_pid:
                continue
            if pid_has_libssl(dev, p.pid):
                return p.pid
        time.sleep(0.3)
    return None


def main():
    # Launch the exe in the background using Windows start — simplest and
    # avoids frida.spawn issues with the PyInstaller bootloader.
    subprocess.Popen([TARGET], shell=False)
    print(f"[+] launched {TARGET}")

    dev = frida.get_local_device()
    # Give the child a moment to appear and load libssl.
    child_pid = wait_for_child(dev, parent_pid=-1, timeout=30.0)
    if child_pid is None:
        print("[!] no child with libssl-3.dll appeared in 30s")
        sys.exit(1)
    print(f"[+] child pid={child_pid} has libssl-3.dll — attaching bypass")

    session = dev.attach(child_pid)
    script = session.create_script(SCRIPT)
    script.on("message", on_msg)
    script.load()

    print("[+] bypass armed. Interact with the GUI. Ctrl-C to exit.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        session.detach()


if __name__ == "__main__":
    main()
