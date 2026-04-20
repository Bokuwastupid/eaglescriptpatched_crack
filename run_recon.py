"""Controller: attach recon.js and let the user gate the recording window
around the Verify click, so Tk noise doesn't drown out the real comparisons.

Usage:
  1. Launch 8V453l0SdS.exe by hand.
  2. python run_recon.py
  3. When told, type Enter to ARM, click Verify, wait for "Invalid product key",
     then type Enter to DISARM. The captured comparisons print between the
     two markers.
"""
import frida, sys, time, threading
from pathlib import Path

HERE = Path(__file__).parent
SCRIPT = (HERE / "recon.js").read_text(encoding="utf-8")
TARGET = "8v453l0sds.exe"


def on_message(msg, data):
    if msg["type"] == "send":
        print(msg["payload"])
    elif msg["type"] == "error":
        print("[frida-error]", msg.get("stack") or msg.get("description"))
    else:
        print(msg)


def pick_python_child():
    dev = frida.get_local_device()
    procs = [p for p in dev.enumerate_processes() if TARGET in p.name.lower()]
    if not procs:
        print("[!] target not running")
        sys.exit(1)
    print(f"[+] candidates {[(p.pid, p.name) for p in procs]}")
    for p in procs:
        try:
            s = frida.attach(p.pid)
            probe = s.create_script(
                "rpc.exports.check = () => Process.enumerateModules()"
                ".some(m => /^python3\\d+\\.dll$/i.test(m.name));"
            )
            probe.load()
            ok = probe.exports_sync.check()
            s.detach()
            if ok:
                return p.pid
        except Exception as e:
            print(f"[!] probe {p.pid}: {e}")
    print("[!] no child has python312.dll")
    sys.exit(1)


def print_script_console(script):
    # Frida prints console.log from script as on_message 'type: send' when we send(),
    # but console.log goes via 'type: log'. Handle both:
    pass


def main():
    pid = pick_python_child()
    print(f"[+] attaching to pid {pid}")
    session = frida.attach(pid)
    script = session.create_script(SCRIPT)

    def on_msg(msg, data):
        t = msg.get("type")
        if t == "send":
            print(msg["payload"])
        elif t == "log":
            print("[js]", msg.get("payload"))
        elif t == "error":
            print("[frida-error]", msg.get("stack") or msg.get("description"))

    script.on("message", on_msg)
    script.load()
    time.sleep(0.5)

    print("\n" + "=" * 60)
    print(" Press ENTER to ARM recording, then click Verify in the GUI.")
    print(" After 'Invalid product key' appears, press ENTER to stop.")
    print(" Ctrl-C to exit.")
    print("=" * 60)

    try:
        while True:
            input("\n>>> ENTER to ARM <<<")
            script.exports_sync.start()
            input(">>> ARMED — click Verify, then ENTER to STOP <<<")
            script.exports_sync.stop()
    except (KeyboardInterrupt, EOFError):
        session.detach()


if __name__ == "__main__":
    main()
