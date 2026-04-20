"""Attach-mode probe: run the exe manually first, then this script to list
modules and tell us what Python-looking DLL is actually loaded."""
import frida, sys, time

TARGET = "8v453l0sds.exe"  # PyInstaller onefile renames to lowercase in _MEI

SCRIPT = r"""
function dump() {
    const mods = Process.enumerateModules();
    send({tag: "count", n: mods.length});
    for (const m of mods) {
        if (/python|pyarmor|_MEI/i.test(m.name) || /python|_MEI/i.test(m.path)) {
            send({tag: "hit", name: m.name, path: m.path, base: m.base.toString()});
        }
    }
    send({tag: "done"});
}
dump();
setInterval(dump, 2000);
"""

def on_msg(m, d):
    if m["type"] == "send":
        print(m["payload"])
    else:
        print("[err]", m)

# find pid by name
dev = frida.get_local_device()
procs = [p for p in dev.enumerate_processes() if TARGET.lower() in p.name.lower()]
if not procs:
    print("[!] target not running. Launch 8V453l0SdS.exe manually first, then re-run this.")
    sys.exit(1)
print("[+] candidates:", [(p.pid, p.name) for p in procs])
# PyInstaller onefile spawns a child; the child is the real Python process.
# Pick the highest PID (spawned later).
pid = max(p.pid for p in procs)
print("[+] picking pid", pid)
session = frida.attach(pid)
s = session.create_script(SCRIPT)
s.on("message", on_msg)
s.load()
print("[+] attached to pid", pid, "— Ctrl-C to stop")
try:
    while True: time.sleep(1)
except KeyboardInterrupt:
    pass
