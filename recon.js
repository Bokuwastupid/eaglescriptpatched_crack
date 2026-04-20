// Recon v2: noise-filtered, gated by external trigger.
// Tkinter flood makes raw logging useless; we only record comparisons during
// a short window that the controller script opens when the user is about to
// click Verify.

const CMP_OP = { 0: "<", 1: "<=", 2: "==", 3: "!=", 4: ">", 5: ">=" };

let installed = false;
let pyMod = null;
let PyUnicode_AsUTF8 = null;
let recording = false;

// Tkinter / CTk widget id + known boring strings. If either side of a compare
// matches, drop it.
const NOISE = /^(\d{10,}|tkerror|exit|destroy|iconic|update|user|system|check_dpi_scaling|_update_dimensions_event|_focus_in_event|on_closing|zoomed|normal|withdrawn|tcl|tk|https?|ftp|hdl|prospero|imap|self|request|timeout|verify|cert|stream|proxies|allow_redirects|key_[a-z_]+|blocksize|host|port|maxsize|block|headers|retries|_proxy.*|_cls|num_pools|cnf|require_redraw|_scan|vk|char|is_dead|strict|HTTP\/[0-9.]+|date|server|content-[a-z]+|application\/json|message\/[a-z-]+|multipart|application|transfer-encoding|connection|content-transfer-encoding|chunked|set-cookie2?|POST|HEAD|GET|gzip|x-gzip|deflate|br|zstd|urllib3|Request-(started|sent)|Idle|win32|darwin|windll|pointer|wintypes|level|proxy|text|method|url|data|json|key|hooks|hook_data|stdout|stdin|stderr|startupinfo|creationflags|input|capture_output|check|UNKNOWN|\/|\.|\.\.|@@@SKIP_HEADER@@@|logging\\\\__init__\.py|urllib3\\\\connectionpool\.py)$/i;
const NOISE_PREFIX = /^\d{10,}/;
const SINGLE_CHAR = /^.$/;  // drop single-char compares (they're always noise from Py interning)

function isNoise(s) {
    if (!s || s.length < 1) return true;
    if (SINGLE_CHAR.test(s)) return true;
    return NOISE.test(s) || NOISE_PREFIX.test(s);
}

function findExp(mod, name) {
    if (typeof mod.findExportByName === "function") {
        const a = mod.findExportByName(name);
        if (a && !a.isNull()) return a;
    }
    try {
        for (const e of mod.enumerateExports()) if (e.name === name) return e.address;
    } catch (_) {}
    return null;
}

function tryInstall() {
    if (installed) return true;
    let mod = null;
    for (const m of Process.enumerateModules()) {
        if (/^python3\d+\.dll$/i.test(m.name)) { mod = m; break; }
    }
    if (!mod) return false;

    pyMod = mod;
    console.log("[+] " + mod.name + " @ " + mod.base);

    const a = findExp(mod, "PyUnicode_AsUTF8");
    if (a) PyUnicode_AsUTF8 = new NativeFunction(a, "pointer", ["pointer"]);

    hook("PyUnicode_RichCompare", onCmpStr);
    hook("PyObject_RichCompareBool", onCmpBool);
    hook("PyDict_GetItemString", onDictGetEnter, onDictGetLeave);
    hook("PyUnicode_Compare", onUniCompare);
    hook("_PyUnicode_Equal", onUniEqual);

    installed = true;
    console.log("[*] hooks installed — use rpc to open/close recording window");
    return true;
}

function hook(name, onEnter, onLeave) {
    const addr = findExp(pyMod, name);
    if (!addr) return;
    try {
        Interceptor.attach(addr, { onEnter, onLeave });
        console.log("[+] " + name + " @ " + addr);
    } catch (_) {}
}

function isStr(obj) {
    if (obj.isNull()) return false;
    try {
        const ob_type = obj.add(Process.pointerSize).readPointer();
        const name = ob_type.add(Process.pointerSize * 3).readPointer().readCString();
        return name === "str";
    } catch (_) { return false; }
}

function reprObj(obj) {
    if (obj.isNull()) return null;
    try {
        if (isStr(obj) && PyUnicode_AsUTF8) {
            const p = PyUnicode_AsUTF8(obj);
            if (!p.isNull()) {
                const s = p.readUtf8String();
                if (s !== null && s.length < 600) return s;
            }
        }
    } catch (_) {}
    return null;
}

function logPair(tag, a, b, op) {
    if (!recording) return;
    if (a === null && b === null) return;
    // drop pure-noise pairs; keep if at least one side looks "interesting"
    const na = a === null ? true : isNoise(a);
    const nb = b === null ? true : isNoise(b);
    if (na && nb) return;
    console.log("[" + tag + "] " + JSON.stringify(a) + " " + op + " " + JSON.stringify(b));
}

function onCmpStr(args) {
    if (!recording) return;
    const a = reprObj(args[0]), b = reprObj(args[1]);
    logPair("cmp", a, b, CMP_OP[args[2].toInt32()] || args[2]);
}
function onCmpBool(args) {
    if (!recording) return;
    const a = reprObj(args[0]), b = reprObj(args[1]);
    logPair("bool", a, b, CMP_OP[args[2].toInt32()] || args[2]);
}
function onDictGetEnter(args) {
    if (!recording) return;
    try {
        const key = args[1].readCString();
        if (key && /valid|status|success|ok|key|license|result|error|msg|message|detail|token|hwid|hardware|uuid|user|data|auth/i.test(key)) {
            this._key = key;
        }
    } catch (_) {}
}
function onDictGetLeave(ret) {
    if (!recording || !this._key) return;
    const v = reprObj(ret);
    console.log("[dict] " + JSON.stringify(this._key) + " -> " + (v === null ? "<non-str>" : JSON.stringify(v)));
}
function onUniCompare(args) {
    if (!recording) return;
    const a = reprObj(args[0]), b = reprObj(args[1]);
    logPair("uni", a, b, "vs");
}
function onUniEqual(args) {
    if (!recording) return;
    const a = reprObj(args[0]), b = reprObj(args[1]);
    logPair("eq", a, b, "==");
}

rpc.exports = {
    start: () => { recording = true; console.log("=== RECORDING ON ==="); },
    stop: () => { recording = false; console.log("=== RECORDING OFF ==="); },
};

if (!tryInstall()) {
    console.log("[*] waiting for python3XX.dll...");
    for (const exp of ["LoadLibraryExW", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryA"]) {
        try {
            Interceptor.attach(Module.getExportByName("kernel32.dll", exp), {
                onLeave: function () { if (!installed) tryInstall(); }
            });
        } catch (_) {}
    }
    let ticks = 0;
    const iv = setInterval(() => { ticks++; if (tryInstall() || ticks > 150) clearInterval(iv); }, 200);
}
