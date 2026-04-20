// Bypass for 8V453l0SdS.exe / eaglescript.space:5643/verify
//
// Observed server reply (for bad key):
//   HTTP/1.1 400 Bad Request
//   content-type: application/json
//   content-length: 50
//
//   {"status":"error","message":"Invalid product key"}
//
// We intercept SSL_read chunks coming from libssl-3.dll. Headers and body
// may arrive in separate reads, so we patch them independently:
//   - If a chunk starts with "HTTP/1.1 4xx", rewrite it to 200 OK and fix
//     Content-Length to match the JSON body we'll emit next.
//   - If a chunk looks like the JSON error body, replace it with a success
//     JSON of the same structure.
//
// The Python code then sees {"status":"ok", ...} and follows the success path.

const SUCCESS_BODY = '{"status":"ok","message":"License verified"}';

let sslMod = null;
let hooked = false;
// Track per-SSL connection what we did, so Content-Length stays consistent.
let lastSeenVerify = false;

function findExp(mod, name) {
    if (mod.findExportByName) {
        const a = mod.findExportByName(name);
        if (a && !a.isNull()) return a;
    }
    try { for (const e of mod.enumerateExports()) if (e.name === name) return e.address; } catch (_) {}
    return null;
}

function tryHook() {
    if (hooked) return true;
    for (const m of Process.enumerateModules()) {
        if (/^libssl-3\.dll$/i.test(m.name)) { sslMod = m; break; }
    }
    if (!sslMod) return false;

    const sslRead = findExp(sslMod, "SSL_read");
    const sslReadEx = findExp(sslMod, "SSL_read_ex");
    if (!sslRead && !sslReadEx) { console.log("[!] no SSL_read in libssl"); return false; }
    console.log("[+] libssl-3.dll @ " + sslMod.base);

    if (sslRead) {
        Interceptor.attach(sslRead, {
            onEnter(args) { this.buf = args[1]; this.cap = args[2].toInt32(); },
            onLeave(retval) {
                const n = retval.toInt32();
                if (n <= 0) return;
                const patchedLen = rewrite(this.buf, this.cap, n);
                if (patchedLen !== null && retval.replace) retval.replace(patchedLen);
            }
        });
        console.log("[+] hooked SSL_read @ " + sslRead);
    }
    if (sslReadEx) {
        Interceptor.attach(sslReadEx, {
            onEnter(args) { this.buf = args[1]; this.cap = args[2].toInt32(); this.pBytes = args[3]; },
            onLeave(retval) {
                if (retval.toInt32() === 0) return;
                const n = Number(this.pBytes.readU64());
                const patchedLen = rewrite(this.buf, this.cap, n);
                if (patchedLen !== null) this.pBytes.writeU64(patchedLen);
            }
        });
        console.log("[+] hooked SSL_read_ex @ " + sslReadEx);
    }
    hooked = true;
    return true;
}

function rewrite(buf, cap, n) {
    let text;
    try { text = buf.readUtf8String(n); } catch (_) { return null; }
    if (!text) return null;

    // Log small chunks for debugging
    if (n < 2000) {
        const esc = text.replace(/\r\n/g, "\\r\\n").slice(0, 300);
        console.log("[ssl_read " + n + "B] " + esc);
    }

    // Case 1: HTTP status line + headers (possibly with body appended).
    if (/^HTTP\/1\.[01]\s+\d{3}/.test(text)) {
        // Normalize status to 200 OK.
        let patched = text.replace(/^HTTP\/1\.[01]\s+\d{3}[^\r\n]*/i, "HTTP/1.1 200 OK");
        // Fix Content-Length to our success body size. If headers and body
        // are in one chunk we also replace body below; if body comes later,
        // we still need CL to match — we'll replace body with our fixed body.
        patched = patched.replace(/(content-length:\s*)\d+/i,
            "$1" + SUCCESS_BODY.length);

        // If this chunk also contains a body, swap it.
        const sep = patched.indexOf("\r\n\r\n");
        if (sep >= 0 && patched.length > sep + 4) {
            const headers = patched.slice(0, sep + 4);
            patched = headers + SUCCESS_BODY;
        }

        if (patched.length > cap) {
            console.log("[-] patched " + patched.length + "B > cap " + cap + "B; skipping");
            return null;
        }
        buf.writeUtf8String(patched);
        // Pad any remaining bytes in the claimed length with spaces so the
        // parser doesn't see stale junk (shouldn't matter because we return
        // the new length, but defensive).
        console.log("[+] rewrote headers+body -> 200 OK, CL=" + SUCCESS_BODY.length);
        lastSeenVerify = true;
        return patched.length;
    }

    // Case 2: standalone JSON body chunk following headers we already patched.
    if (lastSeenVerify && /^\s*\{[^]*"status"\s*:/i.test(text)) {
        if (SUCCESS_BODY.length > cap) return null;
        buf.writeUtf8String(SUCCESS_BODY);
        console.log("[+] rewrote JSON body -> " + SUCCESS_BODY);
        lastSeenVerify = false;  // consumed
        return SUCCESS_BODY.length;
    }

    return null;
}

if (!tryHook()) {
    console.log("[*] waiting for libssl-3.dll...");
    let t = 0;
    const iv = setInterval(() => { t++; if (tryHook() || t > 300) clearInterval(iv); }, 200);
}
