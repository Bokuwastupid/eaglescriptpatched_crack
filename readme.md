# Crack writeup: 8V453l0SdS.exe (crackmes.one, difficulty 5/6)

PyInstaller onefile + PyArmor + online license check with HWID. Bypass via
Frida-injected TLS response rewriter. Final deliverable: single self-contained
`LicenseBypass.exe`.

## Target analysis

| Property | Value |
|---|---|
| Format | PE x64 (Windows) |
| Packer | PyInstaller onefile |
| Python | 3.12 |
| Obfuscator | PyArmor (pyarmor_runtime_000000) |
| UI | Tkinter (CustomTkinter theme) |
| Net stack | `requests` + `urllib3` over TLS (`libssl-3.dll`) |
| Endpoint | `https://eaglescript.space:5643/verify` |
| Process layout | Parent bootloader + Python child (two `*.exe` entries) |

Ghidra MCP on the raw EXE confirmed it is just the PyInstaller C bootloader
(strings `[PYI-%d:%s]`, `PYINSTALLER_RESET_ENVIRONMENT`, `PyImport_ImportModule`,
`pyi-python-flag`). All real logic lives inside the bundled `.pyc` files, so
patching the EXE is pointless — the branches we care about don't exist there.

## Why the obvious paths didn't work

1. **Static decompilation of `main.pyc`** — `pycdc` dumps `from pyarmor_runtime_000000 import __pyarmor__; __pyarmor__(__name__, __file__, b'PY000000...')`. Bytecode is encrypted; a native runtime swaps in the real code objects at execution time. Dead end from source alone.
2. **Patching the license check in the `.pyc`** — there is nothing to patch; the check outcome is decided by the server, not locally.
3. **Network mock (mitmproxy / hosts redirect)** — `requests` ships with a pinned CA bundle via `certifi`. Making the Python code trust a custom CA means either modifying the bundle or recompiling — both fragile across updates and more work than necessary.

## Chosen approach

Hook `SSL_read` / `SSL_read_ex` in `libssl-3.dll` and rewrite the HTTP
response body in place. This runs below PyArmor entirely — the obfuscator
has no visibility into what the OpenSSL buffer contains after decryption.
The Python layer sees our synthetic `{"status":"ok"}` payload and follows
the success branch.

## Tooling used

- `pyinstxtractor-ng` — extract the PyInstaller archive
- `pycdc` — decompile `.pyc` (only useful for identifying PyArmor)
- `frida` + `frida-tools` (17.9.1)
- `x64dbg` — initial peek at the GUI flow
- Ghidra + Ghidra MCP — confirm PyInstaller bootloader
- `PyInstaller` — build the final standalone bypass EXE

## Step-by-step reproduction

### 0. Setup

```bash
pip install frida frida-tools pyinstxtractor-ng pyinstaller
```

### 1. Unpack the PyInstaller bundle

```bash
pyinstxtractor-ng 8V453l0SdS.exe
```

Output: `8V453l0SdS.exe_extracted/` with `main.pyc`, `pyarmor_runtime_000000/`,
`PYZ-00.pyz_extracted/` etc.

### 2. Try to decompile the entrypoint

```bash
tools/pycdc.exe 8V453l0SdS.exe_extracted/main.pyc
```

Result:
```python
from pyarmor_runtime_000000 import __pyarmor__
__pyarmor__(__name__, __file__, b'PY000000\x00\x03\x0c\x00\xcb\r\r\n...')
```

Confirms PyArmor. Skip static analysis, move to dynamic.

### 3. Identify which process runs Python

PyInstaller onefile spawns a child. Only the child has `python312.dll`.
[probe.py](probe.py) attaches to each `8V453l0SdS.exe` PID and dumps loaded
modules. In the child we find:

```
python312.dll       @ C:\Users\...\Temp\_MEI38682\python312.dll
libssl-3.dll        @ C:\Users\...\Temp\_MEI38682\libssl-3.dll
pyarmor_runtime.pyd @ C:\Users\...\Temp\_MEI38682\pyarmor_runtime_000000\
```

The child's PID is **not** always `max(pids)`; reliable selector is "process
where `python312.dll` is loaded." See [run_bypass.py](run_bypass.py#L38).

### 4. Recon the license-check path

[recon.js](recon.js) hooks CPython comparison primitives in `python312.dll`:

- `PyUnicode_RichCompare`
- `PyObject_RichCompareBool`
- `PyUnicode_Compare` / `_PyUnicode_Equal`
- `PyDict_GetItemString` (filtered to license-y keys)

Tkinter's event loop generates an enormous amount of string-compare noise
(`tkerror`, widget ids, `update`, `check_dpi_scaling`, …). Two filters fix
it: per-entry noise regex, and a gated recording window (press Enter to
ARM right before clicking Verify). See the `NOISE` regex and the
`rpc.exports.start/stop` handlers in [recon.js](recon.js).

Key observations after one armed Verify click with a junk key:

```
https://eaglescript.space:5643/verify                    ← endpoint
POST                                                       ← method
UUID ... 03000200-0400-0500-0006-000700080009            ← HWID via PowerShell Get-CimInstance
content-length: 94 bytes (outgoing JSON — key + HWID)
content-length: 50 bytes (response body)
```

### 5. Discover the response schema

First attempt at rewriting guessed the body shape. Hooking `SSL_read`
logged the actual failure payload:

```
[ssl_read 134B] HTTP/1.1 400 Bad Request\r\ndate: ...\r\nserver: uvicorn\r\ncontent-length: 50\r\ncontent-type: application/json\r\n\r\n
[ssl_read  50B] {"status":"error","message":"Invalid product key"}
```

So the schema is `{"status": "...", "message": "..."}` and the server uses
HTTP `400` (not 200) for failure. The success branch expects `status == "ok"`
(inferred; confirmed by the bypass working).

### 6. Build the SSL rewriter

[bypass.js](bypass.js) hooks both `SSL_read` and `SSL_read_ex` in
`libssl-3.dll`. Two cases, because headers and body arrive in separate
TLS records:

| Chunk type | Action |
|---|---|
| starts with `HTTP/1.x NNN` | rewrite to `HTTP/1.1 200 OK`, fix `Content-Length` to match `SUCCESS_BODY` length |
| standalone body matching `{...status...}` | replace with `SUCCESS_BODY` |

```javascript
const SUCCESS_BODY = '{"status":"ok","message":"License verified"}';
```

Crucial Frida-specific details:

- Frida 17 changed module API — use `mod.findExportByName(name)` not the
  deprecated global `Module.getExportByName(modName, name)`.
- When the hooked read returned a new length, call `retval.replace(n)` for
  `SSL_read`, or update the `*readbytes` out-parameter for `SSL_read_ex`.
- PyInstaller loads `libssl-3.dll` lazily from `_MEI*`. Either poll for the
  module or hook `kernel32!LoadLibraryExW` and install on `onLeave`.

### 7. Drive from Python

[run_bypass.py](run_bypass.py) launches the target, polls until a child
with `libssl-3.dll` exists, attaches `bypass.js`, and stays alive. Run:

```bash
python run_bypass.py
```

Any input → click Verify → success.

### 8. Ship as a single EXE

Wrap everything into [launcher.py](launcher.py) and freeze:

```bash
pyinstaller --onefile --noconsole --name LicenseBypass \
    --add-data "bypass.js;." \
    --add-data "8V453l0SdS.exe;." \
    launcher.py
```

Result: `dist/LicenseBypass.exe` (~82 MB — includes Frida + CPython +
the target itself). Double-click launches target + injects bypass silently.

## File inventory

| File | Role |
|---|---|
| [bypass.js](bypass.js) | Frida script — TLS response rewriter |
| [recon.js](recon.js) | Frida script — string-compare logger used during discovery |
| [launcher.py](launcher.py) | Standalone entrypoint for the frozen EXE |
| [run_bypass.py](run_bypass.py) | Dev-mode driver (attaches bypass.js) |
| [run_recon.py](run_recon.py) | Dev-mode driver (attaches recon.js with ARM/DISARM gate) |
| [probe.py](probe.py) | Dumps loaded modules of a running target — for picking the right PID |
| [launch.bat](launch.bat) | Lightweight alternative to the frozen EXE |
| [dist/LicenseBypass.exe](dist/LicenseBypass.exe) | Final standalone bypass |

## Lessons / notes for the next time

- For a PyInstaller+PyArmor target, **never waste time on bytecode**. Hook
  CPython or, better, the layer underneath (sockets/TLS). PyArmor protects
  bytecode, not data.
- The "right PID" for a PyInstaller onefile is not `max(pids)` — it's the
  one where the Python DLL is mapped. A tiny probe script is the reliable
  filter.
- Tkinter floods `PyUnicode_RichCompare` with thousands of interned string
  comparisons per second. Any unconditional logger is useless — gate by
  time window, filter by noise regex, or both.
- When hooking OpenSSL, assume headers and body arrive as separate records.
  Patch headers (status + `Content-Length`) and body independently, not as
  a single buffer.
- Frida 17 moved exports to the `Module` instance — update any script that
  still calls `Module.getExportByName(name, fn)`.
- Antivirus will flag PyInstaller + Frida + cross-process injection. It's
  a correct heuristic; whitelist the artifact if you need it to run.
