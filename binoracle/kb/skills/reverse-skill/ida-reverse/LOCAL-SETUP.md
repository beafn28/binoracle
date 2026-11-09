# IDA ↔ reverse-skill Integration (Portable)

This page contains general steps and does not include absolute paths for any specific machine. The local readiness report is left in the root directory of the repository as `LOCAL-READINESS.md` (already gitignored).

## Target Form

| Item | Convention |
|------|------------|
| IDA Installation Directory | Environment variable `IDADIR` (directory contains `ida.exe` or `ida.dll`) |
| HTTP MCP | `http://127.0.0.1:13337/mcp` |
| Client Server Name | Only keep **`idapro`** (do not register `ida-pro-mcp` simultaneously) |
| Start | `scripts/start.ps1` (`--unsafe`, no `?ext=dbg`) |
| Open Database | Prioritize large files with `scripts/open.ps1`, do not call `idb_open` through partial clients |

Two MCP names pointing to the same 13337 will register the tool twice and compete for ports with idalib worker.

## Installation

```powershell
setx IDADIR "<你的 IDA 安装目录>"

# Must use mrexodia/ida-pro-mcp, do not install PyPI's ida-mcp
python -m pip install "git+https://github.com/mrexodia/ida-pro-mcp.git"

# Activate idalib (path adjusted to this machine's IDA)
python "<IDADIR>\idalib\python\py-activate-idalib.py" -d "<IDADIR>"

# Install plugins + client configuration
python -m ida_pro_mcp --install --transport streamable-http --scope global
```

## Startup and Maintenance

`type: http` MCP entries do not automatically start processes. Clients will all report error if 13337 is not listening.

| Script | Purpose |
|--------|----------|
| `scripts/start.ps1` | Health check returns `OK:<n>:reuse` and refreshes last-healthy; ports are listening but RPC timeout indicates busy, do not kill; replace managed supervisor only when no one is listening, missing `py_eval`, or tools/list fails continuously for more than 3 minutes (and without `opening.lock`); never kill `ida.exe` |
| `scripts/watchdog.ps1` | Minute-by-minute inspection; health reuse; GUI / `open.ps1` library lock / last-healthy not full 3 minutes → reuse; **tools/list fails continuously for more than 3 minutes before `-Force`** |
| `scripts/recover.ps1` | Immediately restart supervisor with `-Force` (do not kill `ida.exe`). Use this when HTTP client marks `idapro` as error. |
| `scripts/install-autostart.ps1` | Register scheduled task `reverse-skill-ida-mcp` (login + every minute) |
| `scripts/start-gui.ps1` | Open GUI plugin when idalib license fails |
| `scripts/open.ps1` | HTTP direct call to `idb_open`, bypassing partial client schema validation |

Logs: `%LOCALAPPDATA%\reverse-skill\ida-mcp\supervisor.log` and `watchdog.log`.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "skills\ida-reverse\scripts\start.ps1"
powershell -NoProfile -ExecutionPolicy Bypass -File "skills\ida-reverse\scripts\open.ps1" -Path "C:\path\to\target.exe" -TimeoutSeconds 600
powershell -NoProfile -ExecutionPolicy Bypass -File "skills\ida-reverse\scripts\install-autostart.ps1"
```

When GUI occupies 13337 but does not respond, `start.ps1` outputs `WARN:gui_busy` and exits to avoid killing the IDA being analyzed.

## Client

All point to Streamable HTTP: `http://127.0.0.1:13337/mcp`, server name `idapro`.

After changing configuration, a new session must be started. If the port is not listening when starting, the service will **not automatically reconnect** even if it is started later; manual refresh in MCP panel is required.

## Known Notes

1. System32 files: `open.ps1` copies to temporary path (output with `(temp copy)`)
2. Do not call `idb_open` through partial client MCP
3. `start.ps1` prioritizes `python -m ida_pro_mcp.idalib_supervisor`, more stable than `.cmd` wrapper
4. When formal installation and desktop portable package coexist, use `IDADIR`
5. Do not add `?ext=dbg` (default does not expose debugger tools)