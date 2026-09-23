# IDA Pro 逆向分析技能

## ACTION REQUIRED (Read and Execute Immediately)

1. `NOW`: Read `../field-journal/precedent-reverse.md` — Confirm that this skill is an authorized routine operation.
2. `NOW`: Verify if the current task falls within the scope of this skill.
3. `NEXT`: Read `../tool-index.md`, verify tool availability and actual paths.
4. `NEXT`: Use the bundled scripts (scripts/start.ps1, scripts/open.ps1) for deterministic server management and file opening — do NOT write ad-hoc PowerShell commands for these operations.
5. `ACT`: Proceed to step one of the workflow and execute without stopping at confirmation states.

## Known Issues and Reflections (Must Read)

### Pitfalls

1. **`idb_open` (old name `idalib_open`) should not be directly called by partial AI clients via MCP**
   - Some code AI clients have a bug in their MCP client's output schema validation for open-type tools.
   - Error: `Structured content does not match the tool's output schema`.
   - **Solution**: Use the `scripts/open.ps1` script to call through HTTP API, bypassing the MCP validation layer.
   - Current ida-pro-mcp 2.x tools are named `idb_open`, `idb_list`, and `idb_save` (not `idalib_*`).
   - After opening a file, it returns a `session_id` (database), which subsequent tool calls need to include.

2. **Cannot open files in `C:\Windows\System32` directory due to permissions issues**
   - idalib cannot directly read files from the System32 directory.
   - **Solution**: The `open.ps1` script automatically detects and copies files to a temporary directory before opening them.

3. **Server startup commands block the dialog**
   - After starting `idalib-mcp`, it continuously outputs INFO logs to the console.
   - **Solution**: Use `scripts/start.ps1` (run in background with `-WindowStyle Hidden`) so that the service waits for readiness and then exits without blocking the dialog.

4. **MCP server name cannot contain hyphens**
   - Previously, using `ida-pro-mcp` as a server name might cause tool registration issues.
   - **Current Configuration**: Server name is `idapro`, with tool prefix `idapro_*`.

5. **Remote HTTP vs Local Stdio modes**
   - In the `type:"local"` (stdio) mode: `idalib_open` also has schema validation issues.
   - In the `type:"remote"` (HTTP) mode: files can be opened first using scripts, then analyzed with MCP tools.
   - **Current Solution**: Use Remote HTTP mode.

6. **PR #389 fixed some schema issues**
   - Author mrexodia merged PR #389 to fix issues in the HTTP mode structuredContent schema.
   - Some code AI clients still have schema validation problems on their side.
   - Ensure you are using the latest `main` branch version.

7. **idalib leaves orphan worker processes with lock files**
   - After a first `open.ps1` timeout, idalib's Python worker process might become an orphan and hang onto `.id0`, `.id1`, or `.nam`.
   - Any tool or manual drag into IDA GUI will result in "Insufficient permissions".
   - **Prohibit** using `taskkill /F /T` to kill the entire process tree—`/T` would also kill the GUI `ida.exe` child processes.
   - **Solution**: In `start.ps1`, only replace the managed supervisor when no one is listening on the port or if `tools/list` returns quickly but lacks `py_eval` (old supervisor). If RPC times out and 13337 is still listening, it's considered busy. Do not kill `ida.exe`.
   - **Deadlock Exception**: Replace the supervisor only if `tools/list` fails continuously for more than 3 minutes (based on last-healthy timestamp, not process creation time), has no in-flight `opening.lock`, and is not holding a GUI port.
   - **Fallback**: In `open.ps1`, automatically copy old libraries to Temp with GUID prefix when they are locked.

8. **Automatic analysis opening looks like it's stuck**
   - After calling `idalib_open(run_auto_analysis=true)`, the MCP tool might hang indefinitely, but the backend is actually continuing to open and analyze.
   - Previously users saw "PowerShell never outputs anything", which could be misinterpreted as a script deadlock.
   - **Current Solution**: In `open.ps1`, add `-TimeoutSeconds` and switch to background request + front-end polling + periodic progress output.
   - When the session is ready, it will return `OK:filename:session_id` early. If timeout occurs, it returns `ERR:open_timeout_xxs`.

9. **HTTP MCP exits silently after login**
   - Cursor/Claude's `type: http` does not automatically start a process; old task plans run only once upon login.
   - `pythonw` has no console and crashes leave empty Application logs.
   - **Solution**: In `start.ps1`, reuse the server if healthy. Use `watchdog.ps1` to check every minute. Logs are stored in `%LOCALAPPDATA%\reverse-skill\ida-mcp\`.
   - Installation: Run `scripts/install-autostart.ps1`. If MCP panel needs refreshing, do so manually when starting HTTP clients.

10. **Streamable HTTP GET `/mcp` can hang a single-threaded supervisor**
   - Some HTTP MCP clients might send long-lived connections to `/mcp` (SSE). The stock `idalib_supervisor` uses `background=False` for `HTTPServer`, processing one request at a time.
   - Result: `tools/list` times out, and the client marks `idapro` as error.
   - **Solution**: In `run-supervisor.py`, switch to `ThreadingHTTPServer` accepting GET `/mcp`. If patching fails, skip starting supervisor but still start it. When hung, use `scripts/recover.ps1` (force kill).

## Script Resources

### start.ps1 — Start MCP HTTP Server

Path: `scripts/start.ps1`

- Automatically resolves `IDADIR` (environment variable / portable desktop path / common installation paths)
- Prefers using Ida's built-in `Python314\python.exe -m ida_pro_mcp.idalib_supervisor`
- Defaults to probing `http://127.0.0.1:13337/mcp` for health; outputs `OK:<n>:reuse` and exits if healthy
- 13337 is listening but `tools/list` times out → outputs `WARN:busy` / `OK:busy:reuse`, **does not kill** (library or GUI occupying ports cannot respond)
- If `tools/list` fails continuously for more than 3 minutes (last-healthy timestamp) and no `opening.lock` exists → considers deadlock, outputs `INFO:deadlock` and `-Force` replaces supervisor. In-progress `idb_open` and GUI do not follow this path
- Only replaces managed supervisor if the port is unoccupied, missing `py_eval`, or there's a deadlock; **never kills `ida.exe`, no `taskkill /T`**
- GUI occupying 13337 outputs `WARN:gui_busy` and exits without starting a new supervisor
- Outputs `OK:<tool count>` (currently around 66) on success, `ERR:timeout` on failure
- Supervisor logs are stored in `%LOCALAPPDATA%\reverse-skill\ida-mcp\supervisor.log`
- The server runs in the background, not blocking communication

**Invocation Method**:
```
powershell -File "<skill-root>\ida-reverse\scripts\start.ps1"
```

### watchdog.ps1 / recover.ps1 / install-autostart.ps1 — Keep-alive

- `watchdog.ps1`: probes 13337; reuses if healthy (refreshes last-healthy); GUI or `open.ps1` opens lock, last-healthy under 3 minutes → reuse; only starts `start.ps1 -Force` if `tools/list` fails continuously for more than 3 minutes
- `recover.ps1`: immediately starts `start.ps1 -Force` (does not kill `ida.exe`). Used when HTTP clients mark `idapro` as error due to `idapro`.
- `install-autostart.ps1`: registers the scheduled task `reverse-skill-ida-mcp` (logged in + every minute)
- Logs are stored in `%LOCALAPPDATA%\reverse-skill\ida-mcp\watchdog.log`

### open.ps1 — Open Binary Files

Path: `scripts/open.ps1`

- Directly calls `idb_open` via HTTP API to bypass MCP schema validation
- Automatically detects System32 path and copies it to a temporary directory
- Automatically cleans up old database files (`.id0`, `.id1`, `.nam`, `.til`, `.i64`)
- Automatically downgrades if the old library is locked: copies to Temp with GUID prefix, opens without errors
- Queues opening requests to run in the background to avoid long sync waits causing script unresponsiveness
- Supports `-TimeoutSeconds`; outputs `ERR:open_timeout_xxs` on timeout and does not hang indefinitely
- Outputs `INFO:opening:已用时/超时秒数` every 10 seconds for monitoring, avoids hanging indefinitely
- Outputs `OK:文件名:session_id` on success (with `(temp copy)` if downgraded), outputs `ERR:open_timeout_xxs` on failure and retries using Temp副本

**Invocation Method**:
```
powershell -File "<skill-root>\ida-reverse\scripts\open.ps1" -Path "C:\path\to\file.exe"
```

**Optional Parameters**:
```
# Specify SessionId
powershell -File "scripts\open.ps1" -Path "file.exe" -SessionId "my_session"

# Skip automatic analysis (recommended for large files)
powershell -File "scripts\open.ps1" -Path "large.exe" -NoAutoAnalysis

# Set timeout to avoid hanging indefinitely with auto-analysis
powershell -File "scripts\open.ps1" -Path "file.exe" -TimeoutSeconds 600
```

**Output Convention**:
```
# Analysis in progress (output every 10 seconds)
INFO:opening:已用时/超时秒数

# Successful opening
OK:文件名:session_id

# Successful opening, but downgraded to Temp copy due to locked file
OK:文件名:session_id (temp copy)

# Timeout reached
ERR:open_timeout_xxs
```

**Real-World Explanation**:
- `Snipaste.exe` takes approximately `324s` to return on success; this is not a deadlock but analysis taking time.
- Therefore, when dealing with GUI programs or complex samples, it's recommended to set `-TimeoutSeconds 600` explicitly.

## Core Tools List

### Overview Analysis (Step 1)
- `idapro_survey_binary(detail_level="minimal")` — Quick Overview: number of functions, strings, segments, entry points, import categories (cryptographic/network/file I/O)
- `idapro_list_funcs(queries)` — List Functions (pagination, name filtering)
- `idapro_list_globals(queries)` — List Global Variables
- `idapro_entity_query(kind, filter)` — Unified Query: functions/globals/imports/strings/names

### Decompilation and Disassembly
- `idapro_decompile(addr)` — Decompile to pseudocode
- `idapro_disasm(addr, max_instructions=N)` — Disassemble
- `idapro_analyze_function(addr, include_asm=false)` — Comprehensive Analysis (pseudocode+strings+constants+callers+ callees+blocks)
- `idapro_func_profile(queries)` — Function Profile Metrics

### Cross-references and Data Flow
- `idapro_xrefs_to(addrs)` — Who references the target address?
- `idapro_xref_query(addr, direction)` — Advanced xref query (direction/type filtering)
- `idapro_callees(addrs)` — List of sub-functions
- `idapro_callgraph(roots, max_depth)` — Call graph
- `idapro_trace_data_flow(addr, direction, max_depth)` — Data flow tracing (forward/backward)

### Search
- `idapro_find_regex(pattern, limit)` — Regex search for strings
- `idapro_search_text(pattern)` — Text search in decompiled listings
- `idapro_find_bytes(patterns, limit)` — Byte pattern search (supports ?? wildcard)
- `idapro_find(type, targets)` — Advanced search (immediate numbers/strings/references)

### Memory and Data
- `idapro_get_bytes(addrs)` — Read raw bytes
- `idapro_get_string(addrs)` — Read strings
- `idapro_get_int(queries)` — Read integer values
- `idapro_get_global_value(queries)` — Read global variable values
- `idapro_read_struct(queries)` — Read struct field values
- `idapro_search_structs(filter)` — Search for structs

### Modification Operations
- `idapro_set_comments(items)` — Add comments (bidirectional synchronization between decompiled and reassembled)
- `idapro_append_comments(items)` — Append comments
- `idapro_rename(batch)` — Batch rename (functions/globals/local/stack variables)
- `idapro_patch_asm(items)` — Patch assembly instructions
- `idapro_patch(patches)` — Patch bytes
- `idapro_define_func(items)` — Define a function
- `idapro_undefine(items)` — Undefine
- `idapro_define_code(items)` — Convert bytes to code

### Type System
- `idapro_declare_type(decls)` — Declare C structs/enum/unions
- `idapro_set_type(edits)` — Apply type to functions/globals/local
- `idapro_infer_types(addrs)` — Infer types
- `idapro_type_query(queries)` — Query declared types
- `idapro_type_inspect(queries)` — Inspect types

### Stack Frames
- `idapro_stack_frame(addrs)` — View stack frame variables
- `idapro_declare_stack(items)` — Declare stack variables
- `idapro_delete_stack(items)` — Delete stack variables

### Signatures
- `idapro_make_signature(addrs)` — Generate a unique byte signature for addresses
- `idapro_make_signature_for_function(addrs)` — Generate a signature for a function
- `idapro_find_xref_signatures(addrs)` — Generate signatures for code referencing the given addresses

### Debugger (requires ?ext=dbg)
- `idapro_open_file(file_path)` — Open file in GUI IDA instance
- The debugger tools are hidden by default and can be enabled via URL parameter `?ext=dbg`

### Session Management (ida-pro-mcp 2.x)
- `idapro_idb_open` / HTTP `idb_open` — ⚠️ Recommended to use `open.ps1`
- `idapro_idb_list` / HTTP `idb_list` — List all sessions
- `idapro_idb_save` / HTTP `idb_save` — Save database
- Many analysis tools require the `database=<session_id>` parameter (output by open.ps1)

### Other
- `idapro_int_convert(inputs)` — Base conversion (**must use this, don't calculate bases yourself!**)
- `idapro_export_funcs(addrs, format)` — Export functions (json/c_header/prototypes)
- `idapro_py_eval(code)` — Execute Python in IDA context
- `idapro_server_health()` — Server health check
- `idapro_server_warmup()` — Warm-up subsystems (string cache, Hex-Rays, etc.)

## Reverse Engineering Complete Workflow

### Step 1: Start the Server

**Path A — Headless idalib (requires a valid license)**
```
powershell -File "scripts/start.ps1"
```
Output `OK:<number of tools>` (currently around 65) to indicate readiness.

**Path B — GUI + Plugins (if idalib license fails or interactive analysis is needed)**  
```
powershell -File "scripts/start-gui.ps1" -Path "C:\目标.exe"
```  
Or double-click the portable `Launch-IDA-Pro.cmd` in IDA to open the sample.

Ensure that the Output window shows `[MCP] ... port=13337` before using MCP tools.

See `LOCAL-SETUP.md` for general setup steps.

### Step 2: Open the File

**Headless Mode**
```
powershell -File "scripts/open.ps1" -Path "C:\目标.exe" -TimeoutSeconds 600
```  
Output `OK:file_name:session_id` to indicate success (with `(temp copy)` for automatic downgrade to a temporary file).

If you encounter `ERR:idalib_license:...`, switch to Path B (GUI mode) and do not retry the open.ps1 script.

**GUI Mode**: Open the sample directly in IDA without using open.ps1.

### Step 3: Global Overview (Including Hard Gates for Import Table)
```
idapro_survey_binary(detail_level="minimal")
```  
Focus on:
- Architecture (x86/x64/ARM)
- Entry Points (main/WinMain/DllMain)
- Interesting Strings (URLs, paths, error messages)
- **Import Categories (MUST)**: Encryption functions / Network APIs / File Operations / Process Injection / Registry — Must be recorded as Evidence (suggest ID: `E-imports`), can use `idapro_entity_query(kind="imports")` or the imports segment from the survey output.
- **DLL/SYS**: Export Table alongside Import Table (Evidence `E-exports`)
- **.NET**: When no traditional IAT, use module/metadata/managed references as equivalent anchors for E-imports semantics
- **Clean Import Table**: Mark dynamic loading suspicion and push dynamic API breakpoints verification
- Hot Functions (functions with high xref counts are usually key logic)

**Hard Gates**: Do not proceed to Step 4 without writing the import view/view summary (or valid equivalent anchor) into Evidence. Do not claim that the survey is complete. Record failure phenomena when Import Table is empty or query fails. Add `E-iat-repair-fail` for IAT repair failures and switch to dynamic debugging to capture API calls, avoid static analysis.

When users request a recheck of imports/IAT, redo the named step (with feasibility gate: explain+confirm; force with quality=unreadable), do not change unrelated steps.

### Step 4: Deep Dive into Key Functions
```
idapro_analyze_function(addr="关键函数名")
```  
Or:
```
idapro_decompile(addr="函数名")
idapro_disasm(addr="函数名", max_instructions=50)
```

### Step 5: Data Flow and Cross-References
```
idapro_xrefs_to(addrs="关键地址/字符串")
idapro_callgraph(roots=["关键函数"], max_depth=3)
idapro_trace_data_flow(addr="关键地址", direction="backward", max_depth=5)
```

### Step 6: Record and Optimize
```
idapro_set_comments(items=[{"addr": "0x140001000", "comment": "你的理解"}])
idapro_rename(batch={"func": [{"addr": "函数地址", "name": "有意义的名字"}]})
```

### Step 7: Output Report
After analysis, generate a `report.md` to record findings and steps.

## Prompt Engineering Guidelines

1. **Do not manually calculate bases** — Convert numbers at any time using `idapro_int_convert`.
2. **Survey first, then dive in** — Start with an overview before targeted analysis.
3. **Persistently add comments and rename** — Continuously update function names and variable names during the analysis to improve accuracy for subsequent steps.
4. **Track cross-references** — Discover interesting data/strings by using `xrefs_to` to see who references them.
5. **Preprocess obfuscated code** — Begin with string decryption, removing import hashes, flattening control flow, etc., before diving into the analysis.
6. **C++ STL Code**: After identifying library functions with FLIRT/Lumina, analyze business logic.
7. **Do not brute-force crack** — Use reverse disassembly to derive solutions and use simple Python for auxiliary calculations.
8. **Handle "No database bound"** — No binary files opened yet, run `open.ps1` first.
9. **Handle "Failed to open database"** — The old database file might be locked; `open.ps1` will automatically downgrade to a temporary copy (output with `(temp copy)`).
10. **For GUI/complex samples with automatic analysis** — Default add `-TimeoutSeconds 600`, do not mistake long `INFO:opening:...` for script hang.

---

## Context Routing

**Upstream Entry**: `skills/SKILL.md` (Master Control), `routing.md`
**Upstream Alternatives**: `radare2/` (if you prefer to use r2 quickly)
**Downstream Exit**:
- Need dynamic verification → `reverse-engineering/tools-dynamic.md`
- Need symbolic execution / angr → `reverse-engineering/tools-dynamic.md`
- Need general reverse engineering methodology → `reverse-engineering/SKILL.md`

**Peer Modules**: `radare2/` (alternative for when IDA is unavailable)

---

## On-Demand Bootstrap

This skill's entry script is integrated into the unified bootstrap system.

### Automation Capabilities Boundaries

| Tool | Can Automatically Install | Installation Method | Description |
|------|---------------------------|-----------------------|-------------|
| idalib-mcp | ✓ | pip install (from GitHub) | `start.ps1` missing, automatically installs |
| IDA Pro itself | ✗ | Commercial software, manual installation required | Set the environment variable `IDADIR` to point to the installation directory |

### Installation Steps (Verified)

```cmd
# 1. Set IDA path (replace with your actual IDA installation directory)
setx IDADIR "<yourIDAinstallationdirectory>"

# 2. Install ida-pro-mcp from GitHub (ida-mcp on PyPI is another project, don't install that one! )
pip install git+https://github.com/mrexodia/ida-pro-mcp.git

# 3. Install IDA plugins (choose Streamable HTTP + Global + Select All Client)
ida-pro-mcp --install

# 4. Restart IDA Pro and open the target file
# Plugin automatically listens on `127.0.0.1:13337`

# 5. Verify
ida-pro-mcp --config
```

> **Note**: The package `ida-mcp` (author jtsylve) from PyPI is another project, not the one we need.
> Must install `mrexodia/ida-pro-mcp` from GitHub.

### Bootstrap Trigger Points

- `scripts/start.ps1`: Calls `bootstrap-reverse.ps1` if `idalib-mcp` is missing
- MCP registration: The bootstrap automatically writes `idapro` to Claude MCP configuration

### Preceding Conditions

- IDA Pro installed and the `IDADIR` environment variable set (or script uses correct default path)
- Recommended use of IDA's built-in Python3.14 (`idalib-mcp`) in a portable version
- Common native configurations:
  - User env `IDADIR`: IDA installation directory (contains `ida.exe`)
  - Optional: `~\Tools\bin\idalib-mcp.cmd` / `ida-pro-mcp.cmd` wrapper scripts
  - Client MCP server name only keeps `idapro`: `http://127.0.0.1:13337/mcp`

## Task Completion Self-Inspection (Must Pass Before Claiming Completion)

- [ ] Have I executed each step in the workflow (rather than just reading about it)?
- [ ] Has survey/imports been written to Evidence (E-imports or equivalent)? Are DLL/SYS containing E-exports? Is IAT failure noted as E-iat-repair-fail?
- [ ] If a user requests re-doing of import tables/IAT, have I done the same step again?
- [ ] Have I used real tool paths based on `tool-index`?
- [ ] Have I produced reproducible evidence (commands/scripts/screenshots/reports)?
- [ ] Have I completed and back-written the RULES-required Checklist items?