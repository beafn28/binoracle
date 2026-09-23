# IDA Pro MCP Tool Quick Reference

> ida-pro-mcp 2.x categorizes tools by function, includes common parameters and typical usage examples.
> Server name: `idapro`, tool prefix: `idapro_*`, runs in HTTP mode. Number of tools varies with version (around 66, including `py_eval`).

---

## Starting and Session Management

### Server Startup

```powershell
# Start MCP HTTP server (silently; healthy then OK:<n>:reuse)
powershell -File "scripts/start.ps1"
# Output OK:<tool count> to indicate readiness (approx. 66, including py_eval)

# Open target file (bypasses schema validation)
powershell -File "scripts/open.ps1" -Path "C:\target.exe"
# Output OK:filename:session_id

# Suggest adding timeouts for large files/GUI programs
powershell -File "scripts/open.ps1" -Path "C:\big.exe" -TimeoutSeconds 600

# Skip automatic analysis (for quick opening)
powershell -File "scripts/open.ps1" -Path "C:\huge.sys" -NoAutoAnalysis
```

### Session Tools

| Tool | Purpose | Example |
|------|---------|----------|
| `idapro_idb_list()` / HTTP `idb_list` | List all sessions | — |
| `idapro_idb_open()` / HTTP `idb_open` | Open database (prefer using `open.ps1`) | Large files use scripts |
| `idapro_idb_save(path)` / HTTP `idb_save` | Save database | Save analysis progress |
| `idapro_idb_current()` | Current bound session (if available) | — |
| `idapro_idb_switch(session_id)` | Switch to session | When comparing multiple files |
| `idapro_idb_close(session_id)` | Close session | Release resources |
| `idapro_server_health()` | Server health check | — |
| `idapro_server_warmup()` | Warm up subsystems | Before first use |

---

## Step 1: Global Overview

### survey_binary — Quick Overview

```powershell
idapro_survey_binary(detail_level="minimal")
```

Returns:
- Architecture (x86/x64/ARM/MIPS)
- Entry point
- Function count
- String statistics
- Segment information
- Import categories (encrypted/network/file I/O/registry)
- Hot functions with high xrefs

**detail_level options**:
- `"minimal"` — Quick overview (recommended first choice)
- `"standard"` — Includes more details
- `"full"` — Full information

### Function List

```powershell
# List all functions (paginated)
idapro_list_funcs(queries=[{"offset": 0, "limit": 50}])

# Filter by name
idapro_list_funcs(queries=[{"filter": "crypt", "offset": 0, "limit": 20}])
idapro_list_funcs(queries=[{"filter": "main", "offset": 0, "limit": 10}])
```

### Unified Query

```powershell
# Query imported functions
idapro_entity_query(kind="imports", filter="Create")

# Query strings
idapro_entity_query(kind="strings", filter="http")

# Query all named symbols
idapro_entity_query(kind="names", filter="")
```

---

## Decompilation and Disassembly

### Decompilation (Pseudo Code)

```powershell
# By function name
idapro_decompile(addr="main")
idapro_decompile(addr="sub_140001000")

# By address
idapro_decompile(addr="0x140001000")
```

### Disassembly

```powershell
# Default instruction count
idapro_disasm(addr="main")

# Specify instruction count
idapro_disasm(addr="0x401000", max_instructions=100)
```

### Comprehensive Analysis (Recommended)

```powershell
# Get all at once: pseudo code + strings + constants + callers + callees + basic blocks
idapro_analyze_function(addr="main", include_asm=false)

# Include assembly
idapro_analyze_function(addr="sub_401000", include_asm=true)
```

### Function Summary

```powershell
# Batch get function metrics (size, block count, xref count)
idapro_func_profile(queries=["main", "sub_401000", "sub_402000"])
```

---

## Cross-references and Call Graphs

### Who Calls the Target

```powershell
# See who calls a function
idapro_xrefs_to(addrs=["sub_401000"])

# See who references a string/data
idapro_xrefs_to(addrs=["0x404000"])

# Batch query
idapro_xrefs_to(addrs=["CreateFileW", "ReadFile", "WriteFile"])
```

### Advanced Xref Queries

```powershell
# Specify direction and type
idapro_xref_query(addr="0x401000", direction="to")    # Who calls me
idapro_xref_query(addr="0x401000", direction="from")  # Who I call
```

### List of Called Functions

```powershell
idapro_callees(addrs=["main"])
```

### Call Graph

```powershell
# Depth 3 from main
idapro_callgraph(roots=["main"], max_depth=3)

# Multiple starting points
idapro_callgraph(roots=["sub_401000", "sub_402000"], max_depth=2)
```

### Data Flow Tracing

```powershell
# Backward: Where does this value come from?
idapro_trace_data_flow(addr="0x401050", direction="backward", max_depth=5)

# Forward: Where does this value go?
idapro_trace_data_flow(addr="0x401050", direction="forward", max_depth=5)
```

---

## Search

### String Search (Regex)

```powershell
# Search URLs
idapro_find_regex(pattern="https?://", limit=20)

# Search file paths
idapro_find_regex(pattern="C:\\\\", limit=20)

# Search error messages
idapro_find_regex(pattern="error|fail|invalid", limit=30)

# Search related to keys/passwords
idapro_find_regex(pattern="key|password|secret|token", limit=20)
```

### Disassembly Text Search

```powershell
# Search in disassembly list
idapro_search_text(pattern="call    sub_")
idapro_search_text(pattern="xor     eax, eax")
```

### Byte Pattern Search

```powershell
# Exact bytes
idapro_find_bytes(patterns=["48 8B 05"], limit=10)

# With wildcards
idapro_find_bytes(patterns=["48 89 ?? 24 ??"], limit=10)

# Multiple patterns
idapro_find_bytes(patterns=["CC CC CC CC", "90 90 90 90"], limit=5)
```

### Advanced Search

```powershell
# Search immediate values
idapro_find(type="immediate", targets=["0xDEADBEEF"])

# Search string references
idapro_find(type="string", targets=["password"])
```

## Memory and Data Reading

### Reading Raw Bytes

```bash
idapro_get_bytes(addrs=[{"addr": "0x401000", "size": 64}])
```

### Reading Strings

```bash
idapro_get_string(addrs=["0x404000", "0x404100"])
```

### Reading Integers

```bash
idapro_get_int(queries=[{"addr": "0x405000", "size": 4}])
```

### Reading Global Variables

```bash
idapro_get_global_value(queries=["g_flag", "g_key_size"])
```

### Reading Structures

```bash
idapro_read_struct(queries=[{"addr": "0x405000", "type": "HEADER"}])
```

### Searching for Structs

```bash
idapro_search_structs(filter="FILE")
```

---

## Modification Operations

### Adding Comments

```bash
# Single comment
idapro_set_comments(items=[{"addr": "0x401000", "comment": "Decryption function entry"}])

# Batch comments
idapro_set_comments(items=[
    {"addr": "0x401000", "comment": "XOR decryption loop"},
    {"addr": "0x401050", "comment": "Key initialization"},
    {"addr": "0x4010A0", "comment": "Result verification"}
])

# Append comments (do not overwrite existing)
idapro_append_comments(items=[{"addr": "0x401000", "comment": "Supplement: Key length is 16"}])
```

### Renaming

```bash
# Rename function
idapro_rename(batch={"func": [
    {"addr": "sub_401000", "name": "decrypt_payload"},
    {"addr": "sub_402000", "name": "verify_license"}
]})

# Rename global variable
idapro_rename(batch={"global": [
    {"addr": "0x405000", "name": "g_encryption_key"}
]})

# Rename local variable
idapro_rename(batch={"local": [
    {"func": "decrypt_payload", "old": "v1", "name": "plaintext_buf"}
]})
```

### Patching Assembly

```bash
# NOP out detection code
idapro_patch_asm(items=[{"addr": "0x401050", "asm": "nop"}])

# Modify jump
idapro_patch_asm(items=[{"addr": "0x401060", "asm": "jmp 0x401080"}])

# Force return true
idapro_patch_asm(items=[
    {"addr": "0x401000", "asm": "mov eax, 1"},
    {"addr": "0x401005", "asm": "ret"}
])
```

### Patching Bytes

```bash
# Directly write bytes
idapro_patch(patches=[{"addr": "0x401050", "bytes": "9090909090"}])
```

---

## Type System

### Declaring Structures

```bash
idapro_declare_type(decls=[{
    "name": "PacketHeader",
    "decl": "struct PacketHeader { uint32_t magic; uint16_t type; uint16_t length; uint8_t data[0]; };"
}])
```

### Applying Types

```bash
# Set function prototype types
idapro_set_type(edits=[{
    "addr": "sub_401000",
    "type": "int __fastcall decrypt(void *buf, int size, const char *key)"
}])

# Set global variable type
idapro_set_type(edits=[{
    "addr": "0x405000",
    "type": "PacketHeader"
}])
```

### Inferring Types

```bash
idapro_infer_types(addrs=["sub_401000", "sub_402000"])
```

### Querying/Inspecting Types

```bash
idapro_type_query(queries=["Packet"])
idapro_type_inspect(queries=["PacketHeader"])
```

---

## Stack Frame Analysis

```bash
# View function stack frames
idapro_stack_frame(addrs=["main", "sub_401000"])

# Declare stack variables
idapro_declare_stack(items=[{
    "func": "sub_401000",
    "offset": -0x20,
    "name": "local_buf",
    "type": "char [32]"
}])
```

---

## Signature Generation

```bash
# Generate unique byte signatures for addresses
idapro_make_signature(addrs=["0x401000"])

# Generate signature for entire function
idapro_make_signature_for_function(addrs=["decrypt_payload"])

# Generate signature for code referencing an address
idapro_find_xref_signatures(addrs=["0x405000"])
```

---

## Base Conversion

```bash
# Hexadecimal to Decimal
idapro_int_convert(inputs=["0x401000"])

# Decimal to Hexadecimal
idapro_int_convert(inputs=["4198400"])

# Batch conversion
idapro_int_convert(inputs=["0xDEAD", "0xBEEF", "12345"])
```

> ⚠️ **Always use this tool for base conversions, never calculate manually!**

---

## Exporting and Scripts

### Exporting Functions

```bash
# JSON format
idapro_export_funcs(addrs=["main", "sub_401000"], format="json")

# C header file
idapro_export_funcs(addrs=["main", "sub_401000"], format="c_header")

# Function prototypes
idapro_export_funcs(addrs=["main", "sub_401000"], format="prototypes")
```

### Executing Python Scripts

```bash
# Execute Python in IDA context
idapro_py_eval(code="import idautils; print(list(idautils.Functions())[:10])")

# Get segment information
idapro_py_eval(code="import idc; print(idc.get_segm_name(0x401000))")

# Batch operations
idapro_py_eval(code="import ida_funcs; f=ida_funcs.get_func(0x401000); print(f.size())")
```

## Typical Analysis Flow

### Malware Analysis

```text
1. survey_binary → Check for imports (network APIs? Encryption? Registry?)
2. find_regex("http|socket|connect") → Find network-related strings
3. xrefs_to(network string addresses) → Find referenced functions
4. decompile(referenced function) → Examine communication logic
5. trace_data_flow(cryptographic parameters, "backward") → Trace key origins
6. set_comments + rename → Mark discovered findings
```

### Registration Validation Cracking

```text
1. find_regex("serial|license|register|valid") → Find validation-related strings
2. xrefs_to(validation string) → Locate validation function
3. analyze_function(validation function) → Understand its logic
4. callgraph(validation function, 2) → Examine the call chain
5. patch_asm(condition jump addresses, "jmp always_pass") → Patch
```

### CTF Inverse Engineering

```text
1. survey_binary → Confirm architecture and entry point
2. decompile(main) → Look at main logic
3. find_regex("flag|correct|wrong") → Find judgment points
4. trace_data_flow(judgment points, "backward") → Track input transformations
5. Use Python to assist in calculations or decryption → Obtain the flag
```

### Vulnerability Analysis

```text
1. entity_query(kind="imports", filter="strcpy|sprintf|gets") → Find dangerous functions
2. xrefs_to(dangerous function) → Locate call points
3. analyze_function(function at call point) → Examine context
4. stack_frame(function) → Confirm buffer size
5. trace_data_flow(hazardous parameters, "backward") → Confirm user-controllable inputs
```

---

## Common Errors and Solutions

| Error | Reason | Solution |
|-------|--------|-----------|
| "No database bound" | No file opened | Execute `open.ps1` |
| "Failed to open database" | Old library locked | Use `open.ps1` automatically downgrades to Temp |
| Schema validation fails | MCP client bug | Replace `idb_open` with `open.ps1` |
| Tool timeouts | Analysis of large files | Add `-TimeoutSeconds 600` |
| "ERR:timeout" (start.ps1) | Server startup failure | Check Python/idalib-mcp installation |
| Incorrect base conversion | Manual calculation error | Use `idapro_int_convert` |
| Function name not found | Name is imprecise | Use `list_funcs` + filter to search first |
```