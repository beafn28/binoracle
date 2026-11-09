# Red Team Sharp* Tool Analysis & Installation Matrix & dnSpy MCP

## Red Team Sharp* Tool Analysis

Red team tools are predominantly written in C# (Sharp* series), and reversing them is a common scenario: understanding detection logic, modifying features, extracting embedded configurations.

### Common Sharp* Tool Cheat Sheet

| Tool | Function | Reversing Focus |
|------|----------|-----------------|
| **Rubeus** | Kerberos Attacks (AS-REP roast / Kerberoast / S4U / pass-the-ticket) | Fixed Rubeus engineering structure, look for `Interop.*` P/Invoke segments to see native calls |
| **SharpHound** | BloodHound Data Collector | LDAP query logic, set of collected attributes |
| **SharpShell / SharpWS** | Remote Execution, Lateral Movement | WMI / WinRM calls, command obfuscation |
| **Seatbelt** | Information Gathering | List of collection items, judgment logic |
| **SharpRoast** | Kerberoasting | Ticket request/parse |
| **Inveigh / SharpSploit** | Man-in-the-Middle / General Exploitation Framework | Reflection loading, API call chain |

### Generic Analysis Routine

```text
1. Open with dnSpyEx (usually not obfuscated, some teams might use ConfuserEx)
2. Look at Program.Main or entry command dispatch (Rubeus uses a switch(command) structure)
3. Find the implementation class/method for the target command
4. Look at the P/Invoke segment (Interop.* namespace) — native API calls are here
5. Extract embedded resources (some tools embed configuration/templates)
6. If modifying features (EDR evasion): change command strings, API calls, string constants
```

### Rubeus Structure Example

Rubeus uses command dispatch, with each subcommand in a separate class. Find Kerberoasting logic:

```text
Entry: Rubeus.CommandLineParser → parse args
Dispatch: switch(command) → "kerberoast" → execute Ask.TGS(...)
P/Invoke: Rubeus.Interop.Lsa* / Native.cs → native Kerberos API
Key: LsaCallAuthenticationPackage (KERB_RETRIEVE_TKT_REQUEST)
```

Modify features (evasion): change the command string `"kerberoast"` to a custom name, change the `Rubeus` banner string, and reorder P/Invoke calls.

### Extracting Embedded Configurations

Many loaders/tools embed C2, keys, certificates encrypted in resources or fields:

```powershell
# In dnSpyEx, look at Resources (resource tree)
# Or from command line
powershell -c "[System.Reflection.Assembly]::LoadFile('target.exe').GetManifestResourceNames()"
# Find the resource and right-click → Extract / Save
```

Runtime decrypted configurations → dynamically break on the return point of the decryption method to dump plaintext (see `common-workflow.md`).

---

## Tool Installation Matrix

### Windows (Preferred, dnSpyEx is GUI)

```powershell
# Method A: Chocolatey
choco install dnspy ilspy de4dot detect-it-easy

# Method B: Manual download of release (recommended, version controlled)
# dnSpyEx:    https://github.com/dnSpyEx/dnSpy/releases
# de4dot:     https://github.com/de4dot/de4dot/releases
# ILSpy:      https://github.com/icsharpcode/ILSpy/releases
# DIE:        https://github.com/horsicq/Detect-It-Easy/releases
# dnlib:      dotnet add package dnlib  (NuGet)
```

### Linux / macOS (No dnSpyEx GUI, use CLI)

```bash
# ILSpy CLI decompilation
dotnet tool install -g ilspycmd
ilspycmd target.exe -p -o outdir/         # Decompile to directory

# de4dot cross-platform (requires mono or dotnet)
# Download de4dot product .dll from release, run with dotnet
dotnet de4dot.dll target.exe -o target-clean.exe

# dnlib (scripted, requires dotnet SDK)
dotnet new console -o dnclean && cd dnclean
dotnet add package dnlib

# DIE CLI (diec)
# Linux: Install from https://github.com/horsicq/Detect-It-Easy
diec target.exe
```

### .NET Runtime Prerequisites

```bash
# Linux
sudo apt install dotnet-runtime-8.0        # Or 6.0/7.0 depending on the target
# macOS
brew install --cask dotnet-sdk
```

> dnSpyEx (with IL editor + debugger) only has a Windows GUI version. For .NET reverse engineering on Linux/macOS, you can use `ilspycmd` decompilation + `dnlib` script patching; there is no equivalent interactive debugging GUI. Prioritize Windows when patching.

---

## dnSpy MCP Integration

The community has several dnSpy MCP projects that expose dnSpy's decompilation/IL inspection tools as MCP tools, allowing AI to be directly called —— aligning with the reverse-skill MCP philosophy.

### Mainstream dnSpy MCP Projects

| Project | Features | Compatibility |
|---------|----------|---------------|
| **soufianetahiri/dnspy-mcp** | Core MCP Server, exposes decompile, IL inspection tools | Claude Code / Cursor |
| **AgentSmithers/DnSpy-MCPserver-Extension** | Runs as a dnSpyEx extension, deeply integrates GUI | Loaded within dnSpyEx |
| **malwarecakefactory/dnspy-mcp-extension** | 33 tools, covering triage → deobfuscation full workflow | Full automation |

### Registering with Claude MCP Configuration

After installing the dnSpyEx extension corresponding to the project, register in `~/.claude/mcp.json` (specific command/args based on the project README):

```json
{
  "mcpServers": {
    "dnspy": {
      "command": "dotnet",
      "args": ["path/to/dnspy-mcp.dll"]
    }
  }
}
```

After registration, this skill's AI linkage path: User says "analyze this .NET" → routed to `dotnet-reverse/` → prioritize calling the `dnspy_decompile` / `dnspy_inspect_il` tool interface → if not possible, switch to GUI.

> dnSpy MCP is not a built-in bootstrap capability of reverse-skill; users need to manually install extensions and register as per the project README. Consider adding it to `bootstrap-manifest.json` in the future.

## Community Resource Index

### Strongly Recommended

- **Washi Blog** — .NET Reversing Expert: https://blog.washi.dev/posts/misconceptions-about-dotnet/
  - Core Viewpoint: **Do not over-rely on dnSpy's C# decompiler, familiarize yourself with the IL editor** (consistent with this project's IL priority principle)
- **dnSpyEx** — Active maintenance branch of dnSpy: https://github.com/dnSpyEx/dnSpy
- **de4dot** — .NET Obfuscation Removal: https://github.com/de4dot/de4dot
- **dnlib** — Metadata Programming: https://github.com/dnlib/dnlib

### Practical Tutorials

- Medium《De-obfuscating and reversing a .NET/C# spyware》— dnSpy + de4dot实战 info-stealer 脱混淆
- YouTube《dnSpy Patch .NET EXEs & DLLs》— Step-by-step patch + keygen
- Kuaishou Forum .NET Reversing Section — Search ".net 逆向" / "dnSpy" / "ConfuserEx" for numerous practical posts, Nuitka reverse engineering, and anti-malware discussions
- Guided Hacking《Top 5 .NET Reverse Engineering Tools》— dnSpy still ranks first
- StackExchange / Reverse Engineering — Advanced questions such as `DynamicMethod` debugging

### Resources in This Repository (Linked)

- `reverse-engineering/tools.md` `.NET Analysis` section — Quick reference for tools like dnSpy/ILSpy + Codegate 2013 two-stage XOR+AES-CBC mode
- `reverse-engineering/field-notes.md` `.NET` section — Tool quick reference
- `reverse-engineering/awesome-re-resources.md` — de4dot included
- `field-journal/seed-014_unity-il2cpp-reverse.md` — Unity IL2CPP (native side, complementary to .NET managed layer)

.NET Reversing deep content is unified in this module. Only keep the quick reference index in `reverse-engineering/`.