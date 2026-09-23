---
name: ghidra-reverse
description: Use for free/open reverse engineering with Ghidra (headless or GUI), including decompile, cross-refs, and optional Ghidra MCP workflows when IDA is unavailable.
---

# Ghidra Reverse Engineering

## ACTION REQUIRED（读完后立刻执行）

1. `NOW`: Read `../field-journal/precedent-reverse.md`
2. `NOW`: Confirm the need for **Ghidra** (no IDA / preference for open-source / batch headless)
3. `NEXT`: Read `../tool-index.md` to find ghidra / ghidra-mcp paths
4. `NEXT`: Missing tools → bootstrap `ghidra-mcp` (if manifest supports) or install Ghidra manually
5. `ACT`: Import sample → Automatic analysis → Export key function decompilations

## Applicable Scenarios

- Main reverse engineering entry when IDA license is unavailable
- Batch headless analysis / decompilation in CI
- Ghidra scripts (Java/Python Jython/PyGhidra) automation
- Integration with `binary-diff` / `patch-diff-exploit` using ghidriff

## Division of Labor with IDA

| Requirement | Priority |
|-------------|----------|
| Existing IDA MCP deep dive | `ida-reverse/` |
| Open-source / batch / teaching | **This skill** |
| CLI quick reconnaissance only | `radare2/` |

## Workflow

### 1. Project and Automatic Analysis

```text
□ Create Project → Import file → Analyze (default analyzer)
□ Record language/compiler recognition results and base address
□ Mark entry points, export tables, string cross-references
```

### 2. Key Functions

```text
□ Reverse from strings / imported APIs
□ Restore algorithm in Decompile window
□ Rename functions/variables; write Plate comments
□ Hand over to Frida/GDB when dynamic (reverse-engineering dynamic chapters)
```

### 3. Headless (Batch)

```bash
# Example: analyzeHeadless path varies by installation, MUST be taken from tool-index
analyzeHeadless /path/to/project Proj -import sample.bin -postScript ExportDecomp.py
```

### 4. MCP (if configured)

```text
□ Confirm Ghidra MCP port (commonly 8765, based on tool-index)
□ Use MCP tools to pull decompilations/xrefs, do not guess ports
```

## Toolchain

| Tool | Purpose | Bootstrap |
|------|---------|-----------|
| Ghidra | Main decompiler tool | Manual release / package manager |
| ghidra-mcp | AI bridge | Bootstrap capability name `ghidra-mcp` |
| ghidriff | Patch diff | See `patch-diff-exploit` |

## References

- `references/ghidra-cheatsheet.md`
- `../ida-reverse/` `../radare2/` `../binary-diff/`

## Routing Context

**Upstream**: MASTER R22  
**Downstream**: Dynamic validation → Frida/GDB; Exploit → `pwn-chain`  
**Peer**: `ida-reverse` (commercial deep dive)

## Task Completion Self-Check

- [ ] Based on real Ghidra/tool-index paths?
- [ ] Function addresses and renaming marked?
- [ ] Reproducible steps available?
- [ ] Checklist / journal?