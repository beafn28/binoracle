---
name: go-rust-reverse
description: Use for reverse engineering stripped Go and Rust binaries including runtime recognition, pclntab/moduel data recovery, panic strings, and idiomatic decompilation recovery.
---

# Go / Rust Binary Reverse Engineering

## ACTION REQUIRED（读完后立刻执行）

1. `NOW`: Read `../field-journal/precedent-reverse.md`
2. `NOW`: Confirm the sample is a Go/Rust compiled product (`file`/strings/runtime features)
3. `NEXT`: Is GoReSym / related plugins available?
4. `ACT`: Runtime recognition → Symbol/metadata recovery → Business logic

## Applicable Scenarios

- Stripped Go malicious software/tools
- Rust distribution binaries, panic string-driven analysis
- Language-specific methods complementary to generic ida/ghidra

## Workflow

### Go

```text
□ Identify go.buildid, runtime symbols, pclntab
□ GoReSym / redress / IDA Go plugin recover function names
□ Note interface, slice, string structures in decompilation
□ Network/cryptography library paths: crypto/* net/http
```

### Rust

```text
□ Panic strings, rust_begin_unwind, crate path hints
□ Code bloat due to generic instantiation; locate string xrefs first
□ Asynchronous/tokio state machines need cross-referencing
```

### Dynamic

```text
□ Still usable Frida; note Go stack and scheduling
□ Prioritize log and configuration string-driven breakpoints
```

## Toolchain

| Tool | Purpose |
|------|--------|
| GoReSym | Go metadata |
| IDA/Ghidra + Go/Rust plugins | Decompilation |
| radare2 | Quick strings |
| strings / rabin2 | Diagnosis |

## References

- `references/go-rust-notes.md`
- `../reverse-engineering/go-reverse.md` `../ida-reverse/` `../ghidra-reverse/`
- seed: `field-journal/seed-002_go-malware-stripped.md`

## Routing Context

**Upstream**: MASTER R33  
**Downstream**: Malware analysis flow `malware-analysis`; Generic RE `reverse-engineering`

## Task Completion Self-Check

- [ ] Did key function names or equivalent mappings get recovered?
- [ ] Did language runtime evidence get annotated?
- [ ] Checklist?