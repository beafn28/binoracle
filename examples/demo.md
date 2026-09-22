# binoracle demo walkthrough

Assume a Linux CTF pwn binary `./chall` (authorized target).

## 1. What can I run right now?

```bash
binoracle doctor ./chall
```

Shows which oracles are live (radare2, pyelftools, angr, debugger) and whether a local
model is reachable.

## 2. Facts first, no model needed

```bash
binoracle triage ./chall
```

Deterministic, offline. You get: ELF header, checksec mitigations (NX/PIE/RELRO/canary),
imports, and a list of dangerous sinks with their callers. Every block is tagged with the
oracle that produced it.

## 3. Hunt (heuristic if no model, agentic if a model is up)

```bash
binoracle hunt ./chall            # add --dynamic to allow debugger PoCs
```

Without a model: grounded candidates from the sink oracle, scored by mitigation context.
With a local model: the agent traces reachability (r2_disasm, r2_xrefs, angr_reachable)
and promotes candidates to `verified` only when an oracle backs them.

## 4. Ask targeted questions

```bash
binoracle ask ./chall "trace how stdin reaches the first strcpy and whether it overflows"
```

## 5. Full report

```bash
binoracle report ./chall -o chall_report.md
```
