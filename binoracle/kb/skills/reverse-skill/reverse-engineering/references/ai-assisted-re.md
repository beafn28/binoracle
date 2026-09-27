# AI-Assisted Reverse Engineering

> LLM-driven decompilation / Multi-Agent validation / Neural semantic recovery
> 2025-2026 Maximum paradigm shift

## Core Tools and Models

### LLM4Decompile
- The first open-source framework to use LLM for binary→source code decompilation
- Supports multi-architecture: x86/ARM/MIPS
- Input: assembly code → Output: C source code
- Training data: millions of source-code-assemble pairs

### Decaf (2026)
- **Compiler feedback validation**: Converts LLM-generated source code→compiles→compares with original binary
- Effect: Decompilation rate 26% → 83.9% (ExeBench Real -O2)
- Key insight: Feedback loop is more effective than larger models

### Constraint-Guided Multi-Agent (2026)
- Three-tier validation pipeline:
  1. Syntax correctness (parsing)
  2. Compilability (GCC)
  3. Behavioral equivalence (LLM-generated test cases)
- 84-97% re-executability, each costing $0.03-0.05

### REMEND (2026)
- Specialized: Extracts mathematical equations from binary
- Accuracy: 89.8-92.4% across 3 ISA × 3 optimization levels × 2 languages
- Speed: 0.132s/function, only 12M parameters

### Glaurung
- Open-source Ghidra alternative, Rust kernel + Python bindings
- **AI-native architecture**: LLM Agent embedded in each analysis layer
- Evidence artifacts: plain/rich/JSON/JSONL multi-format output for LLM consumption
- Supports: ELF/PE/Mach-O, x86/ARM/RISC-V, IOC detection, entropy analysis

## Workflow: AI-enhanced binary analysis

### 1. LLM-assisted quick reconnaissance

```text
□ strings extraction → LLM semantic classification (URL/key/path/protocol)
□ Import table analysis → LLM infers functionality (encryption=OpenSSL? network=libcurl?)
□ Disassembly snippet → LLM identifies patterns (password algorithms, anti-debugging, VM detection)
□ Error messages → LLM infers context ("Invalid license" → licensing logic position)
```

### 2. Neural decompilation

```bash
# LLM4Decompile
python llm4decompile.py --binary target.so --arch arm64 --output target.c

# Validation results (recompile + compare)
gcc -O2 -o target_recompiled target.c -fPIC -shared
# → Validate output behavior equivalence
```

### 3. Multi-Agent validation

```text
Agent 1 (syntax): Checks if generated C code can be parsed
  ↓ Failure → Feedback error information to LLM for retry
Agent 2 (compile): GCC compile → Check warnings/errors
  ↓ Failure → Feedback compilation errors to LLM
Agent 3 (behavior): LLM generates input → Runs original and recompiled versions → Compares output
  ↓ Inconsistent → Feedback differences to LLM → Iterative correction
```

### 4. LLM-assisted static analysis

```text
□ Function renaming: Input decompiled pseudocode → LLM suggests semanticized names
□ Type recovery: Analyzes context → LLM infers struct/class definitions
□ Algorithm recognition: Assembly snippet → LLM identifies password algorithms (AES/TEA/RC4/custom)
□ Protocol reverse-engineering: Network packet sequence → LLM infers protocol format
□ Comment generation: Decompiled code → LLM generates Chinese/English comments
```

### 5. macOS/iOS private framework reverse (MOTIF)

```text
Problem: macOS private frameworks lack documentation, missing type information
Solution: LLM analyzes usage patterns → Infers method signatures and parameter types
Effect: ObjC signature recovery 15% → 86% (vs static analysis)
```

## LLM Prompt Templates

### Function semantic analysis

```
You are a reverse engineering expert. Analyze this decompiled function:

[伪代码]

1. What does this function do? (one sentence)
2. Suggest a meaningful function name.
3. What are the input parameters and their likely types?
4. What is the return value?
5. What external APIs/functions does it depend on?
6. Any security-relevant operations (crypto, auth, network, file I/O)?
```

### Algorithm recognition

```
Analyze this assembly/disassembly for cryptographic operations:

[汇编代码]

1. Is this a known cryptographic algorithm? (AES/DES/RC4/TEA/ChaCha20/custom?)
2. Identify the key schedule and round structure.
3. What is the key size?
4. Are there any hardcoded constants that identify the algorithm?
```

### Protocol format inference

```
Given this network packet sequence, infer the protocol structure:

[hex dump]

1. Identify magic bytes and length fields.
2. Propose a struct definition for the packet header.
3. What field(s) appear to be checksums/CRCs?
4. Is this a known protocol or custom?
```

## Tool Selection

| Scenario | Recommended Tool | Cost |
|----------|------------------|------|
| Quick decompilation | LLM4Decompile | Free (local GPU) |
| High-precision decompilation | Constraint-Guided Multi-Agent | ~$0.05 per binary |
| Mathematical function extraction | REMEND | Free |
| Cross-platform RE | Glaurung (Rust) | Free open-source |
| LLM interaction | Claude API / GPT-4 / DeepSeek | ~$0.01-$0.10 per request |

## Limitations

- **Complex control flow**: Virtualized/confused code still difficult (control flow flattening, VMProtect)
- **Indirect calls**: Vtables, function pointers hard to recover
- **Inline functions**: Compiler inlining blurs boundaries
- **Floating-point operations**: Semantic recovery of vector instructions有待提升
- **Context window**: Large functions (>1000 lines) exceed LLM context limit

Source: Decaf (2026), REMEND (2026), Constraint-Guided Multi-Agent Decompilation (2026), LLM4Decompile, Glaurung