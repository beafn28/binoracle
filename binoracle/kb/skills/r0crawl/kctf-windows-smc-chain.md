---
name: kctf-windows-smc-chain
description: KCTF 2026 第八题“亥子合辰·塔影迷楼”两级 SMC、反调试、Feistel 与 GF(2^127-39) 多项式求根的可复用解题流程。
---

# Question Type and Conclusion

The target file is a PE32+ x64. The entry does not directly execute the checker but completes two-level runtime decryption in memory; the decrypted checker encodes 16 printable characters as finite field elements, goes through five polynomial operations and two-way 20-round Feistel, and reverses to find roots in the finite field. The final input/Flag:

```text
kanxue@2o26o8!@#
```

## 1. Static Recovery of SMC from PE

`.tgt` provides parameters: `stage1_rva=0x1800`, `stage1_len=0x510`, `stage2_rva=0x1d10`, `stage2_len=0x4962`. Use section mapping to get the `bytearray` of the sections, no need to fix the import table.

Stage 1: XOR each byte of `img[0x1800:0x1d10]` with `0x5a`.

Calculate two sets of FNV-1a for Stage 1 plaintext:

```python
MASK=(1<<64)-1; PRIME=0x100000001b3
h1=0xcbf29ce484222325; h2=0x9e3779b97f4a7c15
for b in stage1:
    h1=((h1^b)*PRIME)&MASK
    h2=((h2^b)*PRIME)&MASK
```

This sample results: `h1=0x73fb4f498aab364f`, `h2=0xb157c7e044b966df`.

Stage 2 each byte:

```python
G=0x9e3779b97f4a7c15; C=0xff51afd7ed558ccd
for i in range(0x4962):
    t=((i*G)&MASK)^h1^h2
    t=(t^(t>>33))*C & MASK
    img[0x1d10+i] ^= t>>56
```

Get the effective x64 checker (about `0x140004380`). Dynamic software breakpoints may disrupt the second stage key stream; prefer offline decryption or use Unicorn simulation.

## 2. Checker Inversion

Input constraints: length 16, ASCII 33..126, and `sum(input)==0x500`. Base-94 Horner encoding:

```python
N=0
for b in inp: N=(N*94 + b-0x21) % P
P=(1<<127)-39
```

Runtime constants derived from Stage 2 two hashes; two-way Feistel each 20 rounds. When implementing reverse rounds, recover `(L,R)` in the opposite order and confirm that both paths of reverse derivation are the same. The common target given in the article:

```text
Y = 0x4be831b0ad3a2d361489375bba3fb8de
```

So construct:

```text
f(X)=X^5+FE0*X^4+FE1*X^3+FE2*X^2+FE3*X+(FE4-Y) mod P
```

Calculate `gcd(f, x^P-x)` on GF(P), then use Cantor–Zassenhaus (or random gcd splitting for five small polynomials) to find a single factor. Roots consecutive `%94` are expanded, each byte `+0x21`, check length/printability/ASCII and.

## 3. Anti-Debug Handling

The checker aggregates PEB.BeingDebugged, NtGlobalFlag, hardware breakpoints, ProcessDebugPort/Object, and multiple `rdtsc` differences mixed into a PRNG; debuggers will dirty constants/S-boxes. Offline decryption does not require handling; if dynamic execution is necessary, hook `rdtsc`, syscall, and set the accumulator `rbx=0`. Class `0x1e` returns `STATUS_PORT_NOT_SET` and buffer=0.

## Verification Checklist

- Two-stage decryption length and RVA correct; Stage2 start should be a normal x64 prologue.
- Both paths of 20-round Feistel reverse derivation yield the same `Y`.
- Roots `<94^16`, restored string is all printable characters with ASCII sum `0x500`.
- Original EXE running with input `kanxue@2o26o8!@#` passes.