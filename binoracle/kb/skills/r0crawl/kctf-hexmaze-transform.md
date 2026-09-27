---
name: kctf-hexmaze-transform
description: Solve KCTF byte-transform puzzles with fixed-size blocks, tail handling, and reversible nibble/byte mappings. Use when the challenge behaves like a deterministic encoder/decoder rather than a checker.
---

# KCTF 第七题 HexMaze·暗能潜流

## Core Conclusion
The input is printable ASCII, the key string `121` actually selects two nibble transformations, and the data is divided into 3-byte blocks in reverse order. Each 3-byte block is encoded as 6 bytes (with a fixed half-byte skeleton), and the tail block is determined by the length modulo 3.

## Workflow

1. Measure the block size, output expansion, and tail rule.
2. Compare one sample block against one wrong block.
3. Infer the forward transform on the smallest possible chunk.
4. Invert the transform block by block.
5. Replay the original sample before trusting the inverse.

## Reverse Algorithm

Extract valid half-byte positions `[0.high,1.high,1.low,2.low,4.high,5.high]` from each 6-byte ciphertext block and assemble them into 3 data bytes. Perform reverse transformation in cycles of key `1,2,1`:

* key=1 (encryption `(H,L)->(L+4,H+5)`): decryption `(a,b)->(H=b-5,L=a-4)`.
* key=2 (encryption `(H,L)->(H+5,L+4)`): decryption `(a,b)->(H=a-5,L=b-4)`.

After obtaining the intermediate string, perform left rotation on 3-byte blocks (`CAB→ABC`), reverse the block order; for remaining 2-byte blocks, swap them, and leave a single byte unchanged. FLAG example: `flag{T1u_2026_Kc7f_Crypt0_M4ster!}`.

## Verification

Replay the entire extraction, inverse nibble, and block rearrangement process using sample pairs like `TLU→94AA48550495` and `Hello→34BB405504B5223594B94C53`; confirm that the tail block format corresponds to `len mod 3`.

## Use this pattern

- 3-byte to 6-byte or other fixed-ratio expansion
- length-dependent tail handling
- deterministic byte/nibble mapping
- inverse derived from samples, not guesses

## Reference

- `references/pattern.md`