---
name: kctf-9-ictf-linear-model
description: Recover the KCTF Ninth Question flag from a PyTorch/safetensors small language model with no embedding; convert argmax constraints to integer linear programming and verify the output.
---

# KCTF9：ICTFForCausalLM Linear Constraint Solving

## Applicable Scenarios

The model `forward` directly converts 16 token IDs to float, passing through `Linear(16→21)+ReLU+Linear(21→64)`; the `lm_head` success row has a huge negative bias. The goal is to find a 16-character string that makes token 62 (`<success>`) the argmax.

## Distillation Process

1. **Parse Model File**: Read safetensors (8-byte little-endian header length, JSON header, followed by float32 data), extract `dense.weight/bias` and `lm_head.weight/bias`, no need to install torch.
2. **Identify Output Constraints**: The success row logit is like `h0 - 1e10·Σ(h1..h20) - 376131.21875`, while the fail row is always `0.4`. Therefore, the feasible conditions are
   - For j=1..20: `W[j]·x + b[j] ≤ 0` (ReLU output is all zero);
   - `W[0]·x+b[0] > 376131.61875`.
3. **First Find Hidden Layer Zeros**: Solve the least squares problem `x=lstsq(W[1:],-b[1:])` for a 20×16 integer matrix, round to the nearest integers and verify that each residual is 0; if not satisfied, use `scipy.optimize.milp` or enumerate the character domain `{0..61}` to solve the linear inequalities.
4. **Character Mapping**: Character table `0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ`, convert 16 integer indices to a string; example solution: `[15,1,10,16,2,0,2,6,12,7,15,10,1,6,6,6] → f1ag2026c7fa1666`.
5. **Validation**: Re-implement forward to confirm that the 20 ReLU outputs are 0 and h0 exceeds the threshold, argmax=62; also test padding id=0 and inputs with insufficient length.

## Common Traps

- Do not treat the model as a standard embedding LM; token ID values themselves are features.
- `argmax` must consider both the fail constant and the huge negative penalty of success, not just the hidden layer zeros.
- Floating-point residuals should be checked to the original precision (usually around 1e-5), then converted to integers and verified against character ranges.