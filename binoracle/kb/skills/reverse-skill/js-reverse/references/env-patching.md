# Environment Setup Rules

- Only patch objects that have already been proven to be needed by page evidence.
- Patch one minimal causal unit at a time.
- First patch the values, then the function shell, and finally the return object contract.
- Each patch must be re-executed and record whether the first divergence has moved forward.