# [Seed] JS Signature Reversing (Webpack + AES + Timestamp)

## Scenario Classification
JS Signature

## Target Overview
Reconstruct the algorithm for generating the `sign` parameter of a web application interface, enabling local reproduction.

## Complete Execution Chain

1. Browser packet capture → Discover POST request with `sign` and `timestamp` parameters
2. Search JS source code for "sign" → Locate the webpack bundled chunk file
3. Set breakpoint at sign assignment → Hit, view call stack
4. Backtrace call stack → Find the signature function (in some webpack module)
5. Analyze signature logic: `sign = HmacSHA256(sorted_params + timestamp, secret_key)`
6. Key source: Hardcoded in another webpack module
7. Local Node.js reproduction → Generated sign matches browser output
8. Verification: Use reproduced sign to request interface → Returns normal data

## Pitfall Records

| Issue | Reason | Solution | Time |
|-------|--------|----------|------|
| Too many search results for "sign" | Webpack bundles compress variable names | Change to search `sign=` or trace back using initiator in network panel | 15min |
| Breakpoint hit but unable to understand code | Webpack compression + variable name obfuscation | Use Chrome's Pretty Print format, and SourceMap (if available) | 10min |
| Local reproduction result inconsistent | Incorrect parameter sorting method | Carefully examine the sort logic in source code (by key alphabetical order + special character handling) | 30min |
| Timestamp precision incorrect | Server uses seconds, I used milliseconds | `Math.floor(Date.now() / 1000)` | 5min |
| Key not found | Key is imported through require from another chunk file | Print key variable at breakpoint using console.log | 10min |

## Toolchain Discovery

- Chrome DevTools' initiator column is faster for locating the signature function compared to searching source code
- Webpack bundled code is more efficient to analyze with Pretty Print + breakpoints than reading directly
- If SourceMap (`.map` file) is available, directly restore original code
- Node.js's `crypto` module can directly reproduce most signature algorithms

## Key Code/Commands

```javascript
// Node.js reproduction
const crypto = require('crypto');

function generateSign(params, timestamp, secretKey) {
    // 1. Parameters sorted by key alphabetical order
    const sorted = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join('&');
    // 2. Concatenate timestamp
    const message = sorted + '&timestamp=' + timestamp;
    // 3. HMAC-SHA256
    return crypto.createHmac('sha256', secretKey).update(message).digest('hex');
}

const params = { user_id: '123', action: 'query' };
const timestamp = Math.floor(Date.now() / 1000);
const secretKey = 'hardcoded_key_from_webpack';
console.log(generateSign(params, timestamp, secretKey));
```

## Suggestions for Improvements to This Package

- js-reverse's env-patching.md should include "how to handle dependencies between webpack chunks"
- Suggest adding a quick reference guide for common signature algorithms (HMAC-SHA256 vs MD5 vs custom)

## Reusable Patterns/Script Snippets

**Standard JS Signature Reversing Workflow**:
```text
1. Capture packet to find request with signature
2. Use initiator/call stack to locate the signature function
3. Analyze signature logic (parameter sorting + concatenation + encryption)
4. Find key source (hardcoded, from interface response, time-based)
5. Local Node.js reproduction
6. Compare and verify
```

**Common Signature Patterns**:
```text
- HmacSHA256(sorted_params, key) → Most common
- MD5(params + salt + timestamp) → Older systems
- AES(JSON.stringify(params), key) → Encryption rather than signing
- RSA sign → Rare, usually in financial applications
```

## Evolution Actions
- [ ] No need to update route matrix
- [ ] No need to update bootstrap-manifest
- [ ] No need to update child skill documentation

## Environment Information
- OS: Windows
- Tool versions: Chrome DevTools, Node.js 20+
- Target platform: Web (Webpack bundled SPA)

## Desensitization Requirements
This entry is seed data based on publicly available techniques and does not involve real targets.