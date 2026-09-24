---
name: browser-extension-reverse
description: Use for authorized reverse engineering of browser extensions (Chrome/Firefox) including manifest analysis, background workers, and extension-based credential or traffic logic recovery.
---

# Browser Extension Reverse Engineering

## ACTION REQUIRED（Read this immediately）

1. `NOW`: Read `../field-journal/precedent-reverse.md`
2. `NOW`: Confirm the target is a **browser extension** (crx/xpi/unpacked directory), not ordinary web JS (ordinary → `js-reverse/`)
3. `NEXT`: Unpack the extension; read manifest
4. `ACT`: Permissions → Background scripts → Network/Storage hooks

## Applicable Scenarios

- Analysis of Chrome/Edge MV2/MV3 extensions
- Firefox extensions
- Malicious extension IOC, supply chain extension poisoning investigation
- Recovery of signature/encryption/proxy logic implemented by extensions

## Workflow

### 1. Body

```text
□ crx extraction / from profile take extension directory
□ manifest.json: permissions, host_permissions, background, content_scripts
□ Evaluate excessive permissions (<all_urls>, webRequest, debugger)
```

### 2. Logic

```text
□ service_worker / background entry point
□ content_script injection points and world (isolated)
□ chrome.storage / IndexedDB keys
□ Similar to `js-reverse`: Observe network and message passing (runtime.sendMessage)
```

### 3. Dynamic

```text
□ Load unpacked directory in developer mode
□ Check errors at chrome://extensions
□ Attach DevTools to service worker
□ Use Frida/Browser CDP (jshookmcp) when necessary
```

## Toolchain

| Tool | Purpose |
|------|--------|
| Unzip/jq | manifest |
| Chrome DevTools | worker debugging |
| js-reverse toolchain | deep JS |
| YARA | malicious extension rules |

## References

- `references/extension-analysis.md`
- field-journal entries related to extension recovery
- `../js-reverse/` `../malware-analysis/`

## Routing Context

**Upstream**: MASTER R30  
**Downstream**: Complex obfuscated JS → `js-reverse`; poisoning investigation → supply-chain / malware

## Task Completion Self-Check

- [ ] Are permissions and entry scripts listed?
- [ ] Is the critical data flow restored?
- [ ] Checklist?