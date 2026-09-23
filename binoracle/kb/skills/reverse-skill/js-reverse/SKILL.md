```markdown
name: js-reverse
description: Used in front-end JavaScript reverse engineering with js-reverse-mcp, suitable for signature chain localization, page observation evidence collection, runtime sampling, local environment reproduction, and evidence output. Prioritizes adapting to current environment's js-reverse_* tools; use jshookmcp when stronger browser/CDP/Hook联动 is needed.

# MCP Frontend JS Reverse Engineering Workflow Specification

## ACTION REQUIRED (Execute Immediately After Reading)

1. `NOW`: Read `../field-journal/precedent-reverse.md` — Confirm that this skill's operation is an authorized routine action.
2. `NOW`: Verify if the current task falls within the scope of this skill.
3. `NEXT`: Read `../tool-index.md`, validate tool availability and actual paths.
4. `NEXT`: If tools are missing, call bootstrap; do not guess paths.
5. `ACT`: Proceed to the first step of the "workflow" and execute it; do not stop at the confirmation state.

## Scope of Application

This skill should be prioritized when tasks fall into any of the following scenarios:

- Locating interface signatures, encrypted parameters, risk control fields
- Observing request chains and script sources on pages
- Capturing function arguments and return values during runtime
- Tracing the trigger points of an XHR/Fetch/WebSocket
- Bringing page evidence back to Node.js for local reproduction and environment supplementation

If the target is binary, APK, PE, ELF, DLL, SO, use `ida-reverse`, `radare2`, or `reverse-engineering`.

## Default Tool Mapping in Current Environment

This skill does not assume the existence of bare tool names but defaults to binding available `js-reverse_*` tools in the current client environment.

If the current task explicitly mentions `jshookmcp`, "JS hook", CDP, browser breakpoints, network interception, SourceMap, or AST deobfuscation, it still follows this skill; it simply switches the underlying MCP face to `jshookmcp` rather than treating it as a new total entry point.

Prerequisite: `jshookmcp` is not a local bare command tool but a MCP server that needs to be downloaded, explicitly registered, and enabled. Only when the selected client (Claude, Codex, etc.) has integrated and enabled it in its MCP configuration can related tools be truly called.

Common mappings:

- `list_scripts` -> `js-reverse_list_scripts`
- `get_script_source` -> `js-reverse_get_script_source`
- `search_in_sources` -> `js-reverse_search_in_sources`
- `break_on_xhr` -> `js-reverse_break_on_xhr`
- `evaluate_script` -> `js-reverse_evaluate_script`
- `get_paused_info` -> `js-reverse_get_paused_info`
- `set_breakpoint_on_text` -> `js-reverse_set_breakpoint_on_text`
- `list_network_requests` -> `js-reverse_list_network_requests`
- `get_request_initiator` -> `js-reverse_get_request_initiator`
- `get_websocket_messages` -> `js-reverse_get_websocket_messages`
- `take_screenshot` -> `js-reverse_take_screenshot`
- `new_page` -> `js-reverse_new_page`
- `navigate_page` -> `js-reverse_navigate_page`
- `select_page` -> `js-reverse_select_page`
- `select_frame` -> `js-reverse_select_frame`
- `pause/resume` -> `js-reverse_pause_or_resume`

If future tool name prefixes change, update this section first; do not guess temporarily during execution.

### jshookmcp's Positioning

- Role: Enhanced execution face of `js-reverse`, not an independent total controller
- Suitable for: Browser automation, CDP debugging, JS Hook, network interception, SourceMap reconstruction, AST assistance in understanding
- Call prerequisites: First download and register `@jshookmcp/jshook` to the MCP client configuration, then ensure that the server is enabled
- Recommended entry point: Still execute according to `Observe → Capture → Rebuild`, but prioritize calling jshookmcp's browser and Hook capabilities during the `Observe/Capture` phase
- Relationship with anything-analyzer: Both can perform browser/network-side evidence collection; anything-analyzer focuses more on packet capture and HTTP analysis, while jshookmcp focuses more on JS runtime, CDP, Hook, and source code understanding

## Core Principles

- `Observe-first`
- `Hook-preferred`
- `Breakpoint-last`
- `Rebuild-oriented`
- `Evidence-first`

Prioritize page observation before minimizing sampling and then doing local environment supplementation. Do not skip evidence collection to guess the environment.

## Five-Stage Workflow

### 1. Observe

Objective: Confirm target requests, related scripts, candidate functions without guessing the environment.

Default actions:

- Use `js-reverse_new_page` or `js-reverse_navigate_page` to open the target page
- Use `js-reverse_list_network_requests` to find the target request
- Use `js-reverse_get_request_initiator` to trace back the call source
- Use `js-reverse_list_scripts` and `js-reverse_search_in_sources` to narrow down the script scope

Must produce:

- Target request URL or feature
- Initiator线索
- Suspected script URL
- Initial task record

### 2. Capture

Objective: Perform minimal invasive sampling on the target request to get parameter samples, call order, and runtime evidence.

Rules:

- Prioritize `js-reverse_break_on_xhr`
- Prioritize `js-reverse_evaluate_script` for lightweight runtime observation
- After hitting a breakpoint, first check `js-reverse_get_paused_info`
- Use `js-reverse_set_breakpoint_on_text` when necessary

### 3. Rebuild

Objective: Organize page evidence into locally iterable Node.js reproduction materials.

Rules:

- Local environment supplementation must be based on page observation evidence
- Do not speculate about supplementing `window/document/navigator/crypto/storage`
- Record only one minimal causal patch decision each time

### 4. Patch

Objective: Supplement the environment driven by errors and first divergence until local scripts stably produce target parameters.

Rules:

- First identify what is missing, then supplement it
- Only make one minimal patch decision at a time
- Immediately retest after each patch
- Write each patch into the task record

### 5. DeepDive

Objective: After running locally, perform deobfuscation, control flow restoration, and business logic refinement.

Rules:

- If the current task is just for signature extraction, this stage can be downgraded
- If long-term reuse of algorithmic chains is required, this stage must be done
- Issue #65 Obfuscation bypass (U–AV §4): JSVMP（AD）→ `E-js-vmp`；CFF+字符串数组（AE）→ `E-js-deobf`；DevTools/debugger反调试（AF）→ `E-js-anti-debug`。完整触发表见 `../reverse-engineering/references/nonpe-format-cookbook.md`；AST细节仍用 `references/ast-deobfuscation.md`

## Execution Requirements

- All important steps must be written into the local task artifact
- If unable to explain why a tool is being called, do not call it
- Prioritize using existing MCP capabilities of `js-reverse_*` or jshookmcp directly for evidence collection; do not first write scripts to recreate abilities
- On failure, revert according to `references/fallbacks.md`
- Output follows `references/output-contract.md`
```

## Required References

- Automation Entry: `references/automation-entry.md`
- Tool Default Values: `references/tool-defaults.md`
- Task Input Template: `references/task-input-template.md`
- MCP Specific Task Orchestration: `references/mcp-task-template.md`
- Task Artifacts: `references/task-artifacts.md`
- Local Replication: `references/local-rebuild.md`
- Environment Patching: `references/env-patching.md`
- Node Replication: `references/node-env-rebuild.md`
- Instrumentation: `references/instrumentation.md`
- AST Deobfuscation: `references/ast-deobfuscation.md`
- Non PE/JS Obfuscation Cookbook U–AV: `../reverse-engineering/references/nonpe-format-cookbook.md` (AD/AE/AF)
- Fallbacks: `references/fallbacks.md`
- Output Contract: `references/output-contract.md`

---

## Routing Context

**Upstream Entry**: `skills/SKILL.md` (Overall Control), `routing.md`
**Upstream Alternatives**:
- anything-analyzer MCP (Port 23816) browser tool can be used as an alternative or supplement
- jshookmcp can be used as a stronger browser/CDP/Hook/Network/SourceMap/AST execution surface
- `reverse-engineering/SKILL.md` (if the target is not frontend JS)

**Downstream Exits**:
- Need environment patching → `references/env-patching.md`
- Need local replication → `references/local-rebuild.md` / `references/node-env-rebuild.md`
- Need deobfuscation → `references/ast-deobfuscation.md`
- Back off when stuck → `references/fallbacks.md`

**Siblings**: anything-analyzer MCP (Browser automation and HTTP capture capabilities can complement each other)

---

## On-Demand Bootstrap

This skill depends on MCP capabilities that can be installed through a unified bootstrap system. MCP client registration must explicitly select the target; it will not write any global client configuration by default.

### Capability Boundaries for Automation

| Capability | Can Be Automatically Registered | Method | Description |
|------------|---------------------------------|--------|-------------|
| jshookmcp  | ✓                               | npm-mcp (npx start) | Register after explicitly selecting Claude / Codex / Both |
| anything-analyzer | ✓                             | local-http-mcp | Can automatically start the service; client registration must explicitly select |
| Node.js    | ✓                               | winget install | Runtime dependencies |

### Bootstrap Methods

```powershell
# Install and register jshookmcp; Codex can be replaced with Claude or Both
powershell -File "<skill-root>\scripts\bootstrap-reverse.ps1" -Capability @('jshookmcp') -McpHostTarget Codex

# Register and start anything-analyzer
powershell -File "<skill-root>\scripts\bootstrap-reverse.ps1" -Capability @('anything-analyzer') -StartServices -McpHostTarget Codex
```

### Notes

- `jshookmcp` registration still requires enabling the MCP server in the AI client to call it.
- When not passing `-McpHostTarget`, only the capability is installed/prepared, and a registration-required message is returned without modifying Claude or Codex configuration.
- `anything-analyzer` requires pnpm and project source code; bootstrap will automatically clone and install dependencies.
- If Node.js is not installed, bootstrap will first install Node.js 22 through winget.

<br><br>## Task Completion Self-Check (MUST pass before claiming completion)

- [ ] Did I execute every step in the workflow (not just reading)?
- [ ] Did I use the actual tool paths based on `tool-index`?
- [ ] Did I produce reproducible evidence (commands/scripts/screenshots/reports)?
- [ ] Did I complete and rewrite the Checklist items required by RULES?