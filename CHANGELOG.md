# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **`investigate --keep-lab-on-failure`**: when the automatic WordPress SQLi verification
  doesn't confirm, leaves the ephemeral WordPress+MySQL Docker lab ALIVE (base URL + admin
  credentials surfaced in the report) instead of tearing it down, and skips the retry loop
  (which would otherwise destroy that same lab to spin up a new one each attempt). For the
  real case that motivated it (CVE-2024-1071): the target's AJAX handler can swallow the real
  MySQL error and always return clean JSON, so none of the 5 automated techniques can see it
  — at that point retrying different payloads blindly doesn't help; inspecting
  `wp-content/debug.log` inside the live container by hand does. The analyst is responsible
  for tearing the lab down afterwards (by the printed Docker tag).
- **WordPress SQLi verifier, a sixth technique: syncing a "custom sort field" gate meta before
  each payload (Ultimate Member/CVE-2024-1071)**: the official patch (2.8.2 -> 2.8.3) reveals
  the real sink — a `LEFT JOIN` with the raw value inside single quotes
  (`...um_key = '{$sortby}'`, rewritten to `$wpdb->prepare()` in the fix) — but that line never
  runs unless the submitted value matches, by exact string equality, a value already stored in
  a real post's `_um_sortby_custom` meta (the Member Directory's configured custom sort field).
  Every injection context (quote + AND/OR) was already covered by techniques 1-4, but without
  that gate open they never reached the vulnerable line at all. Since the ephemeral lab is our
  own, `verify_wordpress_sqli` now recovers the real post ID from the already-resolved hashed
  `directory_id` and writes the exact same value being tested into that meta immediately before
  every single payload — opening the gate itself instead of depending on it already being
  configured. Gated by a small per-plugin registry (`_SQLI_CUSTOM_SORT_GATE`), inactive for any
  other slug.
- **WordPress SQLi verifier, a fifth technique for ORDER BY-context injection**: the first
  four techniques (error-based, UNION-based, boolean-blind, time-based blind) all assume the
  injected value stays part of a WHERE clause (`<value><closer> AND/OR <condition>`) — a sink
  that puts the parameter directly into an ORDER BY (e.g. an unwhitelisted `WP_User_Query`
  `orderby`, confirmed live against CVE-2024-1071/Ultimate Member's `sorting` parameter) can
  never be confirmed that way: there's no WHERE to concatenate onto, and a quote just breaks
  the column/expression syntax instead of closing a string. The new last-resort technique
  sends the injected value as a complete, bare scalar subquery (no AND/OR, no quotes, no
  comment) — first error-based (`extractvalue`/`updatexml`), then, if that filters nothing, a
  CONDITIONAL time-based pair (`CASE WHEN 1=1/1=2 THEN SLEEP(5) ELSE 0 END`, stricter than an
  unconditional `SLEEP` since it proves a real condition controls the delay). Not specific to
  this plugin — any dynamic column/orderby sink without a whitelist hits the same pattern.
- **WordPress SQLi verifier, two real infrastructure fixes chained from CVE-2024-1071**: the
  shortcode page `_bootstrap_lab` creates to source a real nonce now gets created even when
  the attack targets a concrete endpoint (e.g. an AJAX action) rather than the bare homepage —
  previously it was skipped whenever a real endpoint was already known, so the nonce scraped
  always came from a generic page that never carried that specific AJAX action's nonce
  ("Wrong Nonce" forever). Separately, an endpoint placeholder shaped like an id/directory
  (e.g. `{dir_id}`) is no longer resolved by guessing "the first 1-6 digit number anywhere in
  the scraped HTML" — a real page always has *some* unrelated number (a copyright year, a
  post ID...) that silently wins over the far more reliable validated hashed-ID brute force
  that already exists for exactly this. ID/dir placeholders are now always left for that
  brute force. The SQLi retry loop can also now recognize a response rejecting the request
  for a reason unrelated to the parameter being injected (e.g. "Wrong member directory data")
  and ask for that additional real parameter by name (`parametro_adicional_requerido`) — added
  to the request, never replacing the one actually being injected.
- **`investigate --sqli-param`**: lets the analyst pin the exact injectable parameter name,
  bypassing the generic id/search/sort heuristic when `--params` also carries another
  required parameter (e.g. a real directory/resource id) whose name would otherwise be
  preferred by that heuristic over the real injectable one.
- **Generic (CMS-agnostic) dynamic verifiers for 10 web vuln classes** (`genericverify.py`):
  for any CVE whose downloaded source isn't a recognized WordPress/Drupal/Joomla plugin,
  binoracle builds and runs the target's own Dockerfile/docker-compose.yml (or, if it has
  neither, auto-detects Node/Python/PHP by its own manifest files and writes a minimal
  Dockerfile itself) and attacks the real resulting container — never `verified=True` by a
  status code, always by an independent check (a canary written to disk, inside the
  container, a listener on its own network, a real browser executing JS, a real timing
  delay...). Covers command-injection, path-traversal, SSRF, blind SQLi, XXE, XSS, SSTI,
  open-redirect (pre-existing), plus three added this session: an unauthenticated,
  deliberately WEAKER IDOR check (two IDs, no session — never marks `verified`, only a real
  observed difference), a file-upload check (confirms real on-disk storage of a dangerous
  file via `docker exec grep`, not execution), and an LFI-to-RCE escalation via access-log
  poisoning (confirms real code execution, never a raw-reflection false positive).
- **WordPress SQLi verifier, three real fixes chained from one CVE (CVE-2024-3552)**: the
  ephemeral lab now enables `WP_DEBUG`/`WP_DEBUG_DISPLAY` (error-based SQLi was structurally
  blind without it), auto-creates a real page using the plugin's own shortcode when the given
  endpoint is the bare homepage (which shows nothing to inject into), and inserts a real,
  schema-aware row (via a `DESCRIBE`-driven `wp eval`) into whatever relationship table a
  `LEFT JOIN`-based sink joins by post ID — closing a real class of "sink is real but the
  test target has no matching row" false negative.
- **`investigate --json path.json`** (and always in `investigate-batch`): dumps the complete
  `Investigation` object, untouched by the markdown/HTML report's truncation of every
  response body to a few hundred chars — closes a real gap hit repeatedly diagnosing the
  CVE-2024-3552 SQLi, where the full evidence never left the process.
- **LLM-driven evidence-based retry loop** (`cve_agent.py`), now wired across 26 dispatch
  sites (WordPress, Drupal, and the CMS-agnostic generic verifier, up from the 3 it started
  with this session): on a negative, the LLM is handed the same real evidence a human analyst
  would read (a real response-body snippet from the first/control attempt) and asked to name
  a concrete alternative endpoint/parameter grounded in something visible there, or say
  honestly there's no lead — bounded to `_RETRY_MAX_ATTEMPTS` (3) total attempts per
  technique, never a blind or unbounded retry. Built on a shared, technique-agnostic
  `_run_evidence_retry_loop()` helper plus a generic `_GENERIC_RETRY_SYS` prompt (the
  technique name is injected into the evidence payload, not baked into a bespoke prompt per
  site) so new sites cost one dispatch-site edit, not a new prompt. Covers SQLi,
  path-traversal, command-injection, SSTI, XXE, file-upload, open-redirect, XSS, SSRF, and
  blind (time-based) SQLi. Two real evidence-capture bugs were found and fixed along the way:
  several Drupal verifiers only wrote their response-body snippet on the *winning* branch
  (useless to a retry loop, which only runs on a negative), and three verifiers (SSRF, blind
  SQLi, both WP/generic XSS) were silently discarding a usable HTTP response body entirely.
  Deliberately NOT wired: CSRF/account-takeover/deserialization across all three CMS — their
  failure mode doesn't reduce to a single endpoint+parameter retry (3+ params exchanged at
  once, or no endpoint/param axis at all), so forcing them in would mean an ungrounded retry,
  which defeats the whole point of reading real evidence first.
- **bash/curl PoC templates** (`webexploit.py`): all 13 web-vuln-class PoC builders now
  generate copy-pasteable `bash`+`curl` scripts instead of Python/requests.
- **pytest-xdist** for parallel test runs (`pip install -e .[dev]`): the fast suite (~584
  tests, excluding angr/chainanalyzer/rop) drops from ~13-15 min serial to ~4.5 min with
  `-n 4` on a 4-core machine, same pass/fail result.

### Removed
- **Burp Suite routing from the ephemeral CMS lab** (WordPress/Drupal/Joomla): `_wp_login`/
  `_drupal_login`/`_joomla_login` now always use a direct `requests.Session()`, even when
  `--burp-mcp-url` is configured. Routing the lab's own login through Burp was the root cause
  of two distinct real bugs this session (an `UnknownHostException` on `host.docker.internal`,
  then a regression in `http_ready()` when `_lab_host()` was made Burp-aware to fix that) for
  a fully-automated lab that never needed an external proxy in the first place. Burp MCP stays
  available for `genericverify.py`'s analyst-directed verifiers.

### Added (prior)
- **Heap-to-shell (tcache-UAF) exploit**: `autoheap.autoheap_shell` drives a menu-style
  use-after-free (new/free/edit/show, e.g. the `heapexp` sample) to a verified shell — it
  defeats glibc safe-linking without needing exact heap offsets (freeing one chunk into an
  empty tcache bin makes its fd = `mangle(NULL)` = `&chunk >> 12`, so `show` leaks the key
  directly), poisons the tcache to allocate over `free@GOT` (no-PIE / partial RELRO) and
  overwrites it with `win`, then triggers a `free` to spawn the shell. Wired into the `audit`
  backstop (runs regardless of `find_win`) and the `try_heap` agent tool, alongside the
  existing corruption-confirming `autoheap`. Runs in the `binoracle-pwn` image; degrades
  cleanly without it.
- **Dangerous-sink detection now covers statically-linked binaries**: `r2_sinks` previously
  keyed only off PLT imports, so a static binary (no imports) reported "no sinks" even when it
  calls `read`/`gets`. It now also detects compiled-in sink symbols and keeps those reached
  from USER code (`sym.vuln`, not glibc internals like `sym._IO_*`), resolving all candidates
  in a single r2 pass (no per-sink re-analysis). Keyword matching is token-delimited so `read`
  no longer matches `fgets`/`readdir`/`pread`.
- **ROP on PIE (verified by execution)**: `autopie.autopie_rop` resolves the (ASLR-off) PIE
  base in the sandbox, rebases the ELF, builds a ret2libc-`system` or execve-syscall ROP chain
  with absolute addresses and confirms a real shell via a marker — closing the ROP-on-PIE gap
  the scope table listed as not automated. Wired into the `audit` backstop cascade (ROP →
  ret2libc → format-string → ROP-PIE) and covered by a `-static-pie` practice target
  (`samples/src/ropme_pie.c`, no gift function). Runs in the `binoracle-pwn` image; degrades
  cleanly (dict with `ok=False` + note) when Docker or the image is absent.

### Fixed
- **Gift-function detection no longer false-matches substrings**: `find_win` (and the
  `r2_win` gift finder) matched the bare substring `win`, so a static binary's glibc symbol
  like `_Unwind_Resume` was taken as a `win()` gift — false-routing the audit backstop to a
  bogus ret2win instead of the correct ROP/ROP-PIE path. Keywords now match as delimited
  tokens (`win`, `shell`, `backdoor`, `flag`, `give`), so `_Unwind_Resume`/`winner` don't hit
  while `win`/`get_flag`/`give_shell` still do.
- **Agent protocol reliability**: the LLM backends now support a JSON-constrained output
  mode (Ollama `format:json`, OpenAI-compatible `response_format`), and the agent loop
  enables it for every action turn. Small local models (e.g. `qwen2.5-coder:7b`) no longer
  wrap their action in prose after a long tool result, which was the main cause of the
  "model reply was not valid protocol" nudges. Toggle with `BINORACLE_JSON_MODE=0`; prose
  layers (executive summary, per-finding enrichment, synthesis) stay free-form.
- **Anti-loop per tool**: the loop already refused byte-identical tool calls; it now also
  caps how many times the same tool may be called with *different* arguments, so a model
  can no longer burn the step budget scanning (e.g. `cyclic_offset value=0,1,2,...`).
- **`cyclic_offset` guard**: passing a small integer that was never observed in a crash now
  returns a corrective error (send the cyclic pattern with `dbg_run_input`, read the value
  that overwrote RIP/EIP, or use `try_ret2win`/autopoc) instead of a silent "not found".
- **Verdict gate recognises sandbox-verified exploits**: an exploit actually executed and
  confirmed in the sandbox (`sandbox-verified` / `sandbox-confirmed`) now counts as a proof
  source for the `verified` verdict, alongside angr/debugger. Previously a genuinely
  executed ret2win/ROP/fmt/ret2libc finding was wrongly downgraded to `grounded`.
- **Provenance banner sized to real grounding**: the answer no longer shows a scary
  "no citations" warning when a full evidence trail exists — it shows a calm note pointing to
  the grounding ledger. The hard warning now fires only when no oracle was consulted at all.
  The agent prompt also reinforces inline `[src: ...]` citation with a concrete example.
- **`fmtstr_offset` robust to a bad `word`**: a small model passing `word=false`/`0`/garbage
  used to divide by zero and fail the tool repeatedly; the pointer size now snaps to 8 (x64)
  or 4 (x86) instead of crashing.
- **Audit backstop cascades to format-string**: the deterministic shell backstop now tries
  ROP → ret2libc → **format-string** for a binary with no gift function, so a pure
  `printf(user)` target reliably ends the audit with a sandbox-verified exploit (previously
  only ret2win/ROP/ret2libc were attempted, so a format-string binary got no verified PoC).
- **Fabricated-citation detection**: `[src: ...]` tags in the model's prose that reference a
  tool the agent never ran (e.g. a hallucinated `[src: r2_strings]`) are now detected against
  the grounding ledger and flagged with a warning, so an invented citation can no longer pass
  as grounded.
- **Debugger surfaces a clear message when it cannot run the target**: an lldb debugserver /
  gdb ptrace failure (macOS codesigning/SIP, ptrace-not-permitted, non-native binary) now
  returns an actionable error pointing to the sandbox / angr, instead of a raw "Lost debug
  server connection" dump that looked like a crash.
- **Quiet pwntools**: pwntools' cosmetic WARNING noise (e.g. "Could not populate PLT: Cannot
  allocate 1GB memory to run Unicorn Engine") is pinned out of reports via a `_quiet_pwn()`
  helper called after each `from pwn import`, without hiding real errors.
- **Backstop exploits recorded as verified findings**: a sandbox-verified ROP / ret2libc /
  format-string exploit produced by the audit backstop now becomes a `verified` critical
  Finding (like ret2win already did), so the report, the findings JSON and the learned corpus
  record it consistently instead of only mentioning it in the prose.

### Added
- **Local RAG knowledge base** (`binoracle/kb/*.md` + `binoracle/rag.py`): curated
  exploitation cheat sheets (ret2win, ROP/ret2syscall, ret2libc, format-string, heap/tcache,
  PIE/leaks, mitigations, methodology, tools) indexed with a stdlib TF-IDF retriever (no
  external deps). Retrieval is grounding for the model, never a source of verdicts.
  - `binoracle kb [query]` — list cheat sheets or retrieve the most relevant snippets.
  - Wired into `primitives` (LLM narrative) and `audit` (agent system prompt) so the model
    reasons over real technique notes selected from the binary's own facts (checksec + sinks
    + gift functions), via `AgentLoop(kb_hint=...)`.
  - **Learned layer**: the `audit` hint blends the curated cheat sheets with facts binoracle
    has already VERIFIED on similar targets (`global_facts`, same arch + overlapping sinks),
    and `run_audit` now curates its verified findings back into that corpus — so retrieval
    improves on every audit (curated = reference, learned = prior verified evidence).
  - Exposed in the web dashboard (Utiles group) with a query field.
- **`binoracle tools`**: detects the installed binary-pentest toolchain (radare2/rizin,
  pyelftools, angr, pwntools, one_gadget, ROPgadget/ropper, gdb+pwndbg, lldb, ltrace/strace,
  checksec, binutils, docker) and maps each to how binoracle uses it. Also in the web UI.
- Tests: `tests/test_rag.py` (indexing, retrieval relevance, bounded context, fact queries).
- **RAG references** (`binoracle/kb/references.md`): curated index of authoritative external
  sources (ir0nstone, Practical CTF, how2heap, pwn.college, ROP Emporium, libc.rip, pwninit,
  pwntools, GTFOBins, syscall tables) plus a glibc version-notes table (tcache 2.26,
  key-check 2.29, safe-linking 2.32, hooks removed 2.34, FSOP 2.35+). Synthesized notes, not
  copied text; the file points to the originals.

### Changed
- **AI-first workflow**: the autonomous `audit` agent now has the FULL tool catalog at its
  disposal, including newly-wired `gen_shellcode` and `gen_fuzz_harness` helpers, so it
  reasons over and drives every capability itself (recon, gadgets, cyclic/offset, shellcode,
  fuzz, format-string index, reachability, and build+run+verify exploit actions) with the RAG
  as technique context. AUDIT_SYSTEM prompt rewritten to make this explicit.
- Web dashboard sidebar streamlined to be AI-centric: the autonomous audit is the primary
  entry; the manual per-technique buttons (triage/hunt/disasm/gadgets/primitives/autopwn/rop/
  shellcode/fmtstring/fuzz/cyclic/verify) were removed from the UI since the AI performs them
  itself. Result views (dashboard, report), the 2-binary `regress`, and reference (kb, tools,
  doctor) remain. The underlying commands still exist in the CLI.

## [0.1.0] - 2026-09-22

First public release. A local, oracle-grounded LLM copilot for binary reverse engineering
and exploitation.

### Added
- **Local-first core** using only the Python standard library; local LLM backends for
  Ollama and any OpenAI-compatible server (llama.cpp, LM Studio, vLLM).
- **Oracle framework** with graceful degradation:
  - `static_r2` (radare2): info, imports, functions, strings, disassembly, xrefs, dangerous
    sinks, cross-format checksec, ROP gadget search, gift-function finder, stack frames.
  - `elf_meta` (pyelftools + stdlib fallback): header, mitigations, GOT/PLT, relocations,
    symbols.
  - `symbolic_angr`: reachability proofs with concrete-input synthesis.
  - `dynamic_dbg` (lldb/gdb): run a target and observe real crashes.
  - `exploit_helpers` (pure stdlib): De Bruijn cyclic patterns, offset finding,
    format-string offset math, bad-char reference.
- **Grounded agent loop**: JSON tool-call protocol, anti-repetition guard, forced
  finalization, and end-of-run synthesis.
- **Anti-false-positive layer enforced in code**: a verdict gate (only angr/debugger proof
  allows `verified`), an evidence gate (empty/untraceable evidence is downgraded), and an
  automatic angr verification pass that promotes `grounded` findings to `verified`.
- **Workflows**: triage, vulnerability hunt, exploitation-primitive reasoner, function
  explanation, pwntools skeleton generation, patch-diffing (radiff2), automatic
  verification, and AI enrichment (professional per-finding analysis + executive summary).
- **Heap corruption confirmed by execution**: autoheap runs the target with probe
  inputs in the sandbox and confirms a real double-free / heap overflow via glibc's
  allocator abort, promoting the static heap candidates to a confirmed bug. Wired
  into autopwn, a try_heap tool and a `heap` CLI command.
- **ret2win on PIE (verified)**: resolves the PIE base in the sandbox and jumps to
  win(), confirmed by execution.
- **Format-string exploitation (verified)**: for a printf(user)-in-a-loop binary, it
  finds the format offset, overwrites printf@GOT with system and gets a real shell,
  confirmed in the sandbox. Works on PIE binaries too (the PIE base is resolved in
  the sandbox, so printf@GOT is overwritten at its real address).
- **ret2libc with leak (verified)**: leaks a libc address, computes the base and
  runs system('/bin/sh'), confirming a real shell in an isolated sandbox (pwntools
  image, ASLR off). Covers dynamic NX+ASLR binaries. Alongside ret2win and static
  ROP/ret2syscall, four exploit classes are now verified by execution (ret2win, static ROP, ret2libc, format-string).
- **Exploitation builders (pwntools)**: `rop` (ret2libc / execve syscall chain builder),
  `shellcode` (execve /bin/sh, with a precompiled fallback when no cross-assembler is
  present), `fmtstring` (format-string leak/write helper for infoleak), and `fuzz`
  (libFuzzer harness / AFL command generator).
- **Deeper static analysis**: modern hardening detection (FORTIFY, ASan, CFI, SafeStack,
  UBSan), C++/vtable detection, and heap attack surface (UAF / double-free candidates).
- **`analyze` one-shot**: give it a `.c`/`.cpp` source (it compiles) or a binary, and it
  runs the full pipeline (triage -> hunt -> angr verification -> AI report -> HTML).
- **`serve` web dashboard** (stdlib http.server, localhost only): metric charts (severity
  donut, exploitability gauge, KPI cards), a concrete mitigation grid, every command
  runnable from the browser (including ROP chains), and binary/source file upload.
- **CLI**: doctor, triage, hunt, ask, chat, report, primitives, gadgets, cyclic,
  exploit-skeleton, explain, diff, verify, view.
- **Interactive HTML report**: self-contained, bilingual (ES/EN toggle), light/dark toggle,
  KPI dashboard, severity distribution, mitigation risk panel, filterable findings,
  attack surface and full evidence trail.
- **Bilingual output** controlled by `BINORACLE_LANG` (default `es`).
- **Format coverage**: ELF, PE/.exe and Mach-O for static analysis and checksec; angr for
  ELF and PE.
- **Practice corpus** (`samples/`): reproducible ELF (ret2win, format-string, ret2libc,
  stripped) and Windows PE targets built via Docker.
- Test suite, `Makefile`, and GitHub Actions CI (Python 3.10-3.12).

### Known limitations
- `angr_reachable` on Windows PE is limited by the mingw C runtime; it reports "not proven"
  rather than a false positive.
- Dynamic execution requires a host that can run the target (Linux ELF on Linux, Windows
  .exe under Windows/wine, Mach-O on macOS).

[0.1.0]: https://example.com/binoracle/releases/tag/v0.1.0
