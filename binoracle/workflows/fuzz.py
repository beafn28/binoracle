"""Fuzzing harness generator — v2.

For AUTHORIZED targets / your own code only.

Modes:
  - libfuzzer: C harness that feeds fuzzed bytes to a target function, with
    ASan/UBSan/MSan coverage options.
  - afl: ready afl-fuzz++ command line (stdin, @@, persistent, QEMU) with
    deduplication config and triage helpers.
  - radamsa: file-mutation fuzzing via radamsa for format-specific targets
    (HTTP, PDF, ZIP, etc.).
  - structured: hypothesis-style property-based harness skeleton (Python).

v2 adds:
  - `FuzzConfig` dataclass to capture target facts
  - `generate_corpus(binary, n)` — auto-seeds corpus from r2/strings
  - `auto_harness(binary, llm)` — uses radare2 to find highest-risk
    function and generates a focused harness for it
  - `triage_crashes(crashes_dir)` — deduplicates AFL crashes via
    exploitable-style heuristics (symbolized stack hash)
  - `render_fuzz_plan(config)` — full markdown fuzz plan
"""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class FuzzConfig:
    binary:        str
    target_func:   Optional[str] = None
    input_type:    str = "raw"       # raw | file | stdin | network
    corpus_dir:    str = "corpus"
    output_dir:    str = "out"
    mode:          str = "afl"       # afl | libfuzzer | radamsa | structured
    with_asan:     bool = True
    with_ubsan:    bool = False
    timeout_ms:    int = 100
    max_len:       int = 4096
    extra_args:    List[str] = field(default_factory=list)
    notes:         List[str] = field(default_factory=list)


@dataclass
class CrashReport:
    crash_file:  str
    stack_hash:  str
    signal:      Optional[str]
    top_frames:  List[str]
    unique:      bool = True


# ── Corpus seeding ────────────────────────────────────────────────────────────

def generate_corpus(binary: str, corpus_dir: str = "corpus", n: int = 10) -> List[str]:
    """
    Auto-seed a fuzzer corpus from strings extracted by r2/strings.
    Returns list of created file paths (may be empty if r2 unavailable).
    For AUTHORIZED targets only.
    """
    os.makedirs(corpus_dir, exist_ok=True)
    created = []

    # Minimal seed always present
    for i, seed in enumerate([b"A", b"\x00", b"\xff\xfe", b"%s%s%s%n"]):
        p = os.path.join(corpus_dir, f"seed_{i:03d}")
        with open(p, "wb") as f:
            f.write(seed)
        created.append(p)

    # Try to extract strings via r2 for a richer seed
    try:
        r = subprocess.run(
            ["r2", "-A", "-q", "-c", "iz~str", binary],
            capture_output=True, text=True, timeout=20,
        )
        strings = []
        for line in r.stdout.splitlines():
            m = re.search(r'"([^"]{4,80})"', line)
            if m:
                strings.append(m.group(1).encode())
        for i, s in enumerate(strings[:max(0, n - len(created))]):
            p = os.path.join(corpus_dir, f"r2_{i:03d}")
            with open(p, "wb") as f:
                f.write(s)
            created.append(p)
    except Exception:
        pass

    return created


# ── Auto harness — find the riskiest function ─────────────────────────────────

def auto_harness(binary: str, llm=None) -> str:
    """
    Use r2 to find the function with the most dangerous sink calls
    (sprintf, strcpy, memcpy, recv, read, etc.) and generate a libFuzzer
    harness focused on that function.
    """
    best_func = None
    best_score = 0

    _SINK_WEIGHT = {
        "sprintf": 3, "vsprintf": 3, "strcpy": 3, "strcat": 3,
        "gets": 4, "scanf": 4,
        "memcpy": 2, "memmove": 2, "strncpy": 1,
        "recv": 2, "recvfrom": 2, "read": 1, "fread": 1,
    }

    try:
        r = subprocess.run(
            ["r2", "-A", "-q", "-c", "axt~", binary],
            capture_output=True, text=True, timeout=30,
        )
        # Map: func_name → score
        func_scores: dict = {}
        for line in r.stdout.splitlines():
            # axt output: addr  code  callee  <caller_func>
            parts = line.split()
            if len(parts) < 4:
                continue
            callee = parts[2].strip("[]") if len(parts) > 2 else ""
            caller = parts[-1] if parts[-1].startswith("sym.") else ""
            sym_name = callee.lstrip("sym.").lstrip("plt.")
            weight = _SINK_WEIGHT.get(sym_name, 0)
            if weight and caller:
                func_scores[caller] = func_scores.get(caller, 0) + weight
        if func_scores:
            best_func, best_score = max(func_scores.items(), key=lambda kv: kv[1])
    except Exception:
        pass

    # Optionally ask Qwen for harness framing advice
    extra_comment = ""
    if llm and best_func:
        try:
            import urllib.request, json as _json
            prompt = (
                f"I am writing a libFuzzer harness for the function `{best_func}` in binary `{binary}`. "
                f"It scored {best_score} on a dangerous-sink heuristic. "
                f"In 2 sentences, what should I watch for when framing the input buffer? "
                f"Be concise and specific."
            )
            req = urllib.request.Request(
                f"{os.environ.get('OLLAMA_URL', 'http://localhost:11434')}/api/generate",
                data=_json.dumps({"model": os.environ.get("BINORACLE_MODEL", "qwen2.5-coder:7b"),
                                  "prompt": prompt, "stream": False, "temperature": 0.1,
                                  "num_predict": 100}).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=20) as resp:
                extra_comment = _json.loads(resp.read()).get("response", "").strip()
        except Exception:
            pass

    func_name = best_func or "target_function"
    comment = f"// Qwen hint: {extra_comment}" if extra_comment else "// Adjust the call to match the real function signature."
    return libfuzzer_harness(func_name, comment=comment)


# ── Crash triage ──────────────────────────────────────────────────────────────

def triage_crashes(crashes_dir: str, binary: str = "") -> List[CrashReport]:
    """
    Deduplicate AFL++ crashes by symbolized stack hash.
    Runs the binary under gdb (or lldb on macOS) for each crash to get a backtrace,
    hashes the top 5 frame addresses.
    Returns a list of CrashReport with duplicates marked unique=False.
    For AUTHORIZED targets only.
    """
    reports: List[CrashReport] = []
    seen_hashes: set = set()

    if not os.path.isdir(crashes_dir):
        return reports

    crash_files = sorted(
        f for f in os.listdir(crashes_dir)
        if not f.startswith(".") and f != "README.txt"
    )

    for fname in crash_files[:50]:  # cap at 50
        fpath = os.path.join(crashes_dir, fname)
        signal_name = None
        frames: List[str] = []

        if binary and os.path.exists(binary):
            # Try gdb
            gdb_script = "run < '{}'\nbt 10\nquit".format(fpath)
            try:
                r = subprocess.run(
                    ["gdb", "-batch", "-ex", gdb_script, "--args", binary],
                    capture_output=True, text=True, timeout=15,
                )
                for line in r.stdout.splitlines():
                    if line.strip().startswith("#"):
                        frames.append(line.strip())
                    if "Signal" in line or "SIGSEGV" in line or "SIGABRT" in line:
                        m = re.search(r"SIG\w+", line)
                        if m:
                            signal_name = m.group(0)
            except Exception:
                pass

        # Hash: top 5 frames by address only (strip filenames/line numbers for stability)
        addr_re = re.compile(r"0x[0-9a-f]+")
        top_addrs = []
        for fr in frames[:5]:
            m = addr_re.search(fr)
            if m:
                top_addrs.append(m.group(0))
        stack_hash = hex(hash(tuple(top_addrs)) & 0xffffffff)

        unique = stack_hash not in seen_hashes
        seen_hashes.add(stack_hash)
        reports.append(CrashReport(
            crash_file=fpath, stack_hash=stack_hash,
            signal=signal_name, top_frames=frames[:5], unique=unique,
        ))

    return reports


# ── Harness generators ────────────────────────────────────────────────────────

def libfuzzer_harness(target_func: str = "target_function",
                       comment: str = "") -> str:
    extra = f"\n    {comment}" if comment else ""
    return f'''// libFuzzer harness generated by binoracle
// AUTHORIZED USE ONLY.
// Build: clang -g -O1 -fsanitize=fuzzer,address harness.c -o fuzz_{target_func}
//        (add -fsanitize=fuzzer,address,undefined for UBSan too)
// Run:   ./fuzz_{target_func} -max_len=4096 -timeout=100 corpus/ -artifact_prefix=crashes/
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// TODO: declare or include the real prototype.
extern void {target_func}(const unsigned char *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {{
    // Feed the fuzz buffer. Adapt the call to the real signature:
    //   C string target:  char *copy = strndup((char*)Data, Size); {target_func}(copy); free(copy);
    //   struct target:    struct Foo f; memset(&f, 0, sizeof(f)); memcpy(&f, Data, min(Size, sizeof(f)));
    {target_func}(Data, Size);{extra}
    return 0;
}}
'''


def afl_command(binary: str, via_stdin: bool = True,
                persistent: bool = False, qemu: bool = True) -> str:
    inp = "@@" if not via_stdin else ""
    argline = f"{binary} {inp}".strip()
    persistent_note = (
        "# PERSISTENT MODE: add __AFL_FUZZ_INIT() + __AFL_LOOP(10000) in harness.c\n"
        f"# Then: afl-fuzz -i in -o out -- ./harness.afl\n"
    ) if persistent else ""
    qemu_flag = "-Q " if qemu else ""
    return f'''# AFL++ fuzzing — AUTHORIZED USE ONLY
# 1) seed corpus
mkdir -p in out crashes && printf 'A' > in/seed && printf '\\x00' > in/null

# 2) (best) build with AFL instrumentation when you have source:
#    CC=afl-clang-fast CXX=afl-clang-fast++ make -C /src
#    Then drop -Q from the fuzz command below.
{persistent_note}
# 3) start fuzzing ({("QEMU black-box mode" if qemu else "instrumented mode")})
AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \\
afl-fuzz {qemu_flag}-i in -o out -- {argline}

# 4) check findings
afl-tmin -i out/crashes/id:* -o minimized/ -- {binary}  # minimize a crash
afl-cov -d out --coverage-cmd "{binary} @@" --code-dir /src  # coverage (optional)
'''


def radamsa_command(binary: str, input_format: str = "text",
                    iterations: int = 10000) -> str:
    seed_file = f"seed.{input_format}"
    return f'''# Radamsa file-mutation fuzzing — AUTHORIZED USE ONLY
# Install: brew install radamsa  OR  apt install radamsa

# 1) place a valid sample in {seed_file}
# 2) fuzz loop
mkdir -p crashes
for i in $(seq 1 {iterations}); do
    radamsa {seed_file} > /tmp/fuzz_input
    timeout 2 {binary} /tmp/fuzz_input 2>/dev/null
    EXIT=$?
    # collect crashes (not clean exits 0/1)
    if [ $EXIT -gt 1 ] && [ $EXIT -ne 124 ]; then
        cp /tmp/fuzz_input crashes/crash_$i.{input_format}
    fi
done
echo "done — $(ls crashes | wc -l) crashes found"
'''


def structured_harness(target_module: str = "target",
                        input_description: str = "arbitrary bytes") -> str:
    return f'''# Hypothesis / property-based harness — AUTHORIZED USE ONLY
# pip install hypothesis pytest
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st
import {target_module}

@given(st.binary(max_size=4096))  # adjust to match: {input_description}
@settings(max_examples=10000, suppress_health_check=[HealthCheck.too_slow])
def test_no_crash(data: bytes):
    # Replace with the real function call; adapt the type (bytes → str, etc.)
    try:
        {target_module}.parse(data)  # TODO: adapt
    except (ValueError, TypeError):
        pass  # expected parse errors are fine; crashes/assertions are not
'''


# ── Top-level entry point ─────────────────────────────────────────────────────

def generate_fuzz(binary: str, target_func: Optional[str] = None,
                  mode: str = "afl", llm=None) -> str:
    """Generate a fuzzer harness or command for `binary`."""
    if mode == "libfuzzer":
        return libfuzzer_harness(target_func or "target_function")
    if mode == "auto":
        return auto_harness(binary, llm=llm)
    if mode == "radamsa":
        return radamsa_command(binary)
    if mode == "structured":
        return structured_harness()
    return afl_command(binary)


def render_fuzz_plan(config: FuzzConfig) -> str:
    """Markdown fuzz plan from a FuzzConfig."""
    out = [
        f"# Fuzz plan — `{os.path.basename(config.binary)}`\n",
        f"- mode: **{config.mode}**\n",
        f"- input type: {config.input_type}\n",
        f"- corpus: `{config.corpus_dir}` → output: `{config.output_dir}`\n",
        f"- max input len: {config.max_len} bytes, timeout: {config.timeout_ms} ms\n",
        f"- ASan: {'yes' if config.with_asan else 'no'}, "
        f"UBSan: {'yes' if config.with_ubsan else 'no'}\n",
    ]
    if config.target_func:
        out.append(f"- target function: `{config.target_func}`\n")
    if config.notes:
        out.append("\n## Notes\n")
        for n in config.notes:
            out.append(f"- {n}\n")
    out.append("\n## Harness\n```\n" + generate_fuzz(
        config.binary, config.target_func, config.mode) + "\n```\n")
    return "".join(out)
