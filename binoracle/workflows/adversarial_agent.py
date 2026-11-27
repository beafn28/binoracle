"""Adversarial agent: second Qwen/ollama pass that challenges the main CVE hypothesis.

adversarial_critique  — tries to DISPROVE the exploit hypothesis before lab time is spent.
patch_bypass_analysis — checks whether a security patch diff is complete or bypassable.
impact_chain_analysis — given confirmed exploit evidence, map the full business-impact chain.

All three use an injected `llm_call(prompt, model) -> str` so they are testable without ollama.
"""
from __future__ import annotations

import json
import re


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _extract_json(text: str) -> dict:
    """Pull the first JSON object out of an LLM response. Returns {} on failure."""
    # Try direct parse first
    text = text.strip()
    try:
        return json.loads(text)
    except Exception:
        pass
    # Find first {...} block
    m = re.search(r"\{[\s\S]*\}", text)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass
    return {}


def _safe_str_list(val) -> list:
    if isinstance(val, list):
        return [str(x) for x in val if x]
    if isinstance(val, str) and val:
        return [val]
    return []


# ---------------------------------------------------------------------------
# adversarial_critique
# ---------------------------------------------------------------------------

_CRITIQUE_PROMPT = """\
You are an adversarial security analyst. Your job is to CHALLENGE an exploit hypothesis for {cve_id}.
Find every reason why the hypothesis might be WRONG. Be specific and cite code when possible.

## Hypothesis
- vuln_class: {vuln_class}
- endpoint: {endpoint}
- http_method: {http_method}
- parameters: {parameters}
- reasoning: {reasoning}

## Relevant source code snippets
{snippets}

## Your tasks (check ALL of these)
1. AUTH CHECKS: Search the snippets for `is_user_logged_in`, `current_user_can`, `check_ajax_referer`,
   `verify_nonce`, `wp_verify_nonce`. If any guard the proposed endpoint, name them.
2. ENDPOINT EXISTS: Does the proposed endpoint appear in the snippets? If not, flag it.
3. PARAMETER NAMES: Do the proposed parameter names appear in the code? If not, suggest correct ones.
4. VERSION GUARDS: Are there version-conditional blocks that might mean this only affects specific versions?
5. VULN CLASS: Is the proposed vuln_class consistent with the code? E.g., is it really SQLi or is it XSS?
6. CORRECTIONS: If you find errors, propose a revised endpoint or params.

Respond ONLY with valid JSON (no markdown, no explanation outside the JSON):
{{
  "confidence_adjustment": <float -1.0 to +1.0>,
  "challenges": ["<specific objection 1>", ...],
  "supported": ["<aspect you agree with>", ...],
  "verdict": "<WEAK|PLAUSIBLE|STRONG>",
  "revised_endpoint": "<corrected endpoint or null>",
  "revised_params": {{}} or null
}}
"""

_CRITIQUE_DEFAULTS: dict = {
    "confidence_adjustment": 0.0,
    "challenges": [],
    "supported": [],
    "verdict": "PLAUSIBLE",
    "revised_endpoint": None,
    "revised_params": None,
}


def adversarial_critique(
    cve_id: str,
    hypothesis: dict,
    source_snippets: list,
    llm_call,
    model: str = "qwen2.5-coder:7b",
) -> dict:
    """Second LLM pass that adversarially challenges the main exploit hypothesis.

    Returns a dict with keys: confidence_adjustment, challenges, supported,
    verdict (WEAK/PLAUSIBLE/STRONG), revised_endpoint, revised_params.
    Never raises — returns safe defaults on LLM or parse failure.
    """
    snippets_text = "\n---\n".join(
        (s if isinstance(s, str) else json.dumps(s))[:600]
        for s in (source_snippets or [])[:6]
    ) or "(no source snippets provided)"

    prompt = _CRITIQUE_PROMPT.format(
        cve_id=cve_id,
        vuln_class=hypothesis.get("vuln_class", "unknown"),
        endpoint=hypothesis.get("endpoint", "unknown"),
        http_method=hypothesis.get("http_method", "POST"),
        parameters=json.dumps(hypothesis.get("parameters") or {}),
        reasoning=(hypothesis.get("reasoning") or "")[:400],
        snippets=snippets_text,
    )

    try:
        raw = llm_call(prompt, model)
    except Exception as exc:
        return {**_CRITIQUE_DEFAULTS, "challenges": [f"llm_call failed: {exc}"]}

    parsed = _extract_json(raw)
    if not parsed:
        return {**_CRITIQUE_DEFAULTS, "challenges": ["LLM returned unparseable response"]}

    result = dict(_CRITIQUE_DEFAULTS)
    try:
        adj = float(parsed.get("confidence_adjustment", 0.0))
        result["confidence_adjustment"] = max(-1.0, min(1.0, adj))
    except (TypeError, ValueError):
        pass
    result["challenges"] = _safe_str_list(parsed.get("challenges"))
    result["supported"] = _safe_str_list(parsed.get("supported"))
    verdict = str(parsed.get("verdict", "PLAUSIBLE")).upper()
    result["verdict"] = verdict if verdict in ("WEAK", "PLAUSIBLE", "STRONG") else "PLAUSIBLE"
    result["revised_endpoint"] = parsed.get("revised_endpoint") or None
    rp = parsed.get("revised_params")
    result["revised_params"] = rp if isinstance(rp, dict) and rp else None
    return result


# ---------------------------------------------------------------------------
# patch_bypass_analysis
# ---------------------------------------------------------------------------

_BYPASS_PROMPT = """\
You are a security researcher analyzing a security patch for {cve_id}.
Determine whether the fix is complete or bypassable.

## Patch diff
{diff}

## Original vulnerability context
- vuln_class: {vuln_class}
- endpoint: {endpoint}
- parameters: {parameters}

## Your tasks
1. WHAT WAS FIXED: Identify the exact check/sanitization/guard added or changed.
2. BYPASS VECTORS: Can the new check be bypassed?
   - Type juggling (PHP loose comparisons: 0 == "foo", true == "anything")
   - Encoding tricks (URL encoding, unicode normalization, null bytes)
   - Alternate code paths not covered by the patch
   - Conditional logic errors (off-by-one, inverted conditions)
3. INCOMPLETE FIX: Was only ONE call site patched while the same pattern exists elsewhere in the diff?
4. CONFIG DEPENDENCY: Is the fix conditional on a configuration value that may be disabled?

Respond ONLY with valid JSON (no markdown):
{{
  "bypass_possible": <true|false>,
  "bypass_reasoning": "<explanation>",
  "bypass_vector": "<specific technique or null>",
  "patch_quality": "<complete|partial|insufficient>"
}}
"""

_BYPASS_DEFAULTS: dict = {
    "bypass_possible": False,
    "bypass_reasoning": "analysis unavailable",
    "bypass_vector": None,
    "patch_quality": "complete",
}


def patch_bypass_analysis(
    cve_id: str,
    patch_diff: str,
    hypothesis: dict,
    llm_call,
    model: str = "qwen2.5-coder:7b",
) -> dict:
    """Analyze a security patch diff to determine if the fix is complete or bypassable.

    Returns a dict with keys: bypass_possible, bypass_reasoning, bypass_vector,
    patch_quality ("complete"/"partial"/"insufficient").
    Never raises.
    """
    if not patch_diff or not patch_diff.strip():
        return {**_BYPASS_DEFAULTS,
                "bypass_reasoning": "no patch diff provided — cannot analyze"}

    prompt = _BYPASS_PROMPT.format(
        cve_id=cve_id,
        diff=patch_diff[:2000],
        vuln_class=hypothesis.get("vuln_class", "unknown"),
        endpoint=hypothesis.get("endpoint", "unknown"),
        parameters=json.dumps(hypothesis.get("parameters") or {}),
    )

    try:
        raw = llm_call(prompt, model)
    except Exception as exc:
        return {**_BYPASS_DEFAULTS,
                "bypass_reasoning": f"llm_call failed: {exc}"}

    parsed = _extract_json(raw)
    if not parsed:
        return {**_BYPASS_DEFAULTS,
                "bypass_reasoning": "LLM returned unparseable response"}

    result = dict(_BYPASS_DEFAULTS)
    result["bypass_possible"] = bool(parsed.get("bypass_possible", False))
    result["bypass_reasoning"] = str(parsed.get("bypass_reasoning") or "")[:500]
    result["bypass_vector"] = parsed.get("bypass_vector") or None
    pq = str(parsed.get("patch_quality", "complete")).lower()
    result["patch_quality"] = (
        pq if pq in ("complete", "partial", "insufficient") else "complete"
    )
    return result


# ---------------------------------------------------------------------------
# Impact chain analysis
# ---------------------------------------------------------------------------

_IMPACT_CHAIN_PROMPT = """\
You are a senior security researcher mapping the full post-exploitation impact chain for
authorized pentest/research. Given CONFIRMED exploit evidence (real dynamic lab output),
reason step by step what an attacker CAN do from this foothold.

Strict rules:
- ONLY reason from the provided evidence. Never invent capabilities not implied by the evidence.
- Use attacker perspective: what does THIS primitive enable?
- Map the chain: Initial Access → Privilege Escalation → Lateral Movement → Impact.
- For each step, cite which piece of evidence justifies it.

CVE: {cve_id}
Vuln class: {vuln_class}
Confirmed evidence (from real lab):
{evidence_json}

Output ONLY valid JSON:
{{
  "initial_access": "<what this exploit achieves — one sentence>",
  "privilege_escalation": "<what escalation is possible from here, or null>",
  "lateral_movement": "<lateral movement paths unlocked, or null>",
  "data_exfiltration": "<data the attacker can exfiltrate with proof from evidence>",
  "persistence_mechanism": "<persistence the attacker can install, or null>",
  "blast_radius": "low|medium|high|critical",
  "blast_radius_reasoning": "<why this severity — cite evidence>",
  "chain_steps": [
    {{"step": 1, "action": "<attacker action>", "evidence_ref": "<field from evidence that enables this>"}},
    ...
  ],
  "max_cve_impact": "<CWE-equivalent one-liner for the full chain>"
}}
"""

_IMPACT_DEFAULTS: dict = {
    "initial_access": "",
    "privilege_escalation": None,
    "lateral_movement": None,
    "data_exfiltration": "",
    "persistence_mechanism": None,
    "blast_radius": "low",
    "blast_radius_reasoning": "",
    "chain_steps": [],
    "max_cve_impact": "",
}


def impact_chain_analysis(
    cve_id: str,
    vuln_class: str,
    evidence: dict,
    llm_call,
    model: str = "qwen2.5-coder:7b",
) -> dict:
    """Map the full post-exploitation impact chain from confirmed dynamic evidence.

    Strictly evidence-based: only capabilities directly implied by the evidence
    are included. Never raises.

    Returns dict with keys from _IMPACT_DEFAULTS.
    """
    if not evidence:
        return {**_IMPACT_DEFAULTS, "blast_radius_reasoning": "no evidence provided"}

    # Sanitize evidence for the prompt: keep only short serializable values
    _safe_ev: dict = {}
    for k, v in (evidence or {}).items():
        if isinstance(v, (str, int, float, bool)):
            _safe_ev[k] = str(v)[:300]
        elif isinstance(v, (list, dict)):
            try:
                _safe_ev[k] = json.dumps(v, ensure_ascii=False)[:300]
            except Exception:
                _safe_ev[k] = str(v)[:200]

    prompt = _IMPACT_CHAIN_PROMPT.format(
        cve_id=cve_id,
        vuln_class=vuln_class,
        evidence_json=json.dumps(_safe_ev, ensure_ascii=False, indent=2)[:2000],
    )

    try:
        raw = llm_call(prompt, model)
    except Exception as exc:
        return {**_IMPACT_DEFAULTS,
                "blast_radius_reasoning": f"llm_call failed: {exc}"}

    parsed = _extract_json(raw)
    if not parsed:
        return {**_IMPACT_DEFAULTS,
                "blast_radius_reasoning": "LLM returned unparseable response"}

    result = dict(_IMPACT_DEFAULTS)
    for _key in ("initial_access", "privilege_escalation", "lateral_movement",
                 "data_exfiltration", "persistence_mechanism",
                 "blast_radius_reasoning", "max_cve_impact"):
        if parsed.get(_key):
            result[_key] = str(parsed[_key])[:600]
    _br = str(parsed.get("blast_radius", "low")).lower()
    result["blast_radius"] = (_br if _br in ("low", "medium", "high", "critical") else "low")
    _steps = parsed.get("chain_steps")
    if isinstance(_steps, list):
        result["chain_steps"] = [
            {"step": s.get("step", i + 1),
             "action": str(s.get("action", ""))[:200],
             "evidence_ref": str(s.get("evidence_ref", ""))[:100]}
            for i, s in enumerate(_steps[:10])
            if isinstance(s, dict)
        ]
    return result
