"""YesWeHack scope filter — loads program scopes and matches CVE descriptions.

Scope config lives in ~/.config/binoracle/ywh_scope.json  (or
$BINORACLE_SCOPE_FILE env var).  Format:

  {
    "programs": [
      {
        "slug": "acme-corp",
        "in_scope": ["wordpress", "drupal", "ghost", "strapi", "*.acme.com"],
        "out_of_scope": ["mobile", "ios", "android"],
        "tech_keywords": ["php", "node", "python"]
      }
    ]
  }

`in_scope` entries are matched case-insensitively against:
  - CVE description text
  - CWE / CVSS vector
  - NVD CPE product names (if available)

A CVE matches the scope if at least one `in_scope` keyword appears in the
description AND no `out_of_scope` keyword appears.

If the scope file doesn't exist or is empty, all CVEs pass (no filtering).
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
from typing import List, Optional


_DEFAULT_SCOPE_PATH = os.path.join(
    os.environ.get("BINORACLE_CONFIG_DIR") or os.path.join(
        os.path.expanduser("~"), ".config", "binoracle"),
    "ywh_scope.json",
)

_SCOPE_FILE = os.environ.get("BINORACLE_SCOPE_FILE", _DEFAULT_SCOPE_PATH)


def _load_scope() -> dict:
    try:
        with open(_SCOPE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except Exception:
        return {}


def _text_matches_patterns(text: str, patterns: List[str]) -> bool:
    text_lc = text.lower()
    for pat in patterns:
        p = pat.lower()
        # wildcard glob (*.acme.com) → fnmatch on each word
        if "*" in p or "?" in p:
            for word in re.split(r"[\s,;]+", text_lc):
                if fnmatch.fnmatch(word, p):
                    return True
        else:
            if p in text_lc:
                return True
    return False


def cve_matches_scope(cve_id: str, description: str,
                      cpe_products: Optional[List[str]] = None) -> dict:
    """Check whether a CVE is in scope for at least one configured YWH program.

    Returns:
        {
          "in_scope": bool,
          "matched_programs": [slug, ...],
          "reason": str,
        }

    When no scope file exists or programs list is empty, returns in_scope=True
    (open/permissive mode — investigate everything).
    """
    scope = _load_scope()
    programs = scope.get("programs") or []
    if not programs:
        return {"in_scope": True, "matched_programs": [], "reason": "no scope file — permissive mode"}

    text = " ".join(filter(None, [description, cve_id] + (cpe_products or [])))
    matched: list[str] = []

    for prog in programs:
        slug = prog.get("slug", "?")
        in_kws = prog.get("in_scope") or []
        out_kws = prog.get("out_of_scope") or []
        tech_kws = prog.get("tech_keywords") or []

        # Must match at least one in_scope keyword
        all_kws = in_kws + tech_kws
        if all_kws and not _text_matches_patterns(text, all_kws):
            continue
        # Must NOT match any out_of_scope keyword
        if out_kws and _text_matches_patterns(text, out_kws):
            continue
        matched.append(slug)

    if matched:
        return {
            "in_scope": True,
            "matched_programs": matched,
            "reason": f"matches programs: {', '.join(matched)}",
        }
    return {
        "in_scope": False,
        "matched_programs": [],
        "reason": "no program scope matches this CVE",
    }


def scope_summary() -> str:
    """Return a one-line summary of the loaded scope config."""
    scope = _load_scope()
    programs = scope.get("programs") or []
    if not programs:
        return f"scope: no config at {_SCOPE_FILE} — permissive (all CVEs)"
    slugs = [p.get("slug", "?") for p in programs]
    total_kws = sum(len(p.get("in_scope") or []) + len(p.get("tech_keywords") or [])
                    for p in programs)
    return (f"scope: {len(programs)} program(s) [{', '.join(slugs[:4])}], "
            f"{total_kws} in-scope keywords")


def write_example_scope() -> str:
    """Write an example scope file if none exists. Returns the path."""
    os.makedirs(os.path.dirname(_SCOPE_FILE), exist_ok=True)
    if os.path.exists(_SCOPE_FILE):
        return _SCOPE_FILE
    example = {
        "programs": [
            {
                "slug": "example-program",
                "in_scope": [
                    "wordpress", "drupal", "joomla", "ghost", "strapi",
                    "directus", "wagtail", "craft cms", "payload cms",
                    "django", "flask", "fastapi", "rails", "laravel",
                    "express", "nestjs", "graphql"
                ],
                "out_of_scope": ["android", "ios", "mobile", "firmware", "kernel"],
                "tech_keywords": ["php", "python", "ruby", "node", "javascript"]
            }
        ]
    }
    with open(_SCOPE_FILE, "w", encoding="utf-8") as f:
        json.dump(example, f, indent=2)
    return _SCOPE_FILE
