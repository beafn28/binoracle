"""Version matrix testing for WordPress plugins.

Given a confirmed vulnerable version, finds the exact vulnerable range by testing
adjacent versions on WP.org SVN, so exploit reports can state precise affected ranges.
"""
from __future__ import annotations

import re
import urllib.request
from typing import Callable, Optional


def get_plugin_version_history(plugin_slug: str, max_versions: int = 20) -> list:
    """Fetch version history from WP.org SVN tags. Returns sorted list newest-first."""
    url = f"https://plugins.svn.wordpress.org/{plugin_slug}/tags/"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "binoracle/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            html = resp.read().decode("utf-8", errors="replace")
    except Exception:
        return []

    # SVN directory listing: <li><a href="4.5.1/">4.5.1/</a></li>
    versions = re.findall(r'href="([0-9][^/"]+)/"', html)
    if not versions:
        return []

    def _ver_key(v: str):
        parts = []
        for p in re.split(r"[.\-]", v):
            try:
                parts.append(int(p))
            except ValueError:
                parts.append(0)
        # pad to 4 parts
        while len(parts) < 4:
            parts.append(0)
        return tuple(parts)

    versions = sorted(set(versions), key=_ver_key, reverse=True)
    return versions[:max_versions]


def semver_adjacent(version: str, direction: str, step_size: int = 1) -> Optional[str]:
    """Return the adjacent version in the given direction.

    '4.5.1' + 'down' → '4.5.0'; '4.5.0' + 'down' → '4.4.99' (approximate)
    '4.5.1' + 'up'   → '4.5.2'
    Returns None if version cannot be parsed.
    """
    parts = re.split(r"\.", version.strip())
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return None

    if len(nums) < 2:
        return None

    # Normalise to 3-part
    while len(nums) < 3:
        nums.append(0)

    major, minor, patch = nums[0], nums[1], nums[2]

    if direction == "up":
        patch += step_size
    elif direction == "down":
        patch -= step_size
        if patch < 0:
            minor -= 1
            if minor < 0:
                major -= 1
                if major < 0:
                    return None
                minor = 99
            patch = 99  # caller will verify against real version list
    else:
        return None

    return f"{major}.{minor}.{patch}"


def find_vulnerable_range(
    plugin_slug: str,
    confirmed_version: str,
    verify_fn: Callable[[str], bool],
    max_versions: int = 6,
    step: Callable = print,
) -> dict:
    """Find the full vulnerable version range given one confirmed vulnerable version.

    Uses real WP.org version history so only real versions are tested.
    """
    result: dict = {
        "confirmed_vulnerable": [confirmed_version],
        "confirmed_patched": [],
        "lower_bound": confirmed_version,
        "upper_bound": confirmed_version,
        "fixed_in": None,
        "range_string": confirmed_version,
        "versions_tested": 1,
    }

    step(f"version_matrix: fetching version history for '{plugin_slug}'...")
    history = get_plugin_version_history(plugin_slug)
    if not history:
        step("version_matrix: no version history from WP.org, testing semver adjacents only")

    # Build a set of known real versions for fast lookup
    known = set(history)

    def _is_real(v: str) -> bool:
        return (v in known) if known else True  # if no history, assume real

    budget = max_versions - 1  # already used 1 for confirmed_version

    # --- search downward (find lower bound) ---
    step(f"version_matrix: searching below {confirmed_version}...")
    cursor = confirmed_version
    while budget > 0:
        candidate = None
        # Try to find the previous real version from history
        if history:
            try:
                idx = history.index(cursor)
                if idx + 1 < len(history):
                    candidate = history[idx + 1]  # history is newest-first
            except ValueError:
                pass
        if candidate is None:
            candidate = semver_adjacent(cursor, "down")
            if candidate and not _is_real(candidate):
                # Try to find nearest lower in history
                candidate = None
                if history:
                    try:
                        idx = history.index(cursor)
                        for h in history[idx + 1:]:
                            candidate = h
                            break
                    except ValueError:
                        pass

        if not candidate:
            step(f"version_matrix: no more versions below {cursor}")
            break

        step(f"version_matrix: testing {candidate} (below {cursor})...")
        budget -= 1
        result["versions_tested"] += 1

        try:
            vuln = verify_fn(candidate)
        except Exception as e:
            step(f"version_matrix: error testing {candidate}: {e}")
            break

        if vuln:
            step(f"version_matrix: {candidate} → VULNERABLE")
            result["confirmed_vulnerable"].append(candidate)
            result["lower_bound"] = candidate
            cursor = candidate
        else:
            step(f"version_matrix: {candidate} → NOT VULNERABLE (lower boundary found)")
            result["confirmed_patched"].append(candidate)
            break

    # --- search upward (find fix version) ---
    step(f"version_matrix: searching above {confirmed_version}...")
    cursor = confirmed_version
    while budget > 0:
        candidate = None
        if history:
            try:
                idx = history.index(cursor)
                if idx - 1 >= 0:
                    candidate = history[idx - 1]  # newer version
            except ValueError:
                pass
        if candidate is None:
            candidate = semver_adjacent(cursor, "up")
            if candidate and not _is_real(candidate):
                candidate = None
                if history:
                    try:
                        idx = history.index(cursor)
                        for h in reversed(history[:idx]):
                            candidate = h
                            break
                    except ValueError:
                        pass

        if not candidate:
            step(f"version_matrix: no more versions above {cursor}")
            break

        step(f"version_matrix: testing {candidate} (above {cursor})...")
        budget -= 1
        result["versions_tested"] += 1

        try:
            vuln = verify_fn(candidate)
        except Exception as e:
            step(f"version_matrix: error testing {candidate}: {e}")
            break

        if vuln:
            step(f"version_matrix: {candidate} → VULNERABLE")
            result["confirmed_vulnerable"].append(candidate)
            result["upper_bound"] = candidate
            cursor = candidate
        else:
            step(f"version_matrix: {candidate} → NOT VULNERABLE (fix version found)")
            result["confirmed_patched"].append(candidate)
            result["fixed_in"] = candidate
            break

    # Build human-readable range string
    lb = result["lower_bound"]
    ub = result["upper_bound"]
    fixed = result["fixed_in"]
    if lb == ub:
        base = lb
    else:
        base = f"{lb} – {ub}"
    if fixed:
        result["range_string"] = f"{base} (fixed: {fixed})"
    else:
        result["range_string"] = f"{base} (upper bound not confirmed)"

    step(f"version_matrix: range = {result['range_string']} "
         f"({result['versions_tested']} versions tested)")
    return result
