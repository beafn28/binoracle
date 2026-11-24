"""
Workspace Guard — tracks file mutations, enforces scope, and detects unexpected changes.

Before any agent-driven repair, the guard records baseline hashes.
After the repair, it compares hashes and reports:
  - Files changed (expected)
  - Files changed outside allowed scope (violation)
  - New unexpected files
  - Removed files

The controller uses this to verify diffs are appropriate and block scope violations.
"""
from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class FileDelta:
    path:      str
    action:    str   # "modified" | "added" | "removed" | "unchanged"
    old_hash:  str = ""
    new_hash:  str = ""
    size_delta: int = 0
    in_scope:  bool = True


@dataclass
class WorkspaceDiff:
    snapshot_at:  float
    compared_at:  float
    modified:     List[FileDelta] = field(default_factory=list)
    added:        List[FileDelta] = field(default_factory=list)
    removed:      List[FileDelta] = field(default_factory=list)
    violations:   List[FileDelta] = field(default_factory=list)   # out-of-scope changes

    @property
    def has_violations(self) -> bool:
        return len(self.violations) > 0

    @property
    def any_changes(self) -> bool:
        return bool(self.modified or self.added or self.removed)

    def summary(self) -> str:
        parts = []
        if self.modified:
            parts.append(f"{len(self.modified)} modified")
        if self.added:
            parts.append(f"{len(self.added)} added")
        if self.removed:
            parts.append(f"{len(self.removed)} removed")
        if self.violations:
            parts.append(f"⚠ {len(self.violations)} OUT-OF-SCOPE")
        return ", ".join(parts) or "no changes"


def _file_hash(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()[:16]
    except Exception:
        return ""


def _walk_tree(root: str, max_files: int = 2000) -> Dict[str, str]:
    """Return {rel_path: sha256_prefix} for all files under root."""
    hashes: Dict[str, str] = {}
    root_path = Path(root).resolve()
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        # Skip common noise
        dirnames[:] = [d for d in dirnames if d not in {
            ".git", "__pycache__", "node_modules", ".venv", "venv",
            ".tox", "dist", "build", ".mypy_cache", ".pytest_cache",
        }]
        for fname in filenames:
            if count >= max_files:
                break
            fpath = Path(dirpath) / fname
            try:
                rel = str(fpath.resolve().relative_to(root_path))
            except ValueError:
                continue
            hashes[rel] = _file_hash(str(fpath))
            count += 1
    return hashes


class WorkspaceGuard:
    """
    Usage:
        guard = WorkspaceGuard(workspace="/path/to/project", allowed_paths=["src/", "tests/"])
        guard.snapshot()
        # ... agent makes changes ...
        diff = guard.diff()
        if diff.has_violations:
            guard.report_violations(diff)
    """

    def __init__(
        self,
        workspace:     str = ".",
        allowed_paths: Optional[List[str]] = None,
        ignored_paths: Optional[List[str]] = None,
    ):
        self.workspace      = str(Path(workspace).resolve())
        self.allowed_paths  = allowed_paths or []  # relative to workspace; empty = all allowed
        self.ignored_paths  = set(ignored_paths or [
            ".git", "__pycache__", "node_modules", ".venv",
            "*.pyc", "*.log", "*.tmp",
        ])
        self._baseline:     Dict[str, str] = {}
        self._snapshot_at:  float = 0.0

    def snapshot(self) -> None:
        """Record current state of the workspace."""
        self._baseline    = _walk_tree(self.workspace)
        self._snapshot_at = time.time()

    def diff(self) -> WorkspaceDiff:
        """Compare current state against the last snapshot."""
        if not self._baseline:
            self.snapshot()
            return WorkspaceDiff(snapshot_at=self._snapshot_at, compared_at=time.time())

        current = _walk_tree(self.workspace)
        result = WorkspaceDiff(
            snapshot_at = self._snapshot_at,
            compared_at = time.time(),
        )

        old_keys = set(self._baseline.keys())
        new_keys  = set(current.keys())

        for path in old_keys & new_keys:
            if self._baseline[path] != current[path]:
                delta = FileDelta(
                    path     = path,
                    action   = "modified",
                    old_hash = self._baseline[path],
                    new_hash = current[path],
                )
                in_scope = self._is_in_scope(path)
                delta.in_scope = in_scope
                result.modified.append(delta)
                if not in_scope:
                    result.violations.append(delta)

        for path in new_keys - old_keys:
            delta = FileDelta(path=path, action="added", new_hash=current[path])
            in_scope = self._is_in_scope(path)
            delta.in_scope = in_scope
            result.added.append(delta)
            if not in_scope:
                result.violations.append(delta)

        for path in old_keys - new_keys:
            delta = FileDelta(path=path, action="removed", old_hash=self._baseline[path])
            in_scope = self._is_in_scope(path)
            delta.in_scope = in_scope
            result.removed.append(delta)
            if not in_scope:
                result.violations.append(delta)

        return result

    def _is_in_scope(self, rel_path: str) -> bool:
        """Check whether a file change is within allowed paths."""
        if not self.allowed_paths:
            return True   # no restriction — everything is allowed
        return any(
            rel_path.startswith(allowed.rstrip("/") + "/") or rel_path == allowed
            for allowed in self.allowed_paths
        )

    def report_violations(self, diff: WorkspaceDiff) -> str:
        if not diff.has_violations:
            return "No scope violations detected."
        lines = [f"⚠ SCOPE VIOLATIONS ({len(diff.violations)} files outside allowed paths):"]
        for v in diff.violations[:10]:
            lines.append(f"  [{v.action.upper()}] {v.path}")
        return "\n".join(lines)

    def cumulative_diff_text(self) -> str:
        """Returns a human-readable summary of all changes since snapshot."""
        d = self.diff()
        lines = [f"Workspace diff ({d.summary()}) since {time.strftime('%H:%M:%S', time.localtime(d.snapshot_at))}:"]
        for f in d.modified[:10]:
            lines.append(f"  ~ {f.path}")
        for f in d.added[:10]:
            lines.append(f"  + {f.path}")
        for f in d.removed[:5]:
            lines.append(f"  - {f.path}")
        if d.violations:
            lines.append(self.report_violations(d))
        return "\n".join(lines)
