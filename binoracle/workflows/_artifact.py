"""Shared bounds for artifact readers: cap how much of a file we slurp into memory.

Static readers that read a whole file must not OOM on a maliciously huge artifact. This caps the
amount read and reports an honest 'too large' degrade. The cap is generous (256 MiB) and
configurable via BINORACLE_MAX_ARTIFACT_BYTES."""
from __future__ import annotations

import os

MAX_ARTIFACT_BYTES = int(os.environ.get("BINORACLE_MAX_ARTIFACT_BYTES", str(256 * 1024 * 1024)))


class ArtifactTooLarge(Exception):
    def __init__(self, size: int, cap: int):
        self.size = size
        self.cap = cap
        super().__init__(f"artefacto demasiado grande ({size} B > limite {cap} B); "
                         f"ajusta BINORACLE_MAX_ARTIFACT_BYTES si es intencional")


def read_bounded(path: str, cap: int = None) -> bytes:
    """Read a whole file but refuse to exceed the cap (checked by stat first, then by read)."""
    cap = MAX_ARTIFACT_BYTES if cap is None else cap
    try:
        size = os.path.getsize(path)
        if size > cap:
            raise ArtifactTooLarge(size, cap)
    except OSError:
        pass
    with open(path, "rb") as f:
        data = f.read(cap + 1)
    if len(data) > cap:
        raise ArtifactTooLarge(len(data), cap)
    return data
