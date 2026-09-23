"""RAG knowledge base: indexing + retrieval relevance."""

from binoracle.rag import get_kb, query_from_facts


def test_kb_loads_chunks():
    kb = get_kb()
    assert len(kb.chunks) > 20
    docs = {c.doc for c in kb.chunks}
    for expected in ("ret2win", "rop", "ret2libc", "format-string", "heap", "mitigations"):
        assert expected in docs


def test_retrieval_is_relevant():
    kb = get_kb()
    # The expected cheat sheet must appear in the top-3 results. We assert PRESENCE in the
    # top-k (how the RAG actually feeds the model), not a single #1 rank, because several
    # sheets legitimately cover overlapping techniques. Queries are kept discriminative and
    # free of incidental tokens (e.g. "no PIE") that name an unrelated sheet.
    cases = {
        "format string percent n arbitrary write": "format-string",
        "execve syscall rop chain static binary": "rop",
        "gift win function stack overflow jump": "ret2win",
        "double free tcache poisoning": "heap",
        "use after free vtable dangling object": "uaf-typeconfusion",
        "leak libc puts then call system shell": "ret2libc",
        "commit_creds prepare_kernel_cred modprobe": "kernel-pwn",
        "addrof fakeobj type confusion float array": "browser-v8",
        "open read write flag seccomp sandbox": "syscalls-seccomp",
    }
    for query, expected in cases.items():
        docs = [c.doc for c, _ in kb.retrieve(query, k=3)]
        assert expected in docs, f"{query!r} -> {docs}"


def test_context_for_is_bounded():
    kb = get_kb()
    ctx = kb.context_for("ret2libc leak puts got system", k=4, max_chars=800)
    assert ctx and len(ctx) <= 900  # bound + small header slack


def test_query_from_facts():
    q = query_from_facts({
        "mitigations": {"NX": "enabled", "PIE": "no", "Canary": "no"},
        "imports": ["gets", "system"],
        "primitives": ["ret2win"],
    })
    assert "ret2win" in q and "gets" in q


def test_empty_query_returns_nothing():
    assert get_kb().retrieve("", k=3) == []
