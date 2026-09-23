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
    # top-1 doc must be exactly right for these unambiguous queries
    top1 = {
        "gets buffer overflow no PIE win function": "ret2win",
        "double free tcache glibc no hooks": "heap",
    }
    for query, expected in top1.items():
        hits = kb.retrieve(query, k=3)
        assert hits and hits[0][0].doc == expected, f"{query!r} -> {hits[0][0].doc if hits else None}"

    # for these, the expected doc must at least appear in the top-k results
    topk = {
        "printf user format string got overwrite": "format-string",
        "NX static binary execve syscall chain": "rop",
    }
    for query, expected in topk.items():
        docs = [c.doc for c, _ in kb.retrieve(query, k=4)]
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
