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
    # For each query the retriever must return, in its top-3, content that actually covers the
    # topic. We check that a distinctive keyword appears in the retrieved CONTENT (title+text),
    # not a specific file name: several curated sheets and imported skills cover overlapping
    # techniques, so asserting an exact doc id is brittle. This tests real relevance.
    cases = {
        "format string percent n arbitrary write": ("%n", "format"),
        "execve syscall rop chain static binary": ("execve",),
        "ret2win gift win function jump no leak": ("ret2win", "win"),
        "double free tcache poisoning": ("tcache",),
        "tcache key clear zeroes GOT neighbor malloc free@GOT win": ("key", "got"),
        "use after free vtable dangling object": ("vtable", "use", "uaf"),
        "leak libc puts then call system shell": ("libc", "system"),
        "commit_creds prepare_kernel_cred modprobe": ("commit_creds", "modprobe"),
        "addrof fakeobj type confusion float array": ("fakeobj", "addrof"),
        "open read write flag seccomp sandbox": ("seccomp", "orw"),
    }
    for query, keywords in cases.items():
        hits = kb.retrieve(query, k=3)
        assert hits, f"no hits for {query!r}"
        blob = " ".join((c.title + " " + c.text).lower() for c, _ in hits)
        assert any(kw.lower() in blob for kw in keywords), f"{query!r} -> {[c.doc for c,_ in hits]}"


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
