"""Exploit-trainer playbook export: grounded, verified-only, RAG-indexable."""
import os
import tempfile

from binoracle.workflows.exploit_trainer import (
    TrainCase, TrainingReport, export_playbook, default_playbook_path, _mitig_summary,
)


def _rep():
    rep = TrainingReport(attempted=3, verified=2)
    rep.cases = [
        TrainCase(binary="a", name="ret2win", arch="x86", bits="64", mitig="NX",
                  vuln_class="stack-overflow", strategy="ret2win", verified=True,
                  offset=72, engine="native"),
        TrainCase(binary="b", name="fmtstring_pie", arch="x86", bits="64",
                  mitig="NX+PIE+Full-RELRO", vuln_class="format-string",
                  strategy="ret2system (full RELRO)", verified=True, offset=6, engine="native"),
        TrainCase(binary="c", name="dud", arch="x86", vuln_class="stack-overflow",
                  strategy="template", verified=False),
    ]
    return rep


def test_mitig_summary_lists_only_active():
    assert _mitig_summary({"nx": True, "pie": True, "canary": False, "relro": "full"}) == "NX+PIE+Full-RELRO"
    assert _mitig_summary({"nx": False, "pie": False, "relro": "partial"}) == "Partial-RELRO"
    assert _mitig_summary({"nx": False}) == "sin mitigaciones"


def test_export_playbook_only_verified_and_indexable():
    p = tempfile.mktemp(suffix=".md")
    try:
        n = export_playbook(_rep(), p)
        assert n == 2, "deberia escribir 2 tecnicas verificadas (no la fallida)"
        text = open(p, encoding="utf-8").read()
        # only verified samples; the unverified 'dud' must not appear
        assert "ret2win" in text and "fmtstring_pie" in text
        assert "dud" not in text
        # each technique is a '## ' section so the RAG chunks it; mitigations + engine recorded
        assert text.count("\n## ") == 2
        assert "NX+PIE+Full-RELRO" in text and "native" in text
        # grounded framing: verified-by-execution, nothing inferred
        assert "VERIFICADO" in text or "verificad" in text.lower()
    finally:
        try:
            os.unlink(p)
        except OSError:
            pass


def test_export_playbook_dedups_by_class_strategy():
    rep = _rep()
    # a second ret2win case (same class+strategy) must collapse to one technique entry
    rep.cases.append(TrainCase(binary="d", name="ret2win_dup", arch="x86", bits="64",
                               mitig="NX", vuln_class="stack-overflow", strategy="ret2win",
                               verified=True, offset=88, engine="native"))
    p = tempfile.mktemp(suffix=".md")
    try:
        n = export_playbook(rep, p)
        assert n == 2, "mismo (clase, estrategia) no debe duplicar la seccion"
    finally:
        try:
            os.unlink(p)
        except OSError:
            pass


def test_export_playbook_empty_when_nothing_verified():
    rep = TrainingReport(attempted=1, verified=0)
    rep.cases = [TrainCase(binary="x", name="x", vuln_class="stack-overflow", verified=False)]
    p = tempfile.mktemp(suffix=".md")
    assert export_playbook(rep, p) == 0
    assert not os.path.exists(p), "no debe escribir fichero si no hay nada verificado"


def test_default_playbook_path_in_kb():
    d = default_playbook_path()
    assert d.endswith(os.path.join("kb", "verified-playbook.md"))
