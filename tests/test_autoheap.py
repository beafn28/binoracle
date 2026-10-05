"""Menu-shape detection for the heap->shell driver (generalization beyond heapexp)."""
import ast
import json
import os
import tempfile

from binoracle.workflows.autoheap import _HEAP_SHELL_DRIVER, detect_menu_spec


def _fake_elf(menu: str) -> str:
    f = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
    f.write(b"\x7fELF" + b"\x00" * 40 + menu.encode() + b"\x00")
    f.close()
    return f.name


def test_detect_real_heapexp():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sample = os.path.join(here, "samples", "bin", "heapexp")
    if not os.path.exists(sample):
        return  # sample not built in this checkout
    spec = detect_menu_spec(sample)
    assert spec == {"prompt": "> ", "new": 1, "free": 2, "edit": 3, "show": 4}


def test_detect_menu_variants():
    # Reordered + dot separators + '>> ' prompt: numbers must follow the LABELS, not position.
    cases = {
        "1. Delete\n2. Create\n3. Show\n4. Edit\n>> ":
            {"prompt": ">> ", "new": 2, "free": 1, "edit": 4, "show": 3},
        # Spanish labels, bracket separators, worded prompt.
        "[1] Reservar\n[2] Liberar\n[3] Editar\n[4] Mostrar\nopcion: ":
            {"prompt": "opcion: ", "new": 1, "free": 2, "edit": 3, "show": 4},
        # Extra non-CRUD option (exit) must be ignored; 'view'->show, 'add'->new.
        "1) add note\n2) edit note\n3) view note\n4) delete note\n5) exit\nchoice> ":
            {"prompt": "choice> ", "new": 1, "free": 4, "edit": 2, "show": 3},
    }
    for menu, want in cases.items():
        p = _fake_elf(menu)
        try:
            assert detect_menu_spec(p) == want, menu
        finally:
            os.unlink(p)


def test_detect_menu_none_when_incomplete():
    # Only three mappable ops (no edit) -> cannot drive the exploit -> None (honest).
    p = _fake_elf("1) alloc\n2) free\n3) show\n> ")
    try:
        assert detect_menu_spec(p) is None
    finally:
        os.unlink(p)


def test_driver_renders_with_spec():
    spec = {"prompt": ">> ", "new": 2, "free": 1, "edit": 4, "show": 3}
    rendered = _HEAP_SHELL_DRIVER.replace("__SPEC_JSON__", json.dumps(spec))
    assert "__SPEC_JSON__" not in rendered
    ast.parse(rendered)  # still valid Python after injection
