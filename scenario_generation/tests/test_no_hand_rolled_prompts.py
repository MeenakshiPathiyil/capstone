"""Tests that nothing builds the [INST] prompt by hand instead of using prompt_format."""

import ast
import json

import pytest

from .conftest import (
    CANONICAL_PROMPT_MODULE,
    EVALUATION_DIR,
    FINE_TUNING_DIR,
    NOTEBOOKS,
    PROMPT_GENERATOR_MODULE,
    REPO_ROOT,
    scanned_python_files,
)


PROMPT_MARKERS = ("[INST]", "[/INST]")

# A string holding this is a notebook shipping prompt_format.py, not a template.
CANONICAL_SOURCE_MARKER = "def build_prompt("


def _repository_module_sources():
    """{filename: current text} for every module a notebook may ship, including the
    canonical prompt_format.py."""
    sources = {
        path.name: path.read_text(encoding="utf-8")
        for path in scanned_python_files()
    }
    sources[CANONICAL_PROMPT_MODULE.name] = CANONICAL_PROMPT_MODULE.read_text(
        encoding="utf-8")
    return sources


def _docstring_constant_ids(tree):
    """ids of the Constant nodes that are docstrings (module / class / function)."""
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", None) or []
            first = body[0] if body else None
            if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                    and isinstance(first.value.value, str)):
                ids.add(id(first.value))
    return ids


def _marker_literals_in_source(source, exempt=()):
    """(lineno, literal) for every non-docstring string literal holding a marker."""
    tree = ast.parse(source)
    skip = _docstring_constant_ids(tree)
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        if id(node) in skip:
            continue
        if not any(marker in node.value for marker in PROMPT_MARKERS):
            continue
        if any(node.value == text for text in exempt):
            continue
        found.append((node.lineno, node.value))
    return found


def _marker_literals(path):
    """Offending literals in a .py file."""
    return _marker_literals_in_source(path.read_text(encoding="utf-8"))


def _code_cells(path):
    """(index, joined source) for every code cell of a notebook."""
    with path.open("r", encoding="utf-8") as f:
        notebook = json.load(f)
    cells = []
    for index, cell in enumerate(notebook.get("cells", [])):
        if cell.get("cell_type") != "code":
            continue
        source = cell.get("source")
        if isinstance(source, list):
            source = "".join(source)
        cells.append((index, source or ""))
    return cells


def _notebook_marker_literals(path, exempt):
    """Offending literals across a notebook's code cells, cell index included."""
    found = []
    for index, source in _code_cells(path):
        try:
            offenders = _marker_literals_in_source(source, exempt=exempt)
        except SyntaxError:
            # A cell of shell magics (`!pip install ...`) is not Python. It cannot
            # hold a prompt either, so it is skipped rather than reported.
            continue
        for lineno, literal in offenders:
            found.append((f"cell {index}, line {lineno}", literal))
    return found


def _canonical_source():
    return CANONICAL_PROMPT_MODULE.read_text(encoding="utf-8")


# ── The scan covers what it claims to cover ───────────────────────────────────

def test_every_notebook_in_the_repository_is_scanned():
    """Notebooks are JSON, so they were invisible to a `*.py` glob while holding
    prompt code. Every one of them must be found, and have code cells to scan.
    """
    names = {path.name for path in NOTEBOOKS}

    assert names == {
        "colab_compare_models.ipynb",
        "colab_finetune_setup.ipynb",
        "finetune_output_test.ipynb",
        "kaggle_compare_models.ipynb",
        "kaggle_prompt_gen.ipynb",
    }, sorted(names)

    for path in NOTEBOOKS:
        assert _code_cells(path), path.name


def test_the_stale_pre_repair_notebooks_are_gone():
    """The two notebooks under fine_tuning/ were pre-repair duplicates of the
    ones create_notebook.py now writes next to itself, and must stay deleted.
    """
    assert not (FINE_TUNING_DIR / "colab_finetune_setup.ipynb").exists()
    assert not (FINE_TUNING_DIR / "finetune_output_test.ipynb").exists()

    # ... and the drifted root-level cell script it shipped alongside
    assert not (REPO_ROOT / "colab_prompt_generator.py").exists()


# ── Nothing hand-rolls the template ───────────────────────────────────────────

@pytest.mark.parametrize("path", scanned_python_files(), ids=lambda p: p.name)
def test_module_does_not_hand_roll_an_inst_prompt(path):
    offenders = _marker_literals(path)
    assert not offenders, (
        f"{path.name} builds an [INST] string itself instead of calling "
        f"prompt_format.build_prompt: {offenders}")


@pytest.mark.parametrize("path", NOTEBOOKS, ids=lambda p: p.name)
def test_notebook_does_not_hand_roll_an_inst_prompt(path):
    """Same assertion, over each code cell's Python. The only marker-bearing literal
    allowed is a verbatim copy of a repository module, which is exempt.
    """
    offenders = _notebook_marker_literals(
        path,
        exempt=tuple(_repository_module_sources().values())
    )
    assert not offenders, (
        f"{path.name} builds an [INST] string itself instead of calling "
        f"prompt_format.build_prompt: {offenders}")


def _shipped_files(path):
    """{filename: shipped text} read out of a notebook's
    `Path(name).write_text(contents)` calls."""
    shipped = {}
    for _, source in _code_cells(path):
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            if not isinstance(function, ast.Attribute) or function.attr != "write_text":
                continue
            target = function.value
            if not (isinstance(target, ast.Call) and node.args):
                continue
            names = [
                argument.value
                for argument in target.args
                if isinstance(argument, ast.Constant)
                and isinstance(argument.value, str)
            ]
            contents = node.args[0]
            if not names or not isinstance(contents, ast.Constant):
                continue
            if not isinstance(contents.value, str):
                continue
            shipped[names[0]] = contents.value
    return shipped


def test_the_notebooks_ship_the_current_modules_verbatim():
    """THE STALENESS CHECK.

    Every module a notebook ships must be byte-identical to the file in the
    repository, or the notebook runs code the tests never saw.
    """
    sources = _repository_module_sources()

    assert CANONICAL_SOURCE_MARKER in sources[CANONICAL_PROMPT_MODULE.name]

    for path in NOTEBOOKS:

        shipped = _shipped_files(path)

        assert CANONICAL_PROMPT_MODULE.name in shipped, (
            f"{path.name} ships no copy of prompt_format.py, so whatever prompt "
            f"it builds is not the repository's")

        for name, text in sorted(shipped.items()):

            if name not in sources:
                # A data file (test_inputs.jsonl, requirements) rather than a
                # module: not this test's claim.
                continue

            assert text == sources[name], (
                f"{path.name} ships a stale copy of {name} — regenerate the "
                f"notebooks with create_notebook.py")


def test_the_canonical_builder_is_the_one_that_does_own_the_template():
    """Sanity check on the scan: prompt_format.py would fail it, hence the skip."""
    assert _marker_literals(CANONICAL_PROMPT_MODULE)


def test_the_scan_would_catch_the_historical_drift():
    """GUARD THE GUARD.

    The scan has to flag the hand-rolled template that actually drifted once, in a
    module and in a notebook cell, while letting a docstring describe the format.
    """
    drifted = (
        'def build(instruction, input_block):\n'
        '    return f"[INST] {instruction}\\n\\n{input_block} [/INST]"\n'
    )

    assert _marker_literals_in_source(drifted)

    # ... and in a notebook cell
    assert _marker_literals_in_source(
        drifted, exempt=(_canonical_source(),)
    )

    # a docstring that merely explains the format is not a violation
    assert _marker_literals_in_source(
        '"""The prompt is <s>[INST] instruction\\n\\ninput [/INST]\\n."""\n'
    ) == []


def test_judge_eval_calls_the_canonical_builder():
    source = (EVALUATION_DIR / "judge_eval.py").read_text(encoding="utf-8")
    assert "prompt_format.build_prompt" in source


def test_prompt_generator_calls_the_canonical_builder():
    source = PROMPT_GENERATOR_MODULE.read_text(encoding="utf-8")
    assert "prompt_format.build_prompt" in source
