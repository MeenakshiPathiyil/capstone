"""Tests that every module imports on Python 3.9 without the ML stack installed."""

import ast
import subprocess
import sys

from .conftest import REPO_ROOT, scanned_python_files


HEAVY_MODULES = ("torch", "transformers", "peft", "trl", "datasets",
                 "bitsandbytes", "accelerate", "google.genai", "dotenv")


def _run_child(code):
    """Run a snippet in a fresh interpreter, from scenario_generation/."""
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(REPO_ROOT), capture_output=True, text=True,
    )


# ── It imports on 3.9 with nothing installed ──────────────────────────────────

def test_importing_judge_eval_pulls_in_no_heavy_dependency():
    result = _run_child(
        "import sys; sys.path.insert(0, 'evaluation'); import judge_eval; "
        f"print(','.join(m for m in {HEAVY_MODULES!r} if m in sys.modules))"
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "", f"eagerly imported: {result.stdout.strip()}"


def test_help_works_without_the_ml_stack():
    result = subprocess.run(
        [sys.executable, "evaluation/judge_eval.py", "--help"],
        cwd=str(REPO_ROOT), capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    for flag in ("--base_model", "--adapter_path", "--test_inputs", "--out", "--gemini_key"):
        assert flag in result.stdout


def test_shared_modules_import_without_the_ml_stack():
    result = _run_child(
        "import sys; sys.path.insert(0, 'fine_tuning'); "
        "import prompt_format, data_split, finetuning, run_inference; print('ok')"
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"


def test_every_non_notebook_module_imports_with_no_ml_stack():
    """THE SCOPE, DERIVED RATHER THAN LISTED.

    Every file scanned_python_files() finds is probed, so a new module is covered
    the moment it exists instead of when someone remembers to add it here.
    """
    probed = []
    offenders = []

    for path in scanned_python_files():

        probed.append(path.name)

        if path.name in ("fine_tune.py",):
            # A launcher whose import *is* the run; covered by --help above.
            continue

        result = _run_child(
            "import sys; sys.path.insert(0, 'evaluation'); "
            "sys.path.insert(0, 'fine_tuning'); "
            f"import importlib.util as u; "
            f"spec = u.spec_from_file_location('probe_{path.stem}', r'{path}'); "
            "mod = u.module_from_spec(spec); spec.loader.exec_module(mod); "
            f"print(','.join(m for m in {HEAVY_MODULES!r} if m in sys.modules))"
        )

        if result.returncode != 0:
            if path.name == "visualize_dataset.py" and "matplotlib" in result.stderr:
                continue
            offenders.append(f"{path.name}: {result.stderr.strip().splitlines()[-1]}")
            continue

        if result.stdout.strip():
            offenders.append(f"{path.name}: eagerly imported {result.stdout.strip()}")

    # An empty file list would make the assertion below pass for free.
    assert "evaluate.py" in probed
    assert "run_inference.py" in probed
    assert "prompt_generator.py" in probed
    assert len(probed) > 8, probed

    assert not offenders, offenders


# ── No runtime PEP-604 unions without the future import (repo-wide) ───────────

def _annotations(tree):
    """Every annotation expression in the module."""
    for node in ast.walk(tree):
        if isinstance(node, ast.arg) and node.annotation is not None:
            yield node, node.annotation
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.returns is not None:
            yield node, node.returns
        elif isinstance(node, ast.AnnAssign) and node.annotation is not None:
            yield node, node.annotation


def _has_future_annotations(tree):
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            if any(alias.name == "annotations" for alias in node.names):
                return True
    return False


def test_no_pep604_union_without_future_import():
    offenders = []
    # Virtualenvs are gitignored and hold third-party code, not this repo's.
    skipped = {".ipynb_checkpoints", "venv", ".venv", "env"}
    files = [p for p in sorted(REPO_ROOT.rglob("*.py"))
             if not skipped.intersection(p.parts)]
    assert files, "found no python files to scan"

    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if _has_future_annotations(tree):
            continue
        for node, annotation in _annotations(tree):
            for sub in ast.walk(annotation):
                if isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.BitOr):
                    offenders.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")

    assert not offenders, (
        "PEP-604 union annotation ('X | Y') without 'from __future__ import "
        "annotations' — these raise TypeError on Python 3.9: " + ", ".join(offenders))
