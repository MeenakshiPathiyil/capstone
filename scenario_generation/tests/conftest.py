"""conftest.py"""

import json
from pathlib import Path

import pytest


# ── Paths (scenario_generation/ is the documented working directory) ───────────

REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET = REPO_ROOT / "dataset" / "training_data.jsonl"
EVALUATION_DIR = REPO_ROOT / "evaluation"
FINE_TUNING_DIR = REPO_ROOT / "fine_tuning"
DATASET_PIPELINE_DIR = REPO_ROOT / "dataset_pipeline"
CANONICAL_PROMPT_MODULE = FINE_TUNING_DIR / "prompt_format.py"

# The inference entry point that consumes the infrastructure repo's export. It
PROMPT_GENERATOR_MODULE = REPO_ROOT / "prompt_generator.py"


# ── What a repo-wide scan covers ──────────────────────────────────────────────

def root_modules():
    """Every .py script at the repository root, sorted. Not tests, not packages."""
    return sorted(
        path for path in REPO_ROOT.glob("*.py")
        if path.is_file()
    )


def notebooks():
    """Every .ipynb in the repository, sorted, checkpoints excluded."""
    return sorted(
        path for path in REPO_ROOT.rglob("*.ipynb")
        if ".ipynb_checkpoints" not in path.parts
    )


def scanned_python_files():
    """Every .py file a prompt-template scan has to look at: the two package"""
    files = []
    for directory in (EVALUATION_DIR, FINE_TUNING_DIR):
        files.extend(sorted(directory.rglob("*.py")))
    files.extend(root_modules())
    return [
        path for path in files
        if path.resolve() != CANONICAL_PROMPT_MODULE.resolve()
    ]


ROOT_MODULES = root_modules()
NOTEBOOKS = notebooks()

# The dataset is gitignored, so a fresh clone may not have it. Tests that need
# real records skip (rather than fail) in that case.
DATASET_MISSING_REASON = f"dataset not present: {DATASET} (run the dataset pipeline)"

# A real attack_paths.json, produced by the infrastructure repo's
ATTACK_PATHS_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "attack_paths.json"


# ── Record fixtures ───────────────────────────────────────────────────────────

@pytest.fixture
def sample_record():
    """A record shaped exactly like one line of dataset/training_data.jsonl."""
    return {
        "instruction": (
            "You are a senior cybersecurity red team expert specializing in cloud "
            "infrastructure attacks.\n\nCRITICAL FORMATTING RULES:\n"
            "1. Your response MUST start immediately with the line: [NATURAL LANGUAGE]\n"
            "2. Do NOT use markdown.\n"
        ),
        "input": (
            "SOURCE: Operation Testbed (C0099)\n"
            "INDUSTRY: Financial Services\n"
            "ATTACK LEVEL: HIGH\n"
            "TECHNIQUES: T1190, T1078\n"
            "SURFACES: Public web application, Cloud metadata service"
        ),
        "output": (
            "[NATURAL LANGUAGE]\nThe operator exploited the public web app (T1190).\n\n"
            "[MATHEMATICAL EXPRESSION]\nG = (N, S, V, P, FS)\n\n"
            "[ATTACK GRAPH]\nStage 1 (Initial Access): Web App [T1190] -> Metadata Service"
        ),
        "_meta": {"source_id": "C0099", "industry": "Financial Services"},
    }


class FakeTokenizer:
    """Stand-in for a HF tokenizer, reproducing Mistral-7B-Instruct-v0.3's chat"""

    bos_token = "<s>"
    eos_token = "</s>"

    def apply_chat_template(self, messages, tokenize=False, add_generation_prompt=False):
        text = self.bos_token
        for message in messages:
            if message["role"] == "user":
                text += "[INST] " + message["content"] + "[/INST]"
            else:
                text += " " + message["content"].strip() + self.eos_token
        return text


@pytest.fixture
def fake_tokenizer():
    """A tokenizer-shaped object whose apply_chat_template matches Mistral's."""
    return FakeTokenizer()


# ── Attack-path fixtures (the cross-repository seam) ──────────────────────────

@pytest.fixture
def attack_path_records():
    """Every record of the committed real attack_paths.json, worst first."""
    with ATTACK_PATHS_FIXTURE.open("r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def attack_path(attack_path_records):
    """The top-ranked exported attack path — one record, exactly six keys."""
    return attack_path_records[0]
