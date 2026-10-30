"""The model Space and its shared runtime, over fake torch, transformers and peft.

No weights are loaded and no GPU is needed: the fakes record what the code
asks for (revisions, quantisation, generation kwargs) and return scripted
tokens. app.py itself is imported only where gradio is installed.
"""

import contextlib
import importlib.util
import sys
from types import ModuleType, SimpleNamespace

import pytest

from app.api import scenario_contract as contract
from app.api.config import REPO_ROOT


SPACE_DIR = REPO_ROOT / "app" / "model_space"
BASE_SHA = "1" * 40
ADAPTER_SHA = "2" * 40
ADAPTER_REPO = "owner/scenario-adapter"
EOS = 2


class FakeRow:
    def __init__(self, values):
        self.values = list(values)

    def __getitem__(self, index):
        return FakeRow(self.values[index])

    def tolist(self):
        return list(self.values)


class FakeTensor:
    def __init__(self, rows):
        self.rows = [list(row) for row in rows]

    def __getitem__(self, index):
        return FakeRow(self.rows[index])


class FakeTokenizer:
    bos_token = "<s>"
    eos_token = "</s>"
    eos_token_id = EOS

    def __init__(self):
        self.pad_token = None
        self.pad_token_id = None

    def __setattr__(self, name, value):
        super().__setattr__(name, value)
        if name == "pad_token" and value == self.eos_token:
            super().__setattr__("pad_token_id", EOS)

    def __call__(self, text, add_special_tokens=True):
        assert add_special_tokens is False
        return {"input_ids": [100 + i for i, _ in enumerate(text.split())]}

    def decode(self, ids, skip_special_tokens=False):
        assert skip_special_tokens is True
        return "  [NATURAL LANGUAGE]\nStory " + " ".join("w" for i in ids if i != EOS) + "  "


class Fakes:
    """sys.modules entries for torch, transformers and peft, plus a call log."""

    def __init__(self, new_ids, bf16=True, context=32768):
        self.calls = {}
        self.new_ids = new_ids
        fakes = self

        class Model:
            device = "cuda:0"

            def __init__(self):
                self.config = SimpleNamespace(max_position_embeddings=context, use_cache=False)
                self.evaluated = False

            def eval(self):
                self.evaluated = True
                return self

            def generate(self, input_ids, attention_mask, **kwargs):
                fakes.calls["generate"] = kwargs
                return FakeTensor([input_ids.rows[0] + fakes.new_ids])

        class AutoModelForCausalLM:
            @staticmethod
            def from_pretrained(model_id, **kwargs):
                fakes.calls["base"] = (model_id, kwargs)
                return Model()

        class AutoTokenizer:
            @staticmethod
            def from_pretrained(model_id, **kwargs):
                fakes.calls["tokenizer"] = (model_id, kwargs)
                fakes.tokenizer = FakeTokenizer()
                return fakes.tokenizer

        class BitsAndBytesConfig:
            def __init__(self, **kwargs):
                fakes.calls["bnb"] = kwargs

        class PeftModel:
            @staticmethod
            def from_pretrained(model, repo, **kwargs):
                fakes.calls["adapter"] = (repo, kwargs)
                fakes.model = model
                return model

        self.torch = ModuleType("torch")
        self.torch.bfloat16, self.torch.float16 = "bf16", "fp16"
        self.torch.cuda = SimpleNamespace(is_available=lambda: True, is_bf16_supported=lambda: bf16)
        self.torch.tensor = lambda rows, device=None: FakeTensor(rows)
        self.torch.ones_like = lambda t: FakeTensor([[1] * len(row) for row in t.rows])
        self.torch.no_grad = contextlib.nullcontext
        self.transformers = ModuleType("transformers")
        self.transformers.AutoModelForCausalLM = AutoModelForCausalLM
        self.transformers.AutoTokenizer = AutoTokenizer
        self.transformers.BitsAndBytesConfig = BitsAndBytesConfig
        self.peft = ModuleType("peft")
        self.peft.PeftModel = PeftModel

    def install(self, monkeypatch):
        for name in ("torch", "transformers", "peft"):
            monkeypatch.setitem(sys.modules, name, getattr(self, name))
        monkeypatch.setitem(sys.modules, "scenario_contract", contract)


def load_module(name, monkeypatch):
    spec = importlib.util.spec_from_file_location(name, SPACE_DIR / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)

    return module


@pytest.fixture
def runtime_with(monkeypatch):
    def make(new_ids, **options):
        fakes = Fakes(new_ids, **options)
        fakes.install(monkeypatch)
        runtime = load_module("model_runtime", monkeypatch)

        return fakes, runtime

    return make


def load_pinned(runtime):
    return runtime.load(
        model_revision=BASE_SHA, adapter_repo=ADAPTER_REPO, adapter_revision=ADAPTER_SHA,
        loading_recipe=contract.NF4_UNMERGED
    )


PROMPT = "<s>one two three four"


# -- model_runtime -------------------------------------------------------------

def test_load_pins_every_download_and_uses_the_evaluated_recipe(runtime_with):
    fakes, runtime = runtime_with([5, 6, EOS])

    loaded = load_pinned(runtime)

    model_id, base_kwargs = fakes.calls["base"]
    assert model_id == contract.BASE_MODEL_ID
    assert base_kwargs["revision"] == BASE_SHA
    assert base_kwargs["device_map"] == "auto"
    assert fakes.calls["tokenizer"] == (contract.BASE_MODEL_ID, {"revision": BASE_SHA, "token": None})
    assert fakes.calls["adapter"] == (ADAPTER_REPO, {"revision": ADAPTER_SHA, "token": None})
    assert fakes.calls["bnb"] == {
        "load_in_4bit": True, "bnb_4bit_quant_type": "nf4", "bnb_4bit_use_double_quant": True,
        "bnb_4bit_compute_dtype": "bf16"
    }
    assert fakes.tokenizer.pad_token == "</s>"
    assert fakes.model.evaluated and fakes.model.config.use_cache is True
    assert loaded.compute_dtype == "bfloat16"


def test_compute_dtype_falls_back_to_fp16(runtime_with):
    fakes, runtime = runtime_with([EOS], bf16=False)

    assert load_pinned(runtime).compute_dtype == "float16"
    assert fakes.calls["bnb"]["bnb_4bit_compute_dtype"] == "fp16"


def test_load_refuses_unpinned_revisions_before_downloading(runtime_with):
    fakes, runtime = runtime_with([EOS])

    with pytest.raises(contract.ScenarioContractError):
        runtime.load(model_revision="main", adapter_repo=ADAPTER_REPO, adapter_revision=ADAPTER_SHA,
                     loading_recipe=contract.NF4_UNMERGED)
    assert fakes.calls == {}


def test_generate_returns_a_valid_contract_response(runtime_with):
    fakes, runtime = runtime_with([5, 6, 7, EOS])
    loaded = load_pinned(runtime)

    ids = runtime.encode_prompt(loaded, PROMPT, 600)
    response = runtime.generate(loaded, ids, 600)

    assert contract.validate_result(response, contract.make_provenance(
        model_revision=BASE_SHA, adapter_repo=ADAPTER_REPO, adapter_revision=ADAPTER_SHA, max_new_tokens=600))
    assert response["text"] == "[NATURAL LANGUAGE]\nStory w w w"
    assert (response["new_tokens"], response["hit_eos"], response["finish_reason"]) == (4, True, "eos")
    assert response["prompt_tokens"] == 4
    assert fakes.calls["generate"] == contract.generate_kwargs(contract.generation_settings(600), EOS, EOS)


def test_generate_reports_the_token_cap(runtime_with):
    fakes, runtime = runtime_with([5, 6, 7])
    loaded = load_pinned(runtime)

    response = runtime.generate(loaded, runtime.encode_prompt(loaded, PROMPT, 3), 3)

    assert (response["hit_eos"], response["finish_reason"]) == (False, "length")
    assert contract.reached_token_cap(response["new_tokens"], response["max_new_tokens"], response["hit_eos"])


@pytest.mark.parametrize("prompt, cap, message", [
    ("one two", 100, "BOS"),
    (PROMPT, 0, "between 1 and 1200"),
    (PROMPT, 1201, "between 1 and 1200"),
    ("", 100, "empty"),
    (PROMPT, 1200, "context")
])
def test_encode_prompt_validates_before_the_gpu(runtime_with, prompt, cap, message):
    fakes, runtime = runtime_with([EOS], context=1203)
    loaded = load_pinned(runtime)

    with pytest.raises(contract.ScenarioContractError, match=message):
        runtime.encode_prompt(loaded, prompt, cap)


def _sample_records():
    import json

    path = REPO_ROOT / "scenario_generation" / "evaluation" / "inputs" / "attack_paths.json"

    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("prompt_format", sorted(contract.PROMPT_VERSIONS))
def test_both_prompt_formats_pass_the_runtime_validation(runtime_with, prompt_format):
    fakes, runtime = runtime_with([EOS])
    loaded = load_pinned(runtime)
    records = _sample_records()

    assert len(records) == 19
    for record in records:
        prompt = contract.build_prompt(record, prompt_format)

        # BOS, length and context checks, as the Space runs them before the GPU
        ids = runtime.encode_prompt(loaded, prompt, contract.MAX_NEW_TOKENS)
        assert prompt.startswith(loaded.tokenizer.bos_token)
        assert len(prompt) <= contract.MAX_PROMPT_CHARS
        assert ids


def test_metadata_lists_every_prompt_version(runtime_with):
    fakes, runtime = runtime_with([EOS])

    metadata = runtime.metadata(load_pinned(runtime))

    assert metadata["prompt_versions"] == contract.PROMPT_VERSIONS


def test_metadata_reports_provenance_without_generating(runtime_with):
    fakes, runtime = runtime_with([EOS])

    metadata = runtime.metadata(load_pinned(runtime))

    assert {key: metadata[key] for key in contract.PROVENANCE_FIELDS} == contract.make_provenance(
        model_revision=BASE_SHA, adapter_repo=ADAPTER_REPO, adapter_revision=ADAPTER_SHA)
    assert metadata["max_new_tokens_limit"] == 1200
    assert "generate" not in fakes.calls


# -- app.py --------------------------------------------------------------------

@pytest.fixture
def space(runtime_with, monkeypatch):
    gr = pytest.importorskip("gradio")
    fakes, _ = runtime_with([5, 6, EOS])
    gpu = {"durations": [], "calls": 0}

    def GPU(duration):
        def decorate(fn):
            def wrapper(*args):
                gpu["calls"] += 1
                gpu["durations"].append(duration(*args))
                return fn(*args)
            return wrapper
        return decorate

    spaces = ModuleType("spaces")
    spaces.GPU = GPU
    monkeypatch.setitem(sys.modules, "spaces", spaces)
    for key, value in {"BASE_REVISION": BASE_SHA, "ADAPTER_REPO": ADAPTER_REPO,
                       "ADAPTER_REVISION": ADAPTER_SHA, "LOADING_RECIPE": contract.NF4_UNMERGED}.items():
        monkeypatch.setenv(key, value)

    return gr, load_module("app", monkeypatch), gpu


def test_space_exposes_generate_and_metadata(space):
    gr, app, _ = space

    api_names = {dep.get("api_name") for dep in app.demo.config["dependencies"]}

    assert {"generate", "metadata"} <= api_names


def test_space_generate_end_to_end(space):
    gr, app, gpu = space

    response = app.generate(PROMPT, 1200)

    assert contract.validate_result(response, contract.make_provenance(
        model_revision=BASE_SHA, adapter_repo=ADAPTER_REPO, adapter_revision=ADAPTER_SHA))
    assert gpu["calls"] == 1
    assert gpu["durations"] == [140]


@pytest.mark.parametrize("prompt_format", sorted(contract.PROMPT_VERSIONS))
def test_space_accepts_both_prompt_formats(space, prompt_format):
    gr, app, gpu = space

    response = app.generate(contract.build_prompt(_sample_records()[0], prompt_format), 1200)

    assert contract.validate_result(response, contract.make_provenance(
        model_revision=BASE_SHA, adapter_repo=ADAPTER_REPO, adapter_revision=ADAPTER_SHA))
    assert gpu["calls"] == 1


def test_space_rejects_bad_requests_without_using_the_gpu(space):
    gr, app, gpu = space

    for prompt, cap in (("no bos", 100), (PROMPT, 0), (PROMPT, 5000)):
        with pytest.raises(gr.Error):
            app.generate(prompt, cap)
    assert gpu["calls"] == 0


def test_space_requires_its_variables(runtime_with, monkeypatch):
    pytest.importorskip("gradio")
    runtime_with([EOS])
    monkeypatch.setitem(sys.modules, "spaces", ModuleType("spaces"))
    monkeypatch.delenv("BASE_REVISION", raising=False)

    with pytest.raises(RuntimeError, match="BASE_REVISION"):
        load_module("app", monkeypatch)
