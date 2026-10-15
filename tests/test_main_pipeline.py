"""Tests for main.py — the model builder and the file it writes."""

import json

import main


# -----------------------------

def test_build_infra_model_loads_every_resource(real_resource_dicts):
    infra = main.build_infra_model(main.INFRA_PATH)

    assert len(list(infra.all_resources())) == len(real_resource_dicts)


def test_build_infra_model_returns_connected_resources():
    infra = main.build_infra_model(main.INFRA_PATH)

    edges = [
        connection
        for resource in infra.all_resources()
        for connection in resource.connections
    ]

    assert edges


def test_build_infra_model_keeps_properties_the_saved_file_drops():
    """Why later stages must call this instead of reading data/infra_output.json."""

    infra = main.build_infra_model(main.INFRA_PATH)
    instance = infra.get_resource("PublicEC2Instance")

    assert instance.raw_properties
    assert instance.semantic_properties
    assert "raw_properties" not in instance.to_dict()


def test_build_infra_model_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    main.build_infra_model(main.INFRA_PATH)

    assert list(tmp_path.iterdir()) == []


def test_build_infra_from_resources_wires_compute_identity_and_storage(sample_infra):
    """The hand-built fixture chain: EC2 -> SG, EC2 -> role, role -> bucket."""

    def targets_of(resource_id):
        resource = sample_infra.get_resource(resource_id)
        return [c["target"] for c in resource.connections]

    assert "SampleSecurityGroup" in targets_of("SampleEC2Instance")
    assert "SampleRole" in targets_of("SampleEC2Instance")
    assert "SampleBucket" in targets_of("SampleRole")


# -----------------------------

def test_output_lands_in_data_and_not_in_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    main.main()

    assert main.INFRA_OUTPUT_PATH.exists()
    assert main.INFRA_OUTPUT_PATH.parent.name == "data"
    assert not (tmp_path / "infra_output.json").exists()


def test_running_twice_overwrites_instead_of_appending(
    tmp_path,
    monkeypatch,
    real_resource_dicts
):
    monkeypatch.chdir(tmp_path)

    main.main()
    main.main()

    with open(main.INFRA_OUTPUT_PATH, "r", encoding="utf-8") as f:
        saved = json.load(f)

    # A flat list of one entry per resource — 7 today. Not a list of lists,
    # and not 14 because the second run was appended to the first.
    assert len(saved) == len(real_resource_dicts)
    assert all(isinstance(entry, dict) for entry in saved)
    assert all("id" in entry for entry in saved)


def test_saved_entries_match_the_model(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    main.main()

    with open(main.INFRA_OUTPUT_PATH, "r", encoding="utf-8") as f:
        saved = json.load(f)

    infra = main.build_infra_model(main.INFRA_PATH)

    saved_ids = sorted(entry["id"] for entry in saved)
    model_ids = sorted(r.id for r in infra.all_resources())

    assert saved_ids == model_ids
