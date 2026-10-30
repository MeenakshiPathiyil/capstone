"""GET /api/meta and /api/health, and the remediation join."""

from app.api import remediations
from app.api.analysis import rule_info
from attack_path.exporter import DEFAULT_INDUSTRY
from attack_path.renderer import SEVERITY_STYLES


def test_meta_carries_styles_enums_samples_and_limits(client):

    meta = client.get("/api/meta").json()

    assert meta["severity_styles"] == SEVERITY_STYLES
    assert meta["attack_levels"] == ["CRITICAL", "HIGH", "MEDIUM"]
    assert meta["industries"][0] == DEFAULT_INDUSTRY == meta["default_industry"]
    assert {sample["id"]: sample["kind"] for sample in meta["samples"]} == {
        "cloudformation5": "single",
        "nested": "nested"
    }
    assert meta["limits"] == {
        "max_upload_bytes": 2 * 1024 * 1024,
        "max_resources": 500,
        "accepted_extensions": [".yaml", ".yml", ".json", ".template"]
    }
    assert {objective["id"]: objective["base_weight"] for objective in meta["objectives"]} == {
        "data_theft": 4.0,
        "ransomware": 5.0,
        "resource_hijacking": 2.0,
        "identity_takeover": 3.0,
        "denial_of_service": 1.0
    }


def test_health_is_ok_without_pdf_or_model(client):

    health = client.get("/api/health").json()

    assert health["ok"] is True
    assert isinstance(health["weasyprint"], bool)
    assert health["est_generations_left"] is None

    if not health["weasyprint"]:
        assert health["pdf_unavailable_reason"]


def test_health_never_carries_the_token(tmp_path, monkeypatch):

    from fastapi.testclient import TestClient

    from app.api.main import create_app
    from app.api.tests.conftest import make_settings

    monkeypatch.setenv("HF_TOKEN", "hf_not_a_real_token_value")
    monkeypatch.setenv("SPACE_ID", "someone/some-space")

    with TestClient(create_app(make_settings(tmp_path))) as client:
        response = client.get("/api/health")

    assert response.json()["space_configured"] is True
    assert "hf_not_a_real_token_value" not in response.text


# -- Remediations -----------------------------------------------------------------

FINDING = {
    "rule_id": "aws_config:INCOMING_SSH_DISABLED:AWS::EC2::SecurityGroup",
    "source_id": "INCOMING_SSH_DISABLED",
    "state": "sg_unrestricted_ssh"
}


def test_an_absent_catalog_gives_null_remediation(tmp_path):

    catalog = remediations.load_remediations(tmp_path / "missing.yaml")

    assert catalog == {"rules": {}, "methods": {}}

    info = rule_info(FINDING, "AWS::EC2::SecurityGroup", {}, {}, catalog)

    assert info["remediation"] is None


def test_an_unreadable_or_partial_catalog_is_tolerated(tmp_path):

    broken = tmp_path / "broken.yaml"
    broken.write_text("rules: [\n", encoding="utf-8")

    assert remediations.load_remediations(broken) == {"rules": {}, "methods": {}}

    partial = tmp_path / "partial.yaml"
    partial.write_text(
        "rules:\n"
        "  INCOMING_SSH_DISABLED:\n"
        "    fix: Close port 22.\n"
        "  REQUIRED_TAGS:\n"
        "    url: https://example.com/no-fix\n",
        encoding="utf-8"
    )

    catalog = remediations.load_remediations(partial)

    # no url, so not usable; no fix, so not usable
    assert remediations.remediation_for(
        catalog, "x", "INCOMING_SSH_DISABLED", "AWS::EC2::SecurityGroup", False
    ) is None
    assert remediations.remediation_for(
        catalog, "x", "REQUIRED_TAGS", "AWS::S3::Bucket", False
    ) is None


def test_rules_join_by_source_id_and_methods_by_id(tmp_path):

    path = tmp_path / "remediations.yaml"
    path.write_text(
        "rules:\n"
        "  INCOMING_SSH_DISABLED:\n"
        "    fix: >-\n"
        "      Close port 22\n"
        "      to the world.\n"
        "    snippet: |\n"
        "      CidrIp: 10.0.0.0/16\n"
        "    url: https://docs.aws.amazon.com/config/\n"
        "    by_resource_type:\n"
        "      AWS::EC2::SecurityGroupIngress:\n"
        "        snippet: |\n"
        "          CidrIp: 10.1.0.0/16\n"
        "methods:\n"
        "  PRIVESC_ATTACH_ROLE_POLICY:\n"
        "    fix: Remove iam:AttachRolePolicy.\n"
        "    url: https://github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation\n",
        encoding="utf-8"
    )

    catalog = remediations.load_remediations(path)

    group = remediations.remediation_for(
        catalog, FINDING["rule_id"], "INCOMING_SSH_DISABLED",
        "AWS::EC2::SecurityGroup", False
    )

    assert group == {
        "fix": "Close port 22 to the world.",
        "snippet": "CidrIp: 10.0.0.0/16\n",
        "url": "https://docs.aws.amazon.com/config/"
    }

    ingress = remediations.remediation_for(
        catalog, "x", "INCOMING_SSH_DISABLED", "AWS::EC2::SecurityGroupIngress", False
    )

    assert ingress["snippet"] == "CidrIp: 10.1.0.0/16\n"

    method = remediations.remediation_for(
        catalog, "PRIVESC_ATTACH_ROLE_POLICY", "PRIVESC_ATTACH_ROLE_POLICY",
        "AWS::IAM::Role", True
    )

    assert method["snippet"] is None
    assert method["url"].startswith("https://")


def test_the_shipped_catalog_reaches_the_analysis(sample_analysis):
    """Whatever data/remediations.yaml holds today is joined, never required."""

    catalog = remediations.load_remediations()

    for finding in sample_analysis["findings"]:

        remediation = finding["rule"]["remediation"]

        if remediation is not None:
            assert remediation["fix"] and remediation["url"].startswith("http")

        is_rule = not finding["rule_id"].startswith("PRIVESC_")
        key = finding["source_id"] if is_rule else finding["rule_id"]
        entry = catalog["rules" if is_rule else "methods"].get(key) or {}

        if entry.get("fix") and entry.get("url"):
            assert remediation is not None, finding["id"]
