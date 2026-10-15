"""The ATT&CK IaaS matrix, and the ordering the exporter takes from it.

Source: https://attack.mitre.org/matrices/enterprise/cloud/iaas/

The point of this module is that a hand-written phase table drifted and could not
be checked. So these tests are mostly about the two things the data file now makes
checkable: that a technique's position comes from its tactic, and that a technique
outside the cloud matrix is *detectably* outside it.
"""

import pytest
import yaml

from engine.attack_catalog import (
    TECHNIQUES_PATH,
    is_known,
    load_catalog,
    parent_id,
    phase_rank,
    resolve,
    tactic_of,
    tactics,
    technique_name
)


def test_the_matrix_loads():
    catalog = load_catalog()

    assert catalog["tactics"]
    assert catalog["techniques"]


def test_the_tactic_order_is_the_kill_chain():
    order = tactics()

    assert order[0] == "initial access"
    assert order[-1] == "impact"

    assert order.index("privilege escalation") < order.index("collection")
    assert order.index("collection") < order.index("exfiltration")


def test_every_technique_is_filed_under_a_listed_tactic():
    catalog = load_catalog()

    for technique in catalog["techniques"].values():
        assert technique["tactic"] in catalog["tactics"]


def test_technique_ids_are_unique_in_the_file():
    with open(TECHNIQUES_PATH, "r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)

    ids = [entry["id"] for entry in raw["techniques"]]

    assert len(ids) == len(set(ids))


def test_a_tactic_that_is_not_in_the_list_is_a_load_error(tmp_path):
    """A typo in a tactic name is a typo, not a new phase of the kill chain."""

    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "tactics: [initial access]\n"
        "techniques:\n"
        "  - id: T9999\n"
        "    name: Invented\n"
        "    tactic: teatime\n",
        encoding="utf-8"
    )

    with pytest.raises(ValueError):
        load_catalog(bad)


# -----------------------------
# Ordering.

ORDERED = [
    "T1190",       # initial access
    "T1648",       # execution
    "T1098.001",   # privilege escalation
    "T1552.005",   # credential access
    "T1580",       # discovery
    "T1021.007",   # lateral movement
    "T1530",       # collection
    "T1537",       # exfiltration
    "T1486"        # impact
]


def test_ranks_ascend_along_the_kill_chain():
    ranks = [phase_rank(technique_id) for technique_id in ORDERED]

    assert ranks == sorted(ranks)
    assert len(set(ranks)) == len(ranks)


def test_a_sub_technique_falls_back_to_its_parents_tactic():
    """T1078.004 has its own entry; an unlisted sub-technique uses the parent."""

    assert parent_id("T1078.004") == "T1078"
    assert parent_id("T1078") == "T1078"

    # T1530 has no sub-technique entries, so an invented one resolves via parent
    assert tactic_of("T1530.999") == tactic_of("T1530")
    assert phase_rank("T1530.999") == phase_rank("T1530")


def test_an_unknown_technique_sorts_last_rather_than_raising():
    """The ruleset test rejects off-matrix ids; the exporter must not crash on one."""

    assert phase_rank("T9999") == len(tactics())
    assert tactic_of("T9999") is None
    assert technique_name("T9999") == ""


# -----------------------------
# The claim that motivated the file.

@pytest.mark.parametrize("technique_id", ["T1133", "T1567.002"])
def test_the_non_iaas_techniques_the_ruleset_used_to_cite_are_rejected(technique_id):
    """THE REGRESSION THIS FILE EXISTS FOR.

    T1133 (External Remote Services) and T1567.002 (Exfiltration to Cloud
    Storage) were both cited by rules. Neither is in the IaaS matrix: cloud
    initial access is T1190/T1199/T1078 and cloud exfiltration is T1048/T1537.
    """

    assert not is_known(technique_id)


@pytest.mark.parametrize(
    "technique_id",
    ["T1190", "T1078", "T1078.004", "T1098.001", "T1530", "T1537", "T1486", "T1496"]
)
def test_the_techniques_we_do_cite_are_in_the_matrix(technique_id):
    assert is_known(technique_id)


def test_names_come_from_the_matrix():
    assert technique_name("T1190") == "Exploit Public-Facing Application"
    assert technique_name("T1486") == "Data Encrypted for Impact"


def test_resolve_pairs_ids_with_their_official_names():
    resolved = resolve(["T1098.001", "T1496"])

    assert resolved == [
        {
            "id": "T1098.001",
            "name": "Account Manipulation: Additional Cloud Credentials"
        },
        {"id": "T1496", "name": "Resource Hijacking"}
    ]


def test_resolve_of_nothing_is_an_empty_list():
    assert resolve(None) == []
    assert resolve([]) == []
