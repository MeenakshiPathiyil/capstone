"""Export ranked attack paths in the shape the scenario generator reads."""

from pathlib import Path

from engine.attack_catalog import phase_rank as catalog_phase_rank, resolve
from engine.privesc_detector import load_methods
from engine.rule_engine import RuleEngine
from attack_path.path_finder import find_attack_paths
from attack_path.scoring import (
    ATTACK_LEVEL_HIGH,
    select_high_risk
)
from security_state_graph.state_graph import (
    INFRA_PATH,
    RULES_PATH
)
from security_state_graph.state_graph import build_state_graph
from utils.helpers import write_json


BASE_DIR = Path(__file__).resolve().parent.parent

OUTPUT_PATH = BASE_DIR / "output" / "attack_paths.json"

# The per-hop conditions of every ranked path. Its own file because the export
# above is a fixed seven-key contract with the scenario generator, and because
# every other block of the graph is its own file too. See build_steps.
STEPS_PATH = BASE_DIR / "output" / "attack_path_steps.json"

# THE CROSS-REPOSITORY CONTRACT.
EXPORT_KEYS = [
    "source_id",
    "source_name",
    "industry",
    "attack_level",
    "techniques",
    "surfaces",

    # Added with the objectives layer. The consumer needs it: the same hops
    # written as a data-theft story and as a ransomware story are two different
    # scenarios, and only this field distinguishes them.
    "objective"
]

# The prefix and width of the generated source_id.
SOURCE_ID_PREFIX = "AP"
SOURCE_ID_WIDTH = 3

# How a path is named for a human. The hop chain itself, because that is what a
# reader follows on the diagram.
HOP_ARROW = " -> "

# The industry the account belongs to.
DEFAULT_INDUSTRY = "Information technology service activities (ISIC J62)"

# How the technique list is rendered. "Txxxx - Name", comma separated — exactly
# the shape of the TECHNIQUES line in dataset/training_data.jsonl.
TECHNIQUE_JOINER = ", "
TECHNIQUE_NAME_SEPARATOR = " - "

SURFACE_JOINER = ", "

# The kill chain and each technique's place in it now come from
# data/attack_techniques.yaml via engine/attack_catalog.py — see that module's
# THEORY note on what the hand-written versions of these got wrong.

# Resource type -> the attack surface it represents.
SURFACE_BY_TYPE = {
    "AWS::EC2::SecurityGroup": "Internet-facing services / user endpoints",
    "AWS::ElasticLoadBalancingV2::LoadBalancer":
        "Internet-facing services / user endpoints",
    "AWS::EC2::Instance": "Application runtime environment",
    "AWS::IAM::Role": "OS / IAM permission model",

    # The profile is the vehicle the role travels on, not a surface of its own,
    # so it counts as the role's surface.
    "AWS::IAM::InstanceProfile": "OS / IAM permission model",

    "AWS::S3::BucketPolicy": "OS / IAM permission model",
    "AWS::S3::Bucket": "File system / cloud storage / databases",
    "AWS::RDS::DBInstance": "File system / cloud storage / databases",
    "AWS::SecretsManager::Secret":
        "Credential stores / memory / network traffic",
    "AWS::KMS::Key": "Credential stores / memory / network traffic",

    "AWS::DynamoDB::Table": "File system / cloud storage / databases",
    "AWS::EFS::FileSystem": "File system / cloud storage / databases",
    "AWS::Lambda::Function": "Application runtime environment",
    "AWS::IAM::User": "OS / IAM permission model"
}

# A resource type this table has never met is still a hop an attacker took, so
# it gets a generic surface rather than none.
DEFAULT_SURFACE = "Internal network / cloud metadata services"


def technique_index(rules_path=RULES_PATH):
    """rule_id -> the rule's attack_techniques, as [{"id", "name"}]."""

    index = {}

    for rule in RuleEngine(rules_path).rules:

        if not isinstance(rule, dict):
            continue

        rule_id = rule.get("id")

        if not rule_id:
            continue

        # -----------------------------

        # A rule with no attack_techniques indexes to an empty list rather than
        # being left out of the index.
        techniques = []

        for technique in rule.get("attack_techniques") or []:

            if not isinstance(technique, dict):
                continue

            technique_id = technique.get("id")

            if not technique_id:
                continue

            techniques.append({
                "id": str(technique_id),
                "name": str(technique.get("name") or "")
            })

        index[rule_id] = techniques

    # -----------------------------

    # Privilege escalation findings are keyed by the catalogue's method id rather
    # than a rule id, because they do not come from the rule engine — see
    # security_state_graph.state_graph.privesc_findings. Their techniques are cited by id only,
    # so the names are resolved from the matrix instead of repeated 28 times.
    for method in load_methods():

        method_id = method.get("id")

        if not method_id:
            continue

        index[method_id] = resolve(method.get("techniques") or [])

    return index


def base_technique_id(technique_id):
    """"T1078.004" -> "T1078". An id with no sub-technique is returned unchanged."""

    return str(technique_id).split(".")[0]


def phase_rank(technique_id):
    """The kill-chain position of a technique, as a sortable integer.

    Delegates to the IaaS matrix. Sub-techniques resolve through their parent, so
    T1098.001 ranks where ATT&CK files T1098 unless the matrix gives the
    sub-technique its own tactic.
    """

    return catalog_phase_rank(technique_id)


def path_techniques(path, index):
    """Every technique named by the findings on one path, deduped, kill-chain order."""

    # -----------------------------

    collected = []
    seen = []

    for rule_id in path.get("rule_ids") or []:

        for technique in index.get(rule_id, []):

            if technique["id"] in seen:
                continue

            seen.append(technique["id"])
            collected.append(technique)

    # -----------------------------

    # The objective's own techniques, appended before the sort. Without these a
    # ransomware path would carry no impact-tactic technique at all: the findings
    # along it describe how the attacker arrived, never what they did on arrival.
    for technique in resolve(path.get("objective_techniques") or []):

        if technique["id"] in seen:
            continue

        seen.append(technique["id"])
        collected.append(technique)

    # -----------------------------

    # Stable: within one phase the path order above survives, which is what
    # makes the export reproducible byte for byte.
    collected.sort(key=lambda technique: phase_rank(technique["id"]))

    return collected


def render_techniques(techniques):
    """The techniques as the "T1190 - Exploit Public-Facing Application, ..." string"""

    rendered = []

    for technique in techniques:

        if technique["name"]:
            rendered.append(
                technique["id"]
                + TECHNIQUE_NAME_SEPARATOR
                + technique["name"]
            )

        else:
            rendered.append(technique["id"])

    return TECHNIQUE_JOINER.join(rendered)


def path_surfaces(state_graph, path):
    """The attack surfaces the hops of one path represent, deduped in path order."""

    surfaces = []

    for node_id in path.get("hops") or []:

        node = state_graph.node(node_id)

        # -----------------------------

        if node is None:
            surface = DEFAULT_SURFACE

        else:
            surface = SURFACE_BY_TYPE.get(node["type"], DEFAULT_SURFACE)

        if surface not in surfaces:
            surfaces.append(surface)

    return surfaces


def render_surfaces(surfaces):
    """The surfaces as the comma-separated string the prompt template expects."""

    return SURFACE_JOINER.join(surfaces)


def source_id_for(rank):
    """The exported id of the path ranked `rank`, counting from 1: "AP-001"."""

    return "{}-{}".format(
        SOURCE_ID_PREFIX,
        str(rank).zfill(SOURCE_ID_WIDTH)
    )


def source_name_for(path):
    """The exported name of a path: its hop chain, entry first."""

    return HOP_ARROW.join(path.get("hops") or [])


def export_record(state_graph, path, rank, index, industry=DEFAULT_INDUSTRY):
    """One ranked path as the record the scenario generator reads."""

    return {
        "source_id": source_id_for(rank),
        "source_name": str(source_name_for(path)),
        "industry": str(industry),

        # Already a string from attack_level_for(); str() anyway, because
        # every field of the export is a string.
        "attack_level": str(path.get("attack_level") or ""),

        "techniques": render_techniques(path_techniques(path, index)),
        "surfaces": render_surfaces(path_surfaces(state_graph, path)),
        "objective": str(path.get("objective_name") or path.get("objective") or "")
    }


def build_export(state_graph, paths, index, industry=DEFAULT_INDUSTRY):
    """Every ranked path as an export record, in the order it was ranked."""

    return [
        export_record(state_graph, path, rank, index, industry)
        for rank, path in enumerate(paths, 1)
    ]


def build_steps(paths):
    """Every ranked path's hops, with what each one requires and grants.

    THEORY (why this is a separate artifact):
    The export above is a seven-key contract shared with the scenario generator
    and it cannot grow an eighth key without that repository changing too. But the
    per-hop reasoning is the most useful thing the path layer produces: it is what
    lets a reader check that `A -> B -> C` was derived rather than drawn, and it is
    the material a scenario needs to say *why* each step follows. So it is written
    beside the export instead of inside it.

    `precondition` is what actually held, and it appears verbatim in the previous
    hop's `postcondition`. Reading the list top to bottom is reading the chain.
    """

    return [
        {
            "source_id": source_id_for(rank),
            "entry_id": path.get("entry_id"),
            "target_id": path.get("target_id"),
            "objective": path.get("objective"),

            # Task 7 assigns a score to each path. It was computed and then only
            # its band was written out, so the number itself was unverifiable
            # from the artifacts.
            "risk_score": path.get("score"),
            "attack_level": path.get("attack_level"),
            "steps": path.get("steps") or []
        }
        for rank, path in enumerate(paths, 1)
    ]


def write_steps(paths, output_path=STEPS_PATH):
    """Write the per-hop conditions of every ranked path. Returns the path."""

    return write_json(build_steps(paths), output_path)


def write_export(records, output_path=OUTPUT_PATH):
    """Write the records to `output_path` as a JSON list, and return the path."""

    return write_json(records, output_path)




def export_attack_paths(
    infra_path=INFRA_PATH,
    rules_path=RULES_PATH,
    output_path=OUTPUT_PATH,
    industry=DEFAULT_INDUSTRY,
    min_level=ATTACK_LEVEL_HIGH
):
    """Build the graph, rank its paths, and write output/attack_paths.json.

    Filters to the high-risk paths, the same as runner/graph_runner does. Two ways
    to produce the export that disagree about what goes in it is the same class of
    bug as an artifact stating conditions the search does not enforce.
    """

    # -----------------------------

    state_graph = build_state_graph(infra_path, rules_path)

    paths = select_high_risk(find_attack_paths(state_graph), min_level)

    # -----------------------------

    records = build_export(
        state_graph,
        paths,
        technique_index(rules_path),
        industry
    )

    write_export(records, output_path)

    return records
