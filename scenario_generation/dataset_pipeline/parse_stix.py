"""
parse_stix.py
─────────────────────────────────────────────────────────────────────────────
Step 1: Parse enterprise-attack STIX bundle → structured training inputs
Usage:
    python parse_stix.py --stix enterprise-attack-18.1.json --out dataset/inputs/
─────────────────────────────────────────────────────────────────────────────
Output: one JSON file per campaign/group entry, plus a combined JSONL file
        ready for Step 2 (output generation via Claude API)
"""

import json
import argparse
import os
import re
from collections import defaultdict

# ─── ISIC industry mapping (simplified for cloud/enterprise context) ──────────
ISIC_MAP = {
    "financial": "Financial and insurance activities (ISIC K)",
    "energy": "Electricity, gas, steam and AC supply (ISIC D)",
    "healthcare": "Human health and social work (ISIC Q)",
    "government": "Public administration and defence (ISIC O)",
    "telecom": "Information and communication (ISIC J)",
    "manufacturing": "Manufacturing (ISIC C)",
    "cloud": "Information technology service activities (ISIC 6311)",
    "retail": "Wholesale and retail trade (ISIC G)",
    "education": "Education (ISIC P)",
    "default": "Information technology service activities (ISIC J62)",
}

# Keywords to guess industry from campaign description
INDUSTRY_KEYWORDS = {
    "financial": ["bank", "financ", "swift", "payment", "atm", "stock", "trading"],
    "energy": ["energy", "power grid", "electric", "oil", "gas", "utility", "scada", "ics"],
    "healthcare": ["health", "hospital", "medical", "pharma", "patient"],
    "government": ["government", "nation-state", "espionage", "ministry", "defense", "military"],
    "telecom": ["telecom", "isp", "carrier", "mobile network"],
    "manufacturing": ["manufactur", "factory", "industrial", "supply chain"],
    "cloud": ["cloud", "aws", "azure", "gcp", "saas", "kubernetes", "container", "s3"],
    "education": ["universit", "college", "research", "academic"],
}

# Attack level heuristics based on group sophistication keywords
SOPHISTICATION_MAP = {
    "high": ["nation-state", "apt", "advanced", "sophisticated", "espionage",
             "zero-day", "0day", "custom malware", "state-sponsored"],
    "medium": ["cybercriminal", "ransomware", "financially motivated", "intermediate"],
    "low": ["script kiddie", "opportunistic", "novice", "basic"],
}


def guess_industry(text: str) -> str:
    text_lower = text.lower()
    for industry, keywords in INDUSTRY_KEYWORDS.items():
        if any(kw in text_lower for kw in keywords):
            return ISIC_MAP[industry]
    return ISIC_MAP["default"]


def guess_attack_level(text: str) -> str:
    text_lower = text.lower()
    for level, keywords in SOPHISTICATION_MAP.items():
        if any(kw in text_lower for kw in keywords):
            return level
    return "medium"  # default


def clean_text(text: str) -> str:
    """Remove STIX citation markers like (Citation: ...) and extra whitespace."""
    text = re.sub(r'\(Citation:[^)]+\)', '', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def load_stix_bundle(filepath: str) -> dict:
    print(f"[+] Loading STIX bundle from: {filepath}")
    with open(filepath, "r", encoding="utf-8") as f:
        bundle = json.load(f)
    print(f"[+] Total objects in bundle: {len(bundle.get('objects', []))}")
    return bundle


def index_bundle(bundle: dict) -> dict:
    """Build lookup dicts by STIX id for fast cross-referencing."""
    index = {}
    for obj in bundle.get("objects", []):
        index[obj["id"]] = obj
    return index


def get_techniques_for_group_or_campaign(stix_id: str, bundle: dict, index: dict) -> list:
    """
    Find all techniques used by a group or campaign via 'uses' relationships.
    Returns list of technique dicts with id, name, tactic, description.
    """
    technique_ids = set()
    for obj in bundle.get("objects", []):
        if (
            obj.get("type") == "relationship"
            and obj.get("relationship_type") == "uses"
            and obj.get("source_ref") == stix_id
            and "attack-pattern" in obj.get("target_ref", "")
        ):
            technique_ids.add(obj["target_ref"])

    techniques = []
    for tid in technique_ids:
        tech = index.get(tid)
        if not tech:
            continue
        # Get tactic from kill chain phases
        tactics = [
            phase["phase_name"].replace("-", " ").title()
            for phase in tech.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]
        # Get ATT&CK ID (e.g. T1059.001)
        attack_id = ""
        for ext in tech.get("external_references", []):
            if ext.get("source_name") == "mitre-attack":
                attack_id = ext.get("external_id", "")
                break
        techniques.append({
            "attack_id": attack_id,
            "name": tech.get("name", ""),
            "tactics": tactics,
            "description": clean_text(tech.get("description", ""))[:300],
        })
    return techniques


def extract_attack_surfaces_and_vectors(techniques: list) -> tuple:
    """
    Heuristically map techniques to attack surfaces and vectors
    based on tactic categories.
    """
    surface_tactic_map = {
        "Initial Access": "Internet-facing services / user endpoints",
        "Execution": "Application runtime environment",
        "Persistence": "System configuration / registry / cron",
        "Privilege Escalation": "OS / IAM permission model",
        "Defense Evasion": "Security tooling / logging infrastructure",
        "Credential Access": "Credential stores / memory / network traffic",
        "Discovery": "Internal network / cloud metadata services",
        "Lateral Movement": "Internal network / trust relationships",
        "Collection": "File system / cloud storage / databases",
        "Command And Control": "Outbound network / DNS / HTTP channels",
        "Exfiltration": "Data egress points / cloud APIs",
        "Impact": "Production systems / backups / data integrity",
    }

    surfaces = set()
    vectors = []

    for tech in techniques[:6]:  # cap at 6 to keep inputs concise
        for tactic in tech.get("tactics", []):
            if tactic in surface_tactic_map:
                surfaces.add(surface_tactic_map[tactic])
        vectors.append(f"{tech['name']} ({tech['attack_id']})")

    return sorted(list(surfaces))[:4], vectors[:5]


def parse_campaigns(bundle: dict, index: dict) -> list:
    """Extract all campaigns from the STIX bundle."""
    campaigns = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "campaign":
            continue
        description = clean_text(obj.get("description", ""))
        if len(description) < 30:
            continue  # skip stub entries

        techniques = get_techniques_for_group_or_campaign(obj["id"], bundle, index)
        if len(techniques) < 2:
            continue  # skip campaigns with too few techniques to be useful

        attack_surfaces, attack_vectors = extract_attack_surfaces_and_vectors(techniques)

        # Get ATT&CK external ID
        attack_id = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                attack_id = ref.get("external_id", "")
                break

        entry = {
            "source_type": "campaign",
            "source_id": attack_id,
            "source_name": obj.get("name", "Unknown Campaign"),
            "industry": guess_industry(description),
            "attack_level": guess_attack_level(description),
            "attack_surfaces": attack_surfaces,
            "attack_vectors": attack_vectors,
            "mitre_techniques": [
                f"{t['attack_id']} - {t['name']}" for t in techniques[:5]
            ],
            "scenario_seed": description[:400],
        }
        campaigns.append(entry)

    print(f"[+] Extracted {len(campaigns)} campaign entries")
    return campaigns


def parse_groups(bundle: dict, index: dict) -> list:
    """Extract threat actor groups as additional training input sources."""
    groups = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "intrusion-set":
            continue
        description = clean_text(obj.get("description", ""))
        if len(description) < 50:
            continue

        techniques = get_techniques_for_group_or_campaign(obj["id"], bundle, index)
        if len(techniques) < 3:
            continue

        attack_surfaces, attack_vectors = extract_attack_surfaces_and_vectors(techniques)

        attack_id = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                attack_id = ref.get("external_id", "")
                break

        entry = {
            "source_type": "group",
            "source_id": attack_id,
            "source_name": obj.get("name", "Unknown Group"),
            "industry": guess_industry(description),
            "attack_level": guess_attack_level(description),
            "attack_surfaces": attack_surfaces,
            "attack_vectors": attack_vectors,
            "mitre_techniques": [
                f"{t['attack_id']} - {t['name']}" for t in techniques[:5]
            ],
            "scenario_seed": description[:400],
        }
        groups.append(entry)

    print(f"[+] Extracted {len(groups)} group entries")
    return groups


def save_outputs(entries: list, out_dir: str):
    os.makedirs(out_dir, exist_ok=True)

    # Save individual JSON files (useful for manual review/editing)
    individual_dir = os.path.join(out_dir, "individual")
    os.makedirs(individual_dir, exist_ok=True)

    for i, entry in enumerate(entries):
        safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', entry['source_name'])
        filename = f"{entry['source_id']}_{safe_name}.json" if entry['source_id'] else f"entry_{i:03d}.json"
        filepath = os.path.join(individual_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(entry, f, indent=2)

    # Save combined JSONL (one entry per line — used directly for Step 2)
    jsonl_path = os.path.join(out_dir, "training_inputs.jsonl")
    with open(jsonl_path, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")

    # Save a summary stats file
    level_counts = defaultdict(int)
    industry_counts = defaultdict(int)
    type_counts = defaultdict(int)
    for e in entries:
        level_counts[e["attack_level"]] += 1
        industry_counts[e["industry"]] += 1
        type_counts[e["source_type"]] += 1

    summary = {
        "total_entries": len(entries),
        "by_attack_level": dict(level_counts),
        "by_source_type": dict(type_counts),
        "top_industries": sorted(industry_counts.items(), key=lambda x: -x[1])[:8],
    }
    summary_path = os.path.join(out_dir, "summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"\n[+] Saved {len(entries)} entries to: {out_dir}")
    print(f"    → individual JSONs : {individual_dir}/")
    print(f"    → combined JSONL   : {jsonl_path}")
    print(f"    → summary stats    : {summary_path}")
    print(f"\n[+] Summary:")
    print(json.dumps(summary, indent=4))


def main():
    parser = argparse.ArgumentParser(
        description="Parse ATT&CK STIX bundle into structured training inputs"
    )
    parser.add_argument(
        "--stix",
        required=True,
        help="Path to enterprise-attack-18.1.json (or any version)"
    )
    parser.add_argument(
        "--out",
        default="dataset/inputs",
        help="Output directory (default: dataset/inputs/)"
    )
    parser.add_argument(
        "--source",
        choices=["campaigns", "groups", "both"],
        default="both",
        help="Which source types to extract (default: both)"
    )
    args = parser.parse_args()

    bundle = load_stix_bundle(args.stix)
    index = index_bundle(bundle)

    entries = []
    if args.source in ("campaigns", "both"):
        entries += parse_campaigns(bundle, index)
    if args.source in ("groups", "both"):
        entries += parse_groups(bundle, index)

    if not entries:
        print("[!] No entries extracted. Check your STIX file path.")
        return

    save_outputs(entries, args.out)
    print(f"\n[✓] Done. Next step: run generate_outputs.py on training_inputs.jsonl")


if __name__ == "__main__":
    main()