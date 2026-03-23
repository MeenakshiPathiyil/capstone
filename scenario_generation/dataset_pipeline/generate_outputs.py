"""
generate_outputs.py
─────────────────────────────────────────────────────────────────────────────
Step 2: For each structured input from parse_stix.py, call Claude API to
        generate the tri-modal output (natural language + math + attack graph)
        then combine into a final training JSONL for fine-tuning.

Usage:
    export ANTHROPIC_API_KEY=sk-ant-...
    python generate_outputs.py \
        --inputs dataset/inputs/training_inputs.jsonl \
        --out    dataset/training_data.jsonl \
        --limit  80

Cost estimate: ~80 entries × ~1500 tokens output ≈ $0.30–0.50 with Claude Haiku
─────────────────────────────────────────────────────────────────────────────
"""

import json
import argparse
import os
import time
import anthropic

# ─── System prompt for Claude — defines the exact output format ───────────────
SYSTEM_PROMPT = """You are a cybersecurity expert generating realistic cyber attack scenarios for security training purposes. 

Given a structured attack description, you must generate a scenario in EXACTLY three sections with these exact headers. Do not add any text before the first header.

[NATURAL LANGUAGE]
Write a 3-5 paragraph realistic attack narrative. Include: threat actor motivation, initial access method, lateral movement, and final objective. Use technical terminology. Reference the specific MITRE techniques provided. Be specific about the attack sequence.

[MATHEMATICAL EXPRESSION]
Express the attack as a formal graph tuple G = (N, S, V, P, FS) where:
- N = set of nodes (systems, users, devices involved)  
- S = set of attack surfaces (exploitable vulnerabilities)
- V = set of attack vectors (methods used)
- P = set of attack paths (sequences of exploitation)
- FS = full scenario description (the complete attack chain)

List each component explicitly with numbered elements. Example format:
N = {n1: web_application, n2: database_server, n3: admin_workstation}
S = {s1: unpatched_CVE, s2: weak_credentials}
V = {v1: SQL_injection, v2: credential_stuffing}
P = {p1: n1→n2 via v1, p2: n2→n3 via v2}
FS = Full attack achieving [objective]

[ATTACK GRAPH]
Describe the attack graph as numbered stages. Each stage must have:
- Stage name and number
- Node targeted
- Technique used (with ATT&CK ID if available)
- Precondition (what must be true before this stage)
- Postcondition (what becomes true after)

Format each stage as:
Stage N — [Name]: [Node] | Technique: [ATT&CK ID - Name] | Pre: [condition] | Post: [condition]

Use between 3 and 6 stages total.

Keep all three sections grounded in the specific attack details provided. Do not invent techniques not present in the input."""


def build_user_prompt(entry: dict) -> str:
    """Build the per-entry user prompt from the structured input."""
    techniques_str = "\n".join(f"  - {t}" for t in entry.get("mitre_techniques", []))
    surfaces_str = "\n".join(f"  - {s}" for s in entry.get("attack_surfaces", []))
    vectors_str = "\n".join(f"  - {v}" for v in entry.get("attack_vectors", []))

    return f"""Generate a cyber attack scenario based on the following structured input:

SOURCE: {entry.get('source_name', 'Unknown')} ({entry.get('source_id', 'N/A')})
INDUSTRY: {entry.get('industry', 'Information Technology')}
ATTACK LEVEL: {entry.get('attack_level', 'medium').upper()}

ATTACK SURFACES:
{surfaces_str if surfaces_str else '  - General enterprise network'}

ATTACK VECTORS:
{vectors_str if vectors_str else '  - Spearphishing, malware deployment'}

MITRE ATT&CK TECHNIQUES:
{techniques_str if techniques_str else '  - General techniques'}

SCENARIO SEED (background context):
{entry.get('scenario_seed', 'Advanced persistent threat targeting enterprise infrastructure.')}

Now generate the full tri-modal scenario output."""


def call_claude(client: anthropic.Anthropic, entry: dict, model: str = "claude-haiku-4-5-20251001") -> str | None:
    """Call Claude API and return the raw text response."""
    try:
        message = client.messages.create(
            model=model,
            max_tokens=1800,
            system=SYSTEM_PROMPT,
            messages=[
                {"role": "user", "content": build_user_prompt(entry)}
            ]
        )
        return message.content[0].text
    except anthropic.RateLimitError:
        print("    [!] Rate limit hit — waiting 30s...")
        time.sleep(30)
        return call_claude(client, entry, model)
    except anthropic.APIError as e:
        print(f"    [!] API error: {e}")
        return None


def parse_response_sections(raw: str) -> dict:
    """
    Split the Claude response into the three modal sections.
    Returns dict with keys: natural_language, mathematical_expression, attack_graph
    Returns None values if a section is missing (marks entry for review).
    """
    sections = {
        "natural_language": None,
        "mathematical_expression": None,
        "attack_graph": None,
    }

    markers = {
        "natural_language": "[NATURAL LANGUAGE]",
        "mathematical_expression": "[MATHEMATICAL EXPRESSION]",
        "attack_graph": "[ATTACK GRAPH]",
    }

    for key, marker in markers.items():
        start = raw.find(marker)
        if start == -1:
            continue
        start += len(marker)
        # Find the next marker to know where this section ends
        end = len(raw)
        for other_key, other_marker in markers.items():
            if other_key == key:
                continue
            other_start = raw.find(other_marker, start)
            if other_start != -1 and other_start < end:
                end = other_start
        sections[key] = raw[start:end].strip()

    return sections


def validate_entry(sections: dict) -> tuple[bool, list]:
    """Check if an entry is complete enough to use for training."""
    issues = []
    for key, val in sections.items():
        if not val:
            issues.append(f"missing section: {key}")
        elif len(val) < 100:
            issues.append(f"section too short: {key} ({len(val)} chars)")
    return len(issues) == 0, issues


def format_training_example(entry: dict, sections: dict) -> dict:
    """
    Format the input + output into the final training JSONL format.
    Uses the 'instruction' / 'input' / 'output' format compatible with
    most fine-tuning frameworks (trl SFTTrainer, Axolotl, LLaMA-Factory).
    """
    instruction = (
        f"You are a cybersecurity scenario generation expert. "
        f"Generate a detailed tri-modal cyber attack scenario for a {entry.get('attack_level', 'medium')}-level "
        f"attack targeting the {entry.get('industry', 'technology')} sector. "
        f"Output must include natural language narrative, formal mathematical graph expression G=(N,S,V,P,FS), "
        f"and a staged attack graph with preconditions and postconditions."
    )

    input_text = build_user_prompt(entry)

    output_text = (
        f"[NATURAL LANGUAGE]\n{sections['natural_language']}\n\n"
        f"[MATHEMATICAL EXPRESSION]\n{sections['mathematical_expression']}\n\n"
        f"[ATTACK GRAPH]\n{sections['attack_graph']}"
    )

    return {
        "instruction": instruction,
        "input": input_text,
        "output": output_text,
        # Metadata (not used in training, helpful for analysis)
        "_meta": {
            "source_name": entry.get("source_name"),
            "source_id": entry.get("source_id"),
            "source_type": entry.get("source_type"),
            "attack_level": entry.get("attack_level"),
            "industry": entry.get("industry"),
        }
    }


def main():
    parser = argparse.ArgumentParser(
        description="Generate tri-modal outputs for each structured training input"
    )
    parser.add_argument(
        "--inputs",
        required=True,
        help="Path to training_inputs.jsonl from parse_stix.py"
    )
    parser.add_argument(
        "--out",
        default="dataset/training_data.jsonl",
        help="Output path for final training JSONL"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=80,
        help="Max number of entries to process (cost control)"
    )
    parser.add_argument(
        "--model",
        default="claude-haiku-4-5-20251001",
        help="Claude model to use. Haiku is cheapest; use claude-sonnet-4-6 for higher quality"
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help="Seconds to wait between API calls (rate limit safety)"
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Skip entries already present in output file (resume interrupted run)"
    )
    args = parser.parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError(
            "ANTHROPIC_API_KEY environment variable not set.\n"
            "Run: export ANTHROPIC_API_KEY=sk-ant-..."
        )

    client = anthropic.Anthropic(api_key=api_key)

    # Load inputs
    with open(args.inputs, "r", encoding="utf-8") as f:
        entries = [json.loads(line) for line in f if line.strip()]
    print(f"[+] Loaded {len(entries)} input entries")

    # If resuming, find already-processed source IDs
    processed_ids = set()
    if args.resume and os.path.exists(args.out):
        with open(args.out, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    existing = json.loads(line)
                    sid = existing.get("_meta", {}).get("source_id")
                    if sid:
                        processed_ids.add(sid)
                except json.JSONDecodeError:
                    pass
        print(f"[+] Resuming: {len(processed_ids)} entries already done, skipping them")

    # Filter and cap
    to_process = [
        e for e in entries
        if e.get("source_id") not in processed_ids
    ][:args.limit]
    print(f"[+] Will process {len(to_process)} entries with model: {args.model}")

    os.makedirs(os.path.dirname(args.out) if os.path.dirname(args.out) else ".", exist_ok=True)

    # Stats tracking
    stats = {"success": 0, "failed_validation": 0, "api_error": 0}
    review_entries = []

    mode = "a" if args.resume else "w"
    with open(args.out, mode, encoding="utf-8") as out_f:
        for i, entry in enumerate(to_process):
            name = entry.get("source_name", f"entry_{i}")
            print(f"[{i+1}/{len(to_process)}] Processing: {name} ...", end=" ", flush=True)

            raw_response = call_claude(client, entry, args.model)
            if raw_response is None:
                print("SKIPPED (API error)")
                stats["api_error"] += 1
                continue

            sections = parse_response_sections(raw_response)
            is_valid, issues = validate_entry(sections)

            if not is_valid:
                print(f"REVIEW ({', '.join(issues)})")
                stats["failed_validation"] += 1
                review_entries.append({
                    "entry": entry,
                    "issues": issues,
                    "raw_response": raw_response
                })
                continue

            training_example = format_training_example(entry, sections)
            out_f.write(json.dumps(training_example) + "\n")
            out_f.flush()
            stats["success"] += 1
            print(f"OK ({len(raw_response)} chars)")

            time.sleep(args.delay)

    # Save review file for manual inspection
    if review_entries:
        review_path = args.out.replace(".jsonl", "_review.json")
        with open(review_path, "w", encoding="utf-8") as f:
            json.dump(review_entries, f, indent=2)
        print(f"\n[!] {len(review_entries)} entries need review → {review_path}")

    print(f"\n[✓] Done.")
    print(f"    Successful : {stats['success']}")
    print(f"    Need review: {stats['failed_validation']}")
    print(f"    API errors : {stats['api_error']}")
    print(f"    Output     : {args.out}")
    print(f"\n[→] Next step: run fine_tune.py on {args.out}")


if __name__ == "__main__":
    main()