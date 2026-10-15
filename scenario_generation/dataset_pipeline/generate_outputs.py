"""
generate_outputs.py
--------------------
Reads structured attack scenario inputs (produced by parse_stix.py) and calls
the Gemini API to generate tri-modal training outputs for each entry.

Tri-modal output format:
  [NATURAL LANGUAGE]        — human-readable attack narrative
  [MATHEMATICAL EXPRESSION] — formal G=(N,S,V,P,FS) graph notation
  [ATTACK GRAPH]            — staged step-by-step attack path

Usage:
    export GEMINI_API_KEY=your_key_here
    python dataset_pipeline/generate_outputs.py \
        --inputs dataset/inputs/training_inputs.jsonl \
        --out    dataset/training_data.jsonl \
        --limit  80
"""

import argparse
import json
import os
import re
import time
import sys
from pathlib import Path
import httpx

try:
    from dotenv import load_dotenv
except ImportError:
    print("[!] python-dotenv not installed. Run:")
    print("    pip install python-dotenv")
    sys.exit(1)

DOTENV_PATH = Path(__file__).resolve().parents[1] / ".env"
load_dotenv(dotenv_path=DOTENV_PATH, override=True)

try:
    from google import genai
    from google.genai import types
except ImportError:
    print("[!] google-genai not installed. Run:")
    print("    pip install google-genai")
    sys.exit(1)


# ── Prompt templates ──────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a senior cybersecurity red team expert specializing in cloud infrastructure attacks.
Your task is to generate detailed, technically accurate cyber attack scenarios in a strict tri-modal format.

CRITICAL FORMATTING RULES — follow these exactly or the output will be rejected:
1. Your response MUST start immediately with the line: [NATURAL LANGUAGE]
2. Do NOT use markdown. No **, no ##, no *, no backticks, no bold, no headers.
3. The three section headers must appear EXACTLY as plain text on their own line:
   [NATURAL LANGUAGE]
   [MATHEMATICAL EXPRESSION]
   [ATTACK GRAPH]
4. Never skip a section. Never add a preamble before [NATURAL LANGUAGE]. Never add closing remarks after [ATTACK GRAPH].
5. Use real MITRE ATT&CK technique IDs exactly as provided.
6. The mathematical expression must follow G = (N, S, V, P, FS) notation exactly.
7. The attack graph must list numbered stages with plain text arrows (->)."""


def build_user_prompt(entry: dict) -> str:
    """Build the user prompt from a structured input entry."""

    techniques_str = "\n".join(f"  - {t}" for t in entry.get("mitre_techniques", []))
    surfaces_str   = "\n".join(f"  - {s}" for s in entry.get("attack_surfaces", []))
    vectors_str    = "\n".join(f"  - {v}" for v in entry.get("attack_vectors", []))
    cves_str       = ", ".join(entry.get("cve_references", [])) or "None specified"

    return f"""Generate a detailed tri-modal cyber attack scenario for the following context:

SOURCE: {entry.get('source_name', 'Unknown')} ({entry.get('source_id', '')})
INDUSTRY: {entry.get('industry', 'Unknown')}
ATTACK LEVEL: {entry.get('attack_level', 'medium').upper()}

ATTACK SURFACES:
{surfaces_str}

ATTACK VECTORS:
{vectors_str}

MITRE ATT&CK TECHNIQUES:
{techniques_str}

CVE REFERENCES: {cves_str}

SCENARIO SEED:
{entry.get('scenario_seed', 'No seed provided')[:500]}

---

Write your response in plain text with NO markdown. Start immediately with [NATURAL LANGUAGE] on the first line.

[NATURAL LANGUAGE]
Write a 3-5 paragraph detailed narrative describing how this attack unfolds. Include:
- Initial access method
- Lateral movement and privilege escalation steps
- Data exfiltration or impact
- Specific cloud services and misconfigurations exploited

[MATHEMATICAL EXPRESSION]
Express the attack as a graph G = (N, S, V, P, FS) where:
N = set of nodes (systems/services involved)
S = set of security weaknesses exploited
V = set of attack actions/techniques
P = attack paths (sequences of nodes)
FS = final state (attacker's achieved objective)

Write each component on its own line:
N = {{n1: name, n2: name, ...}}
S = {{s1: weakness, s2: weakness, ...}}
V = {{v1: TechniqueID - action, v2: TechniqueID - action, ...}}
P = {{p1: n1 -> n2 -> n3, ...}}
FS = {{objective achieved}}

[ATTACK GRAPH]
List the attack as numbered stages using plain text only:
Stage 1 (Tactic): Component [Technique ID] -> Next component
Stage 2 (Tactic): Component [Technique ID] -> Next component
...continue until full chain...
Final Impact: description of what the attacker achieved"""


# ── Output normalization ──────────────────────────────────────────────────────

def normalize_text(text: str) -> str:
    """Strip common markdown formatting that Gemini adds despite instructions."""
    text = re.sub(r'\*+\[', '[', text)
    text = re.sub(r'\]\*+', ']', text)
    text = re.sub(r'#+\s*\[', '[', text)
    text = re.sub(r'\*\*(.+?)\*\*', r'\1', text)
    text = re.sub(r'\*(.+?)\*', r'\1', text)
    return text


def validate_output(text: str) -> tuple[bool, list]:
    """Check all three required sections are present."""
    required = ["[NATURAL LANGUAGE]", "[MATHEMATICAL EXPRESSION]", "[ATTACK GRAPH]"]
    missing  = [s for s in required if s not in text]
    return (len(missing) == 0), missing


class FatalAPIConfigurationError(Exception):
    """Raised when the API configuration is invalid and retries should stop."""


# ── Gemini API call ───────────────────────────────────────────────────────────

def call_gemini(client, model_name: str, prompt: str, max_retries: int = 3) -> str | None:
    """Call Gemini API with retry + rate-limit backoff."""
    for attempt in range(max_retries):
        try:
            # Prepend system instruction since some models like gemma-3-27b-it do not support it natively
            full_prompt = f"{SYSTEM_PROMPT}\n\n{prompt}"
            response = client.models.generate_content(
                model=model_name,
                contents=full_prompt,
                config=types.GenerateContentConfig(
                    temperature=0.7,
                    max_output_tokens=2048,
                )
            )
            text = response.text
            if text and text.strip():
                return text
            else:
                print(f"\n    [!] Empty response on attempt {attempt + 1}")

        except Exception as e:
            err_str = str(e)
            err_lower = err_str.lower()

            if "api key not valid" in err_lower or "api_key_invalid" in err_lower:
                raise FatalAPIConfigurationError(
                    "GEMINI_API_KEY is invalid for generativelanguage.googleapis.com. "
                    "Create a valid key in Google AI Studio and update .env."
                )

            if "certificate_verify_failed" in err_lower or "self-signed certificate in certificate chain" in err_lower:
                print("\n    [!] TLS certificate verification failed.")
                print("    [!] Your network likely uses a custom/intercepting CA (e.g., corporate proxy).")
                print("    [!] Fix by setting a trusted CA bundle path, e.g.:")
                print("        export SSL_CERT_FILE=/path/to/corporate-ca.pem")
                print("        python dataset_pipeline/generate_outputs.py ...")
                return None

            retry_match = re.search(r'retry_delay\s*\{\s*seconds:\s*(\d+)', err_str)
            suggested_wait = int(retry_match.group(1)) + 2 if retry_match else (2 ** (attempt + 2))

            if "429" in err_str or "quota" in err_str.lower():
                print(f"\n    [!] Rate limit hit. Waiting {suggested_wait}s...")
                time.sleep(suggested_wait)
            else:
                print(f"\n    [!] API error on attempt {attempt + 1}: {err_str[:120]}")
                if attempt < max_retries - 1:
                    wait = 2 ** attempt
                    print(f"    [~] Retrying in {wait}s...")
                    time.sleep(wait)

    return None


# ── Main pipeline ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Generate tri-modal training outputs using Gemma 3 API")
    parser.add_argument("--inputs", required=True,  help="Path to training_inputs.jsonl")
    parser.add_argument("--out",    required=True,  help="Path to output training_data.jsonl")
    parser.add_argument("--limit",  type=int, default=80, help="Max entries to process (default: 80)")
    parser.add_argument("--resume", action="store_true",  help="Skip already-processed entries")
    parser.add_argument("--ca-bundle", default=None,
                        help="Path to PEM CA bundle for TLS verification")
    
    # Updated default to Gemma 3 27B Instruct
    parser.add_argument("--model",  default="gemma-3-27b-it",
                        help="Gemma model (default: gemma-3-27b-it — high rate limits)")
    
    args = parser.parse_args()

    ca_bundle_path = args.ca_bundle or os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE")

    if ca_bundle_path:
        ca_path = Path(ca_bundle_path)
        if not ca_path.exists():
            print(f"[!] CA bundle not found: {ca_path}")
            sys.exit(1)
        os.environ["SSL_CERT_FILE"] = str(ca_path)
        os.environ["REQUESTS_CA_BUNDLE"] = str(ca_path)
        print(f"[+] SSL_CERT_FILE set to: {ca_path}")

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("[!] GEMINI_API_KEY not set. Run: export GEMINI_API_KEY=your_key_here")
        sys.exit(1)

    if api_key.strip().upper() in {"YOUR_KEY", "YOUR_API_KEY", "API_KEY"}:
        print("[!] GEMINI_API_KEY appears to be a placeholder value. Set a real API key.")
        sys.exit(1)

    http_options = None
    if ca_bundle_path:
        http_options = types.HttpOptions(httpx_client=httpx.Client(verify=str(ca_path)))

    client = genai.Client(api_key=api_key, http_options=http_options)
    print(f"[+] Model  : {args.model}")
    print(f"[+] Limits : 15 req/min, 1000 req/day (free tier)")

    inputs_path = Path(args.inputs)
    if not inputs_path.exists():
        print(f"[!] Input file not found: {inputs_path}")
        sys.exit(1)

    with open(inputs_path) as f:
        all_entries = [json.loads(line) for line in f if line.strip()]
    print(f"[+] Loaded {len(all_entries)} input entries")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    processed_ids = set()
    if args.resume and out_path.exists():
        with open(out_path) as f:
            for line in f:
                try:
                    sid = json.loads(line).get("_meta", {}).get("source_id")
                    if sid:
                        processed_ids.add(sid)
                except Exception:
                    pass
        print(f"[+] Resuming — {len(processed_ids)} already done")

    entries_to_process = [
        e for e in all_entries
        if e.get("source_id") not in processed_ids
    ][:args.limit]

    print(f"[+] Processing {len(entries_to_process)} entries → {out_path}")
    print()

    success_count = 0
    fail_count    = 0

    with open(out_path, "a") as out_file:
        for i, entry in enumerate(entries_to_process, 1):
            source_name = entry.get("source_name", "Unknown")
            source_id   = entry.get("source_id", "?")

            print(f"[{i:3}/{len(entries_to_process)}] {source_id} — {source_name} ... ", end="", flush=True)

            try:
                output_text = call_gemini(client, args.model, build_user_prompt(entry))
            except FatalAPIConfigurationError as e:
                print(f"FAILED ({e})")
                print("[!] Stopping run because this is a non-retryable configuration error.")
                break

            if output_text is None:
                print("FAILED (API error)")
                fail_count += 1
                continue

            output_text = normalize_text(output_text)
            valid, missing = validate_output(output_text)

            if not valid:
                preview = output_text[:200].replace('\n', ' ')
                print(f"FAILED (missing: {missing})\n    preview: {preview}")
                fail_count += 1
                continue

            record = {
                "instruction": SYSTEM_PROMPT,
                "input": (
                    f"SOURCE: {entry.get('source_name')} ({entry.get('source_id')})\n"
                    f"INDUSTRY: {entry.get('industry')}\n"
                    f"ATTACK LEVEL: {entry.get('attack_level', '').upper()}\n"
                    f"TECHNIQUES: {', '.join(entry.get('mitre_techniques', []))}\n"
                    f"SURFACES: {', '.join(entry.get('attack_surfaces', []))}"
                ),
                "output": output_text.strip(),
                "_meta": {
                    "source_id":    entry.get("source_id"),
                    "source_name":  entry.get("source_name"),
                    "source_type":  entry.get("source_type"),
                    "attack_level": entry.get("attack_level"),
                    "industry":     entry.get("industry"),
                }
            }

            out_file.write(json.dumps(record) + "\n")
            out_file.flush()
            success_count += 1
            print("OK")

            # 5s between requests = 12 req/min, safely under the 15 req/min limit
            time.sleep(5)

    print()
    print(f"[✓] Done — {success_count} successful, {fail_count} failed")
    print(f"    Output: {out_path}")
    if success_count > 0:
        print(f"\n[+] Next step: run fine_tune.py on {out_path}")


if __name__ == "__main__":
    main()