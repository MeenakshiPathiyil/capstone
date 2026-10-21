"""
manual_eval_metrics.py
----------------------
Reference-free, deterministic evaluation of prompt_gen_comparison.txt.

WHY these metrics (not an LLM judge):
  - Your fine-tuned model was trained on a specific tri-modal format with
    explicit rules (section headers, G-notation, MITRE IDs, numbered stages).
  - A generic LLM judge has no knowledge of those rules and would introduce
    its own biases (length preference, rewording preference, etc.).
  - These metrics directly test what the training actually optimised for.

Usage:
    python evaluation/manual_eval_metrics.py --txt prompt_gen_comparison.txt
    python evaluation/manual_eval_metrics.py --txt prompt_gen_comparison.txt --csv
"""

import argparse
import csv
import re
import sys
from dataclasses import dataclass, fields
from pathlib import Path


# ── Section / format constants ────────────────────────────────────────────────

SECTIONS_ORDERED = [
    "[NATURAL LANGUAGE]",
    "[MATHEMATICAL EXPRESSION]",
    "[ATTACK GRAPH]",
]

# Regex patterns
MITRE_ID_RE   = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')
G_NOTATION_RE = re.compile(r'G\s*=\s*\(\s*N\s*,\s*S\s*,\s*V\s*,\s*P\s*,\s*FS\s*\)')
ARROW_RE      = re.compile(r'->')
# Numbered stage: "1." or "1)" or "Stage 1" at start of line
STAGE_RE      = re.compile(r'(?:^|\n)\s*(?:Stage\s*)?\d+[.):\s]', re.MULTILINE)
# Markdown contamination — things the training explicitly forbade
MD_RE         = re.compile(r'(\*\*|^#{1,3} )', re.MULTILINE)
# G = (...) node lists — each component defined separately (N = {...}, S = {...} etc.)
COMPONENT_RE  = re.compile(r'\b([NSVPF]S?)\s*=\s*\{', re.MULTILINE)
# Section content extractor
NL_TEXT_RE    = re.compile(
    r'\[NATURAL LANGUAGE\](.*?)(?=\[MATHEMATICAL EXPRESSION\]|\Z)', re.DOTALL)
MATH_TEXT_RE  = re.compile(
    r'\[MATHEMATICAL EXPRESSION\](.*?)(?=\[ATTACK GRAPH\]|\Z)', re.DOTALL)
GRAPH_TEXT_RE = re.compile(
    r'\[ATTACK GRAPH\](.*?)(?=\Z)', re.DOTALL)


# ── Data class ────────────────────────────────────────────────────────────────

@dataclass
class OutputMetrics:
    model:               str = ""
    prompt_id:           str = ""
    focus:               str = ""

    # 1. Structural Compliance (0–3 + bool)
    sections_found:      int   = 0    # how many of the 3 headers appear
    sections_in_order:   int   = 0    # 1 if all 3 appear in the correct order
    all_sections_present:int   = 0    # 1 if sections_found == 3

    # 2. MITRE Technique Coverage
    mitre_input_count:   int   = 0    # IDs in the prompt
    mitre_output_count:  int   = 0    # unique IDs found in the output
    mitre_recall:        float = 0.0  # output ∩ input / input
    mitre_precision:     float = 0.0  # output ∩ input / output (no hallucination)

    # 3. Format Specificity (training-critical rules)
    g_notation_exact:    int   = 0    # G = (N, S, V, P, FS) present?
    g_components_defined:int   = 0    # how many of N/S/V/P/FS are separately defined
    arrow_count:         int   = 0    # number of -> edges in attack graph
    numbered_stages:     int   = 0    # numbered stage lines found
    markdown_violations: int   = 0    # ** / # contamination count (lower = better)

    # 4. Lexical Diversity
    word_count:          int   = 0    # total words in output
    nl_word_count:       int   = 0    # words in [NATURAL LANGUAGE] section only
    distinct_1:          float = 0.0  # unique unigrams / total unigrams
    distinct_2:          float = 0.0  # unique bigrams / total bigrams
    type_token_ratio:    float = 0.0  # same as distinct_1, aliased for clarity

    # 5. Completeness signals
    output_truncated:    int   = 0    # 1 if output ends mid-sentence (no terminal punct)
    nl_has_mitre_inline: int   = 0    # MITRE IDs appear in NL prose (not just graph)
    graph_has_arrows:    int   = 0    # attack graph section has at least 1 ->


# ── Parser: extract outputs from comparison TXT ──────────────────────────────

def _extract_technique_ids(techniques_str: str) -> set[str]:
    return set(MITRE_ID_RE.findall(techniques_str))


def parse_comparison_txt(txt_path: Path) -> list[dict]:
    """
    Return a list of dicts, each with keys:
        prompt_id, focus, techniques, model, output
    Parsed from prompt_gen_comparison.txt.
    """
    text = txt_path.read_text(encoding="utf-8")
    records = []

    # Split on the wide separator lines
    blocks = re.split(r'={40,}', text)

    for block in blocks:
        block = block.strip()
        if not block:
            continue

        # Is this a prompt block?
        pm = re.match(r'PROMPT (P\d+): (.+?)\n', block)
        if not pm:
            continue
        prompt_id = pm.group(1)
        focus     = pm.group(2).strip()

        # Extract techniques line
        tech_m = re.search(r'Techniques: (.+?)(?:\n|$)', block)
        techniques = tech_m.group(1).strip() if tech_m else ""

        # Split into baseline / fine-tuned sub-blocks
        parts = re.split(
            r'(BASELINE OUTPUT.*?|FINE-TUNED OUTPUT.*?)\n-{40,}',
            block, flags=re.DOTALL
        )
        # parts alternates: [before, label, content, label, content, ...]
        i = 0
        while i < len(parts):
            part = parts[i].strip()
            if "BASELINE OUTPUT" in part:
                model = "baseline"
                output = parts[i + 1].strip() if i + 1 < len(parts) else ""
                records.append({
                    "prompt_id": prompt_id, "focus": focus,
                    "techniques": techniques, "model": model, "output": output
                })
                i += 2
            elif "FINE-TUNED OUTPUT" in part:
                model = "finetuned"
                output = parts[i + 1].strip() if i + 1 < len(parts) else ""
                records.append({
                    "prompt_id": prompt_id, "focus": focus,
                    "techniques": techniques, "model": model, "output": output
                })
                i += 2
            else:
                i += 1

    return records


# ── Metric computation ────────────────────────────────────────────────────────

def compute_metrics(rec: dict) -> OutputMetrics:
    m   = OutputMetrics()
    txt = rec["output"]
    m.model     = rec["model"]
    m.prompt_id = rec["prompt_id"]
    m.focus     = rec["focus"]

    # ── 1. Structural Compliance ──────────────────────────────────────────────
    present_in_order = [s for s in SECTIONS_ORDERED if s in txt]
    m.sections_found       = len(present_in_order)
    m.all_sections_present = int(m.sections_found == 3)
    m.sections_in_order    = int(present_in_order == SECTIONS_ORDERED)

    # ── 2. MITRE Coverage ────────────────────────────────────────────────────
    input_ids  = _extract_technique_ids(rec["techniques"])
    output_ids = set(MITRE_ID_RE.findall(txt))
    m.mitre_input_count  = len(input_ids)
    m.mitre_output_count = len(output_ids)
    if input_ids:
        m.mitre_recall    = round(len(input_ids & output_ids) / len(input_ids), 3)
    if output_ids:
        m.mitre_precision = round(len(input_ids & output_ids) / len(output_ids), 3)

    # ── 3. Format Specificity ─────────────────────────────────────────────────
    m.g_notation_exact     = int(bool(G_NOTATION_RE.search(txt)))
    m.g_components_defined = len(set(COMPONENT_RE.findall(txt)))
    m.arrow_count          = len(ARROW_RE.findall(txt))
    m.numbered_stages      = len(STAGE_RE.findall(txt))
    m.markdown_violations  = len(MD_RE.findall(txt))

    # ── 4. Lexical Diversity ─────────────────────────────────────────────────
    tokens = re.findall(r'\b\w+\b', txt.lower())
    m.word_count = len(tokens)
    if len(tokens) >= 2:
        bigrams = [f"{tokens[i]}_{tokens[i+1]}" for i in range(len(tokens) - 1)]
        m.distinct_1      = round(len(set(tokens))  / len(tokens), 4)
        m.distinct_2      = round(len(set(bigrams)) / len(bigrams), 4)
        m.type_token_ratio = m.distinct_1

    # Natural-language section word count
    nl_m = NL_TEXT_RE.search(txt)
    if nl_m:
        nl_tokens = re.findall(r'\b\w+\b', nl_m.group(1).lower())
        m.nl_word_count = len(nl_tokens)
        # MITRE IDs in NL prose — fine-tuned should reference them inline
        m.nl_has_mitre_inline = int(bool(MITRE_ID_RE.search(nl_m.group(1))))

    # ── 5. Completeness ──────────────────────────────────────────────────────
    stripped = txt.rstrip()
    m.output_truncated = int(
        bool(stripped) and stripped[-1] not in {'.', '!', '?', '}', ']'}
    )

    graph_m = GRAPH_TEXT_RE.search(txt)
    if graph_m:
        m.graph_has_arrows = int(bool(ARROW_RE.search(graph_m.group(1))))

    return m


# ── Reporting ─────────────────────────────────────────────────────────────────

METRIC_EXPLANATIONS = {
    "sections_found":       "# of [NL]/[MATH]/[GRAPH] headers found (max 3)",
    "sections_in_order":    "All 3 sections appear in the correct order (1=yes)",
    "all_sections_present": "All 3 sections present (1=yes)",
    "mitre_recall":         "Fraction of INPUT technique IDs that appear in output",
    "mitre_precision":      "Fraction of OUTPUT technique IDs that were in the input (hallucination check)",
    "g_notation_exact":     "G = (N, S, V, P, FS) exact notation present (1=yes)",
    "g_components_defined": "# of G components (N/S/V/P/FS) separately defined (max 5)",
    "arrow_count":          "# of -> edges in attack graph (more = richer graph)",
    "numbered_stages":      "# of numbered stage lines",
    "markdown_violations":  "# of ** / # markdown artefacts (lower=better, should be 0 for fine-tuned)",
    "word_count":           "Total word count of output",
    "nl_word_count":        "Word count of [NATURAL LANGUAGE] section only",
    "distinct_1":           "Lexical diversity: unique unigrams / total unigrams (higher=richer)",
    "distinct_2":           "Lexical diversity: unique bigrams / total bigrams (higher=richer)",
    "output_truncated":     "Output appears to be cut off mid-sentence (1=truncated, 0=complete)",
    "nl_has_mitre_inline":  "MITRE IDs appear inline in NL prose (1=yes, as required by training)",
    "graph_has_arrows":     "Attack graph section has at least 1 -> arrow (1=yes)",
}

# Which direction is 'better' for each metric (used in report)
HIGHER_IS_BETTER = {
    "sections_found", "sections_in_order", "all_sections_present",
    "mitre_recall", "mitre_precision", "g_notation_exact",
    "g_components_defined", "arrow_count", "numbered_stages",
    "word_count", "nl_word_count", "distinct_1", "distinct_2",
    "type_token_ratio", "nl_has_mitre_inline", "graph_has_arrows",
}
LOWER_IS_BETTER = {"markdown_violations", "output_truncated"}

NUMERIC_METRICS = [
    "sections_found", "sections_in_order", "all_sections_present",
    "mitre_recall", "mitre_precision",
    "g_notation_exact", "g_components_defined", "arrow_count",
    "numbered_stages", "markdown_violations",
    "word_count", "nl_word_count", "distinct_1", "distinct_2",
    "output_truncated", "nl_has_mitre_inline", "graph_has_arrows",
]


def _avg(values: list) -> float:
    valid = [float(v) for v in values if v != "" and v is not None]
    return round(sum(valid) / len(valid), 4) if valid else 0.0


def print_table(all_metrics: list[OutputMetrics]):
    """Print a compact per-output metrics table to stdout."""
    id_w  = 10
    m_w   = 9

    header = f"{'model':>10} {'pid':>{id_w}}"
    for m in NUMERIC_METRICS:
        header += f" {m[:m_w]:>{m_w}}"
    print(header)
    print("-" * len(header))

    for om in all_metrics:
        row = f"{om.model:>10} {om.prompt_id:>{id_w}}"
        for m in NUMERIC_METRICS:
            val = getattr(om, m)
            row += f" {str(val):>{m_w}}"
        print(row)


def aggregate_by_model(all_metrics: list[OutputMetrics]) -> dict[str, dict]:
    agg = {}
    for model_name in ("baseline", "finetuned"):
        subset = [om for om in all_metrics if om.model == model_name]
        if not subset:
            continue
        agg[model_name] = {}
        for m in NUMERIC_METRICS:
            vals = [getattr(om, m) for om in subset]
            agg[model_name][m] = _avg(vals)
    return agg


def write_markdown_report(
    all_metrics: list[OutputMetrics],
    agg: dict[str, dict],
    out_path: Path
):
    lines = []
    lines.append("# Scenario Generator — Manual Evaluation Report")
    lines.append("")
    lines.append(
        "> **Methodology**: Reference-free metrics. No LLM judge used.  \n"
        "> Each metric directly tests a rule the fine-tuned model was trained on."
    )
    lines.append("")

    # ── Metric legend ──
    lines.append("## Metric Definitions")
    lines.append("")
    lines.append("| Metric | What it measures | Better direction |")
    lines.append("|---|---|:---:|")
    for m in NUMERIC_METRICS:
        direction = "↑ higher" if m in HIGHER_IS_BETTER else "↓ lower"
        lines.append(f"| `{m}` | {METRIC_EXPLANATIONS.get(m, '')} | {direction} |")
    lines.append("")

    # ── Aggregate comparison ──
    lines.append("## Baseline vs Fine-Tuned: Averaged Scores")
    lines.append("")
    lines.append("| Metric | Baseline | Fine-Tuned | Δ | Winner |")
    lines.append("|---|---:|---:|---:|:---:|")
    for m in NUMERIC_METRICS:
        b = agg.get("baseline",  {}).get(m, "—")
        f = agg.get("finetuned", {}).get(m, "—")
        if isinstance(b, float) and isinstance(f, float):
            delta = round(f - b, 4)
            if m in HIGHER_IS_BETTER:
                winner = "🟢 FT" if delta > 0 else ("🔴 Base" if delta < 0 else "Tie")
            else:
                winner = "🟢 FT" if delta < 0 else ("🔴 Base" if delta > 0 else "Tie")
            delta_str = f"+{delta}" if delta > 0 else str(delta)
        else:
            delta_str, winner = "—", "—"
        lines.append(f"| `{m}` | {b} | {f} | {delta_str} | {winner} |")
    lines.append("")

    # ── Per-prompt breakdown ──
    lines.append("## Per-Prompt Breakdown")
    lines.append("")
    prompt_ids = sorted(set(om.prompt_id for om in all_metrics))
    for pid in prompt_ids:
        pair = {om.model: om for om in all_metrics if om.prompt_id == pid}
        b_om = pair.get("baseline")
        f_om = pair.get("finetuned")
        if b_om:
            lines.append(f"### {pid}: {b_om.focus}")
        lines.append("")
        lines.append("| Metric | Baseline | Fine-Tuned |")
        lines.append("|---|---:|---:|")
        for m in NUMERIC_METRICS:
            b_val = getattr(b_om, m, "—") if b_om else "—"
            f_val = getattr(f_om, m, "—") if f_om else "—"
            lines.append(f"| `{m}` | {b_val} | {f_val} |")
        lines.append("")

    # ── Interpretation guide ──
    lines.append("## How to Interpret Results")
    lines.append("")
    lines.append("| What you want to see | Why |")
    lines.append("|---|---|")
    lines.append("| Fine-tuned `sections_in_order = 1` on all prompts | Training enforced strict section ordering |")
    lines.append("| Fine-tuned `mitre_recall` ≥ baseline | Fine-tuned should reference all input technique IDs |")
    lines.append("| Fine-tuned `mitre_precision` ≥ baseline | Fine-tuned should not hallucinate MITRE IDs not in input |")
    lines.append("| Fine-tuned `g_notation_exact = 1` | Exact G=(N,S,V,P,FS) notation was in every training sample |")
    lines.append("| Fine-tuned `g_components_defined` = 5 | All 5 components should be separately defined |")
    lines.append("| Fine-tuned `markdown_violations = 0` | Training explicitly forbade **, ##, etc. |")
    lines.append("| Fine-tuned `nl_has_mitre_inline = 1` | Training required technique IDs inline in NL prose |")
    lines.append("| Fine-tuned `graph_has_arrows = 1` | Training required -> arrows in attack graph |")
    lines.append("| Fine-tuned `output_truncated = 0` | Output should reach a natural conclusion |")
    lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"[OK] Markdown report saved: {out_path}")


def write_csv(all_metrics: list[OutputMetrics], out_path: Path):
    field_names = [f.name for f in fields(OutputMetrics)]
    with out_path.open("w", newline="", encoding="utf-8") as fp:
        w = csv.DictWriter(fp, fieldnames=field_names)
        w.writeheader()
        for om in all_metrics:
            w.writerow({f.name: getattr(om, f.name) for f in fields(OutputMetrics)})
    print(f"[OK] CSV saved: {out_path}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Reference-free eval of prompt_gen_comparison.txt")
    parser.add_argument("--txt",  required=True, help="Path to prompt_gen_comparison.txt")
    parser.add_argument("--csv",  action="store_true", help="Also save eval_results.csv")
    parser.add_argument("--md",   default="", help="Path for markdown report (default: eval_report.md next to --txt)")
    args = parser.parse_args()

    txt_path = Path(args.txt)
    if not txt_path.exists():
        print(f"[!] File not found: {txt_path}")
        sys.exit(1)

    out_dir  = txt_path.parent
    md_path  = Path(args.md) if args.md else out_dir / "eval_report.md"
    csv_path = out_dir / "eval_results.csv"

    print(f"[*] Parsing: {txt_path}")
    records = parse_comparison_txt(txt_path)
    if not records:
        print("[!] No output records found. Check the TXT format.")
        sys.exit(1)
    print(f"[OK] Found {len(records)} outputs ({len(records)//2} prompts x 2 models)")

    print("[*] Computing metrics...")
    all_metrics = [compute_metrics(r) for r in records]

    print()
    print_table(all_metrics)

    agg = aggregate_by_model(all_metrics)

    print()
    print("== AVERAGE SCORES ===============================================")
    print(f"{'metric':<30} {'baseline':>10} {'finetuned':>10}")
    print("-" * 52)
    for m in NUMERIC_METRICS:
        b = agg.get("baseline",  {}).get(m, "-")
        f = agg.get("finetuned", {}).get(m, "-")
        print(f"  {m:<28} {str(b):>10} {str(f):>10}")

    write_markdown_report(all_metrics, agg, md_path)
    if args.csv:
        write_csv(all_metrics, csv_path)


if __name__ == "__main__":
    main()
