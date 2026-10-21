"""
visualize_dataset.py
─────────────────────────────────────────────────────────────────────────────
Generates 6 charts from your parsed and training datasets.
Run from inside scenario_generation/:

    pip install matplotlib seaborn
    python visualize_dataset.py

Outputs: dataset_visualizations/ folder with 6 PNG files
─────────────────────────────────────────────────────────────────────────────
"""

import json
import re
from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt
import seaborn as sns

# ── Config ────────────────────────────────────────────────────────────────────
TRAINING_INPUTS  = Path("dataset/inputs/training_inputs.jsonl")
TRAINING_DATA    = Path("dataset/training_data.jsonl")
OUT_DIR          = Path("dataset_visualizations")

# Colour palette — consistent across all charts
PURPLE = "#534AB7"
TEAL   = "#1D9E75"
AMBER  = "#BA7517"
CORAL  = "#D85A30"
GRAY   = "#888780"

PALETTE = [PURPLE, TEAL, AMBER, CORAL, GRAY]

# ── Setup ─────────────────────────────────────────────────────────────────────
OUT_DIR.mkdir(exist_ok=True)
sns.set_theme(style="whitegrid", font_scale=1.1)
plt.rcParams.update({
    "font.family":  "sans-serif",
    "axes.spines.top":   False,
    "axes.spines.right": False,
})

# ── Load data ─────────────────────────────────────────────────────────────────
def load_jsonl(path: Path) -> list[dict]:
    items = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return items

print("[+] Loading datasets...")
inputs   = load_jsonl(TRAINING_INPUTS)
training = load_jsonl(TRAINING_DATA)
print(f"    Parsed inputs  : {len(inputs)}")
print(f"    Training records: {len(training)}")


# ─────────────────────────────────────────────────────────────────────────────
# Chart 1 — Industry distribution (horizontal bar)
# ─────────────────────────────────────────────────────────────────────────────
def chart_industry_distribution():
    industries = [e.get("industry", "Unknown") for e in inputs]

    # Shorten labels for readability
    short = {
        "Public administration and defence (ISIC O)":         "Government / Defence",
        "Financial and insurance activities (ISIC K)":        "Financial Services",
        "Information technology service activities (ISIC J62)": "IT Services",
        "Electricity, gas, steam and AC supply (ISIC D)":     "Energy / Utilities",
        "Human health and social work (ISIC Q)":              "Healthcare",
        "Education (ISIC P)":                                 "Education",
        "Information and communication (ISIC J)":             "Telecom / Comms",
        "Information technology service activities (ISIC 6311)": "Cloud / SaaS",
        "Manufacturing (ISIC C)":                             "Manufacturing",
    }
    labels = [short.get(i, i) for i in industries]
    counts = Counter(labels)
    sorted_items = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    names, vals = zip(*sorted_items)

    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.barh(list(reversed(names)), list(reversed(vals)),
                   color=[PURPLE, TEAL, AMBER, CORAL, GRAY, PURPLE, TEAL, AMBER, CORAL][:len(names)],
                   edgecolor="white", height=0.6)

    for bar, val in zip(bars, reversed(vals)):
        ax.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height() / 2,
                str(val), va="center", fontsize=10, color="#444441")

    ax.set_xlabel("Number of entries", labelpad=8)
    ax.set_title("Industry distribution across 209 parsed entries", fontsize=13,
                 fontweight="bold", pad=14)
    ax.set_xlim(0, max(vals) + 12)
    plt.tight_layout()
    path = OUT_DIR / "01_industry_distribution.png"
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[✓] {path}")


# ─────────────────────────────────────────────────────────────────────────────
# Chart 2 — Attack level distribution (donut chart)
# ─────────────────────────────────────────────────────────────────────────────
def chart_attack_level():
    levels  = [e.get("attack_level", "unknown") for e in inputs]
    counts  = Counter(levels)
    labels  = list(counts.keys())
    values  = list(counts.values())
    colours = {"high": CORAL, "medium": AMBER, "low": TEAL, "unknown": GRAY}
    clrs    = [colours.get(l, GRAY) for l in labels]

    fig, ax = plt.subplots(figsize=(6, 6))
    wedges, texts, autotexts = ax.pie(
        values,
        labels=labels,
        colors=clrs,
        autopct="%1.1f%%",
        startangle=140,
        pctdistance=0.78,
        wedgeprops={"width": 0.55, "edgecolor": "white", "linewidth": 2},
    )
    for t in texts:
        t.set_fontsize(12)
        t.set_fontweight("bold")
    for at in autotexts:
        at.set_fontsize(10)
        at.set_color("white")

    ax.set_title("Attack level distribution\n(209 entries)", fontsize=13,
                 fontweight="bold", pad=16)
    plt.tight_layout()
    path = OUT_DIR / "02_attack_level_donut.png"
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[✓] {path}")


# ─────────────────────────────────────────────────────────────────────────────
# Chart 3 — Source type breakdown (campaign vs group)
# ─────────────────────────────────────────────────────────────────────────────
def chart_source_type():
    types  = [e.get("source_type", "unknown") for e in inputs]
    counts = Counter(types)

    fig, ax = plt.subplots(figsize=(6, 4))
    bars = ax.bar(
        [t.capitalize() for t in counts.keys()],
        counts.values(),
        color=[PURPLE, TEAL],
        width=0.45,
        edgecolor="white",
    )
    for bar in bars:
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 2,
                str(int(bar.get_height())), ha="center", fontsize=12,
                fontweight="bold", color="#444441")

    ax.set_ylabel("Count", labelpad=8)
    ax.set_title("Entries by source type\n(Campaigns vs Threat Groups)", fontsize=13,
                 fontweight="bold", pad=14)
    ax.set_ylim(0, max(counts.values()) + 20)
    plt.tight_layout()
    path = OUT_DIR / "03_source_type_breakdown.png"
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[✓] {path}")


# ─────────────────────────────────────────────────────────────────────────────
# Chart 4 — Number of techniques per entry (histogram)
# ─────────────────────────────────────────────────────────────────────────────
def chart_techniques_per_entry():
    counts = [len(e.get("mitre_techniques", [])) for e in inputs]

    fig, ax = plt.subplots(figsize=(8, 4))
    ax.hist(counts, bins=range(0, max(counts) + 2), color=PURPLE,
            edgecolor="white", linewidth=0.8, alpha=0.9)
    ax.axvline(sum(counts) / len(counts), color=CORAL, linestyle="--",
               linewidth=1.8, label=f"Mean: {sum(counts)/len(counts):.1f}")
    ax.set_xlabel("Number of MITRE techniques per entry", labelpad=8)
    ax.set_ylabel("Number of entries", labelpad=8)
    ax.set_title("MITRE ATT&CK technique coverage per training input", fontsize=13,
                 fontweight="bold", pad=14)
    ax.legend(fontsize=10)
    plt.tight_layout()
    path = OUT_DIR / "04_techniques_per_entry.png"
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[✓] {path}")


# ─────────────────────────────────────────────────────────────────────────────
# Chart 5 — Top 15 most frequent ATT&CK techniques across dataset
# ─────────────────────────────────────────────────────────────────────────────
def chart_top_techniques():
    all_techs = []
    for e in inputs:
        for t in e.get("mitre_techniques", []):
            # Extract just the ID part e.g. "T1059.001 - ..." → "T1059.001"
            match = re.match(r"(T\d+(?:\.\d+)?)", t)
            if match:
                all_techs.append(match.group(1))

    counts = Counter(all_techs)
    top15  = counts.most_common(15)
    names, vals = zip(*top15)

    fig, ax = plt.subplots(figsize=(10, 5))
    colours = [PURPLE if i % 2 == 0 else TEAL for i in range(len(names))]
    bars = ax.barh(list(reversed(names)), list(reversed(vals)),
                   color=list(reversed(colours)), edgecolor="white", height=0.6)

    for bar, val in zip(bars, reversed(vals)):
        ax.text(bar.get_width() + 0.2, bar.get_y() + bar.get_height() / 2,
                str(val), va="center", fontsize=9, color="#444441")

    ax.set_xlabel("Frequency across 209 entries", labelpad=8)
    ax.set_title("Top 15 most frequent MITRE ATT&CK techniques", fontsize=13,
                 fontweight="bold", pad=14)
    ax.set_xlim(0, max(vals) + 5)
    plt.tight_layout()
    path = OUT_DIR / "05_top_techniques.png"
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[✓] {path}")


# ─────────────────────────────────────────────────────────────────────────────
# Chart 6 — Training vs unseen split + output section length comparison
# ─────────────────────────────────────────────────────────────────────────────
def chart_training_split_and_output_lengths():
    fig, axes = plt.subplots(1, 2, figsize=(12, 4))

    # Left — train/val/unseen split
    ax = axes[0]
    splits = ["Training\n(64)", "Validation\n(17)", "Unseen test\n(10)", "Unused\n(118)"]
    sizes  = [64, 17, 10, 118]
    clrs   = [PURPLE, TEAL, AMBER, GRAY]
    bars   = ax.bar(splits, sizes, color=clrs, width=0.5, edgecolor="white")
    for bar in bars:
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1.5,
                str(int(bar.get_height())), ha="center", fontsize=11,
                fontweight="bold", color="#444441")
    ax.set_ylabel("Number of entries", labelpad=8)
    ax.set_title("Dataset split\n(from 209 total parsed inputs)", fontsize=12,
                 fontweight="bold", pad=12)
    ax.set_ylim(0, 140)

    # Right — output section lengths in training data
    ax2 = axes[1]
    if training:
        nl_lens, math_lens, graph_lens = [], [], []
        for rec in training:
            output = rec.get("output", "")
            sections = {"nl": "", "math": "", "graph": ""}
            nl_start   = output.find("[NATURAL LANGUAGE]")
            math_start = output.find("[MATHEMATICAL EXPRESSION]")
            graph_start = output.find("[ATTACK GRAPH]")

            if nl_start != -1:
                end = math_start if math_start != -1 else len(output)
                sections["nl"] = output[nl_start + len("[NATURAL LANGUAGE]"):end].strip()
            if math_start != -1:
                end = graph_start if graph_start != -1 else len(output)
                sections["math"] = output[math_start + len("[MATHEMATICAL EXPRESSION]"):end].strip()
            if graph_start != -1:
                sections["graph"] = output[graph_start + len("[ATTACK GRAPH]"):].strip()

            nl_lens.append(len(sections["nl"].split()))
            math_lens.append(len(sections["math"].split()))
            graph_lens.append(len(sections["graph"].split()))

        data   = [nl_lens, math_lens, graph_lens]
        labels = ["Natural\nLanguage", "Mathematical\nExpression", "Attack\nGraph"]
        bp = ax2.boxplot(data, labels=labels, patch_artist=True,
                         medianprops={"color": "white", "linewidth": 2})
        for patch, colour in zip(bp["boxes"], [PURPLE, TEAL, AMBER]):
            patch.set_facecolor(colour)
            patch.set_alpha(0.85)
        for element in ["whiskers", "caps", "fliers"]:
            for item in bp[element]:
                item.set_color(GRAY)

        ax2.set_ylabel("Word count", labelpad=8)
        ax2.set_title("Output section lengths\n(81 training records)", fontsize=12,
                      fontweight="bold", pad=12)
    else:
        ax2.text(0.5, 0.5, "training_data.jsonl not found",
                 ha="center", va="center", transform=ax2.transAxes,
                 color=GRAY, fontsize=10)
        ax2.set_title("Output section lengths", fontsize=12, pad=12)

    plt.tight_layout()
    path = OUT_DIR / "06_split_and_output_lengths.png"
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[✓] {path}")


# ── Run all charts ─────────────────────────────────────────────────────────────
print("\n[+] Generating charts...")
chart_industry_distribution()
chart_attack_level()
chart_source_type()
chart_techniques_per_entry()
chart_top_techniques()
chart_training_split_and_output_lengths()

print(f"\n[✓] All charts saved to: {OUT_DIR}/")
print("    01_industry_distribution.png")
print("    02_attack_level_donut.png")
print("    03_source_type_breakdown.png")
print("    04_techniques_per_entry.png")
print("    05_top_techniques.png")
print("    06_split_and_output_lengths.png")