# Scenario Generator — Manual Evaluation Report

> **Methodology**: Reference-free metrics. No LLM judge used.  
> Each metric directly tests a rule the fine-tuned model was trained on.

## Metric Definitions

| Metric | What it measures | Better direction |
|---|---|:---:|
| `sections_found` | # of [NL]/[MATH]/[GRAPH] headers found (max 3) | ↑ higher |
| `sections_in_order` | All 3 sections appear in the correct order (1=yes) | ↑ higher |
| `all_sections_present` | All 3 sections present (1=yes) | ↑ higher |
| `mitre_recall` | Fraction of INPUT technique IDs that appear in output | ↑ higher |
| `mitre_precision` | Fraction of OUTPUT technique IDs that were in the input (hallucination check) | ↑ higher |
| `g_notation_exact` | G = (N, S, V, P, FS) exact notation present (1=yes) | ↑ higher |
| `g_components_defined` | # of G components (N/S/V/P/FS) separately defined (max 5) | ↑ higher |
| `arrow_count` | # of -> edges in attack graph (more = richer graph) | ↑ higher |
| `numbered_stages` | # of numbered stage lines | ↑ higher |
| `markdown_violations` | # of ** / # markdown artefacts (lower=better, should be 0 for fine-tuned) | ↓ lower |
| `word_count` | Total word count of output | ↑ higher |
| `nl_word_count` | Word count of [NATURAL LANGUAGE] section only | ↑ higher |
| `distinct_1` | Lexical diversity: unique unigrams / total unigrams (higher=richer) | ↑ higher |
| `distinct_2` | Lexical diversity: unique bigrams / total bigrams (higher=richer) | ↑ higher |
| `output_truncated` | Output appears to be cut off mid-sentence (1=truncated, 0=complete) | ↓ lower |
| `nl_has_mitre_inline` | MITRE IDs appear inline in NL prose (1=yes, as required by training) | ↑ higher |
| `graph_has_arrows` | Attack graph section has at least 1 -> arrow (1=yes) | ↑ higher |

## Baseline vs Fine-Tuned: Averaged Scores

| Metric | Baseline | Fine-Tuned | Δ | Winner |
|---|---:|---:|---:|:---:|
| `sections_found` | 3.0 | 3.0 | 0.0 | Tie |
| `sections_in_order` | 1.0 | 1.0 | 0.0 | Tie |
| `all_sections_present` | 1.0 | 1.0 | 0.0 | Tie |
| `mitre_recall` | 0.95 | 1.0 | +0.05 | 🟢 FT |
| `mitre_precision` | 0.6727 | 0.7632 | +0.0905 | 🟢 FT |
| `g_notation_exact` | 1.0 | 0.0 | -1.0 | 🔴 Base |
| `g_components_defined` | 5.0 | 5.0 | 0.0 | Tie |
| `arrow_count` | 7.25 | 5.75 | -1.5 | 🔴 Base |
| `numbered_stages` | 7.0 | 8.25 | +1.25 | 🟢 FT |
| `markdown_violations` | 0.0 | 0.0 | 0.0 | Tie |
| `word_count` | 371.0 | 610.75 | +239.75 | 🟢 FT |
| `nl_word_count` | 219.0 | 366.0 | +147.0 | 🟢 FT |
| `distinct_1` | 0.437 | 0.4615 | +0.0245 | 🟢 FT |
| `distinct_2` | 0.776 | 0.8365 | +0.0605 | 🟢 FT |
| `output_truncated` | 1.0 | 1.0 | 0.0 | Tie |
| `nl_has_mitre_inline` | 1.0 | 1.0 | 0.0 | Tie |
| `graph_has_arrows` | 0.75 | 0.25 | -0.5 | 🔴 Base |

## Per-Prompt Breakdown

### P1: Full Tri-Modal Scenario (Standard)

| Metric | Baseline | Fine-Tuned |
|---|---:|---:|
| `sections_found` | 3 | 3 |
| `sections_in_order` | 1 | 1 |
| `all_sections_present` | 1 | 1 |
| `mitre_recall` | 1.0 | 1.0 |
| `mitre_precision` | 0.833 | 0.714 |
| `g_notation_exact` | 1 | 0 |
| `g_components_defined` | 5 | 5 |
| `arrow_count` | 4 | 7 |
| `numbered_stages` | 14 | 8 |
| `markdown_violations` | 0 | 0 |
| `word_count` | 304 | 651 |
| `nl_word_count` | 155 | 372 |
| `distinct_1` | 0.375 | 0.4439 |
| `distinct_2` | 0.7096 | 0.8354 |
| `output_truncated` | 1 | 1 |
| `nl_has_mitre_inline` | 1 | 1 |
| `graph_has_arrows` | 1 | 0 |

### P2: Cloud-Centric IAM Abuse

| Metric | Baseline | Fine-Tuned |
|---|---:|---:|
| `sections_found` | 3 | 3 |
| `sections_in_order` | 1 | 1 |
| `all_sections_present` | 1 | 1 |
| `mitre_recall` | 0.8 | 1.0 |
| `mitre_precision` | 0.4 | 1.0 |
| `g_notation_exact` | 1 | 0 |
| `g_components_defined` | 5 | 5 |
| `arrow_count` | 18 | 12 |
| `numbered_stages` | 0 | 7 |
| `markdown_violations` | 0 | 0 |
| `word_count` | 445 | 561 |
| `nl_word_count` | 269 | 324 |
| `distinct_1` | 0.4247 | 0.4474 |
| `distinct_2` | 0.7815 | 0.8107 |
| `output_truncated` | 1 | 1 |
| `nl_has_mitre_inline` | 1 | 1 |
| `graph_has_arrows` | 1 | 1 |

### P3: Stealth and Persistence (APT-Style)

| Metric | Baseline | Fine-Tuned |
|---|---:|---:|
| `sections_found` | 3 | 3 |
| `sections_in_order` | 1 | 1 |
| `all_sections_present` | 1 | 1 |
| `mitre_recall` | 1.0 | 1.0 |
| `mitre_precision` | 0.625 | 0.625 |
| `g_notation_exact` | 1 | 0 |
| `g_components_defined` | 5 | 5 |
| `arrow_count` | 7 | 4 |
| `numbered_stages` | 7 | 9 |
| `markdown_violations` | 0 | 0 |
| `word_count` | 427 | 591 |
| `nl_word_count` | 262 | 382 |
| `distinct_1` | 0.4614 | 0.489 |
| `distinct_2` | 0.7887 | 0.861 |
| `output_truncated` | 1 | 1 |
| `nl_has_mitre_inline` | 1 | 1 |
| `graph_has_arrows` | 1 | 0 |

### P4: Impact - Ransomware / Data Exfiltration

| Metric | Baseline | Fine-Tuned |
|---|---:|---:|
| `sections_found` | 3 | 3 |
| `sections_in_order` | 1 | 1 |
| `all_sections_present` | 1 | 1 |
| `mitre_recall` | 1.0 | 1.0 |
| `mitre_precision` | 0.833 | 0.714 |
| `g_notation_exact` | 1 | 0 |
| `g_components_defined` | 5 | 5 |
| `arrow_count` | 0 | 0 |
| `numbered_stages` | 7 | 9 |
| `markdown_violations` | 0 | 0 |
| `word_count` | 308 | 640 |
| `nl_word_count` | 190 | 386 |
| `distinct_1` | 0.487 | 0.4656 |
| `distinct_2` | 0.8241 | 0.8388 |
| `output_truncated` | 1 | 1 |
| `nl_has_mitre_inline` | 1 | 1 |
| `graph_has_arrows` | 0 | 0 |

## How to Interpret Results

| What you want to see | Why |
|---|---|
| Fine-tuned `sections_in_order = 1` on all prompts | Training enforced strict section ordering |
| Fine-tuned `mitre_recall` ≥ baseline | Fine-tuned should reference all input technique IDs |
| Fine-tuned `mitre_precision` ≥ baseline | Fine-tuned should not hallucinate MITRE IDs not in input |
| Fine-tuned `g_notation_exact = 1` | Exact G=(N,S,V,P,FS) notation was in every training sample |
| Fine-tuned `g_components_defined` = 5 | All 5 components should be separately defined |
| Fine-tuned `markdown_violations = 0` | Training explicitly forbade **, ##, etc. |
| Fine-tuned `nl_has_mitre_inline = 1` | Training required technique IDs inline in NL prose |
| Fine-tuned `graph_has_arrows = 1` | Training required -> arrows in attack graph |
| Fine-tuned `output_truncated = 0` | Output should reach a natural conclusion |
