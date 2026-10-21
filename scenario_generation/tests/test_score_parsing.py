"""Tests for parsing the judge's score replies, well-formed and malformed."""

import judge_eval


WELL_FORMED = (
    '{"level_of_detail": 8, "technical_accuracy": 7, '
    '"realism": 9, "creativity": 6, "total": 30}'
)


# ── 1. Well-formed reply ──────────────────────────────────────────────────────

def test_parses_well_formed_reply():
    scores = judge_eval.parse_score_json(WELL_FORMED)
    assert judge_eval.is_scored(scores)
    assert scores == {
        "level_of_detail": 8,
        "technical_accuracy": 7,
        "realism": 9,
        "creativity": 6,
        "total": 30,
    }


def test_parses_reply_with_surrounding_prose():
    reply = "Sure! Here are the scores:\n" + WELL_FORMED + "\nHope that helps."
    scores = judge_eval.parse_score_json(reply)
    assert judge_eval.is_scored(scores)
    assert scores["total"] == 30


def test_string_valued_scores_are_coerced_to_int():
    scores = judge_eval.parse_score_json(
        '{"level_of_detail": "8", "technical_accuracy": "7", '
        '"realism": "9", "creativity": "6", "total": "30"}')
    assert judge_eval.is_scored(scores)
    assert scores["level_of_detail"] == 8
    assert scores["total"] == 30


def test_total_is_recomputed_when_the_judge_cannot_add(capsys):
    """Gemini's own arithmetic is not trusted — the sum is always recomputed."""
    scores = judge_eval.parse_score_json(
        '{"level_of_detail": 8, "technical_accuracy": 7, '
        '"realism": 9, "creativity": 6, "total": 99}')
    assert judge_eval.is_scored(scores)
    assert scores["total"] == 30
    assert "mismatch" in capsys.readouterr().out


def test_missing_total_is_computed():
    scores = judge_eval.parse_score_json(
        '{"level_of_detail": 1, "technical_accuracy": 2, '
        '"realism": 3, "creativity": 4}')
    assert judge_eval.is_scored(scores)
    assert scores["total"] == 10


# ── 2. Markdown-fenced reply ──────────────────────────────────────────────────

def test_parses_reply_wrapped_in_a_markdown_fence():
    reply = "```json\n" + WELL_FORMED + "\n```"
    scores = judge_eval.parse_score_json(reply)
    assert judge_eval.is_scored(scores)
    assert scores["total"] == 30


def test_fenced_and_unfenced_replies_parse_identically():
    assert (judge_eval.parse_score_json("```json\n" + WELL_FORMED + "\n```")
            == judge_eval.parse_score_json(WELL_FORMED))


# ── 3. Malformed replies must degrade, not crash ──────────────────────────────

MALFORMED = [
    ("prose only", "I am sorry, I cannot score this scenario."),
    ("empty string", ""),
    ("whitespace", "   \n  "),
    ("none", None),
    ("truncated json", '{"level_of_detail": 8, "technical_accuracy":'),
    ("missing criterion", '{"level_of_detail": 8, "realism": 9, "creativity": 6}'),
    ("non numeric criterion", '{"level_of_detail": "high", "technical_accuracy": 7, '
                              '"realism": 9, "creativity": 6, "total": 30}'),
    ("json list", "[8, 7, 9, 6]"),
    ("refusal with braces", "I can't help with that {sorry}"),
]


def test_malformed_replies_degrade_without_raising():
    for label, reply in MALFORMED:
        scores = judge_eval.parse_score_json(reply)          # must not raise
        assert not judge_eval.is_scored(scores), label
        assert scores["parse_error"], label
        # Shape stays usable so the caller can log/serialise it uniformly.
        assert set(judge_eval.SCORE_KEYS).issubset(scores), label
        assert scores["total"] == 0, label


def test_failed_scores_can_be_logged_like_real_scores(capsys):
    """log_scores must survive a degraded dict — it runs in the same loop."""
    judge_eval.log_scores("BASE scores", judge_eval.failed_scores("no JSON object"))
    assert "TOTAL= 0" in capsys.readouterr().out


def test_failed_scores_are_distinguishable_from_a_genuine_zero():
    """A parse failure must never be mistaken for a real (very bad) score."""
    genuine_zero = judge_eval.parse_score_json(
        '{"level_of_detail": 0, "technical_accuracy": 0, '
        '"realism": 0, "creativity": 0, "total": 0}')
    failure = judge_eval.failed_scores("no JSON object")
    assert genuine_zero["total"] == failure["total"] == 0
    assert judge_eval.is_scored(genuine_zero)
    assert not judge_eval.is_scored(failure)


# ── extract_json_block, the piece underneath ───────────────────────────────────

def test_extract_json_block_returns_none_instead_of_raising():
    assert judge_eval.extract_json_block("no braces here") is None
    assert judge_eval.extract_json_block("") is None
    assert judge_eval.extract_json_block(None) is None


def test_extract_json_block_strips_the_fence():
    assert judge_eval.extract_json_block("```json\n{\"a\": 1}\n```") == '{"a": 1}'
