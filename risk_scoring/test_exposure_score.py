import pytest

from risk_scoring.multipliers.reach_multiplier import ReachabilityClass
from risk_scoring.scoring.exposure_score import compute_exposure_score


@pytest.mark.parametrize(
    ("reachability_class", "expected"),
    [
        (ReachabilityClass.DIRECT, 90.0),
        (ReachabilityClass.VIA_PATH, 65.0),
        (ReachabilityClass.POST_COMPROMISE, 40.0),
    ],
)
def test_reachability_class_maps_to_documented_exposure_score(
    reachability_class, expected
):
    assert compute_exposure_score(reachability_class) == expected


def test_direct_reachability_has_highest_exposure_score():
    direct = compute_exposure_score(ReachabilityClass.DIRECT)
    via_path = compute_exposure_score(ReachabilityClass.VIA_PATH)
    post_compromise = compute_exposure_score(
        ReachabilityClass.POST_COMPROMISE
    )

    assert direct > via_path > post_compromise


@pytest.mark.parametrize("invalid", ["direct", None, 1, True])
def test_invalid_reachability_class_is_rejected(invalid):
    with pytest.raises(TypeError, match="reachability_class must be ReachabilityClass"):
        compute_exposure_score(invalid)


def test_exposure_score_is_within_expected_range():
    for reachability_class in ReachabilityClass:
        score = compute_exposure_score(reachability_class)
        assert 1.0 <= score <= 100.0
