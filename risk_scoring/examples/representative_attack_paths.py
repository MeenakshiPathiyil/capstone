"""Representative attack-path contexts for the scoring tests.

The first four are paths the pipeline finds in sample_yamls/cloudformation5.yml,
with the inputs pipeline_adapter.py derives for them (the template has no tags,
so their metadata is unknown). The last is the same direct S3 path as if its
bucket were tagged as critical production data.
"""

from risk_scoring.graph_model.resource_metadata import CriticalityLevel, Environment
from risk_scoring.models.path_scoring_input import PathScoringInput
from risk_scoring.multipliers.reach_multiplier import ReachabilityClass


def _sample(path_id, reachability, path_length, downstream, criticality=None,
            sensitive=None, environment=None):
    return PathScoringInput(
        path_id=path_id,
        asset_criticality=criticality,
        sensitive_data=sensitive,
        environment=environment,
        reachable_downstream_count=downstream,
        graph_median_reachable=5.0,
        reachability_class=reachability,
        path_length=path_length,
    )


SCENARIOS = [
    {
        "name": "AP-001: open security group to a public S3 bucket, 4 hops",
        "input": _sample("AP-001", ReachabilityClass.DIRECT, 4, 0),
    },
    {
        "name": "AP-006: foothold on an instance to an over-permissive role, 3 hops",
        "input": _sample("AP-006", ReachabilityClass.POST_COMPROMISE, 3, 3),
    },
    {
        "name": "AP-015: denial of service on a public instance, 1 hop",
        "input": _sample("AP-015", ReachabilityClass.DIRECT, 1, 5),
    },
    {
        "name": "AP-019: denial of service on the app server, 1 hop",
        "input": _sample("AP-019", ReachabilityClass.DIRECT, 1, 7),
    },
    {
        "name": "AP-001 if its bucket were tagged critical production data",
        "input": _sample("AP-001-tagged", ReachabilityClass.DIRECT, 4, 0,
                         CriticalityLevel.HIGH, True, Environment.PROD),
    },
]
