from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Environment(Enum):
    PROD = "prod"
    DEV = "dev"
    TEST = "test"


class CriticalityLevel(Enum):
    """
    Authored, tag-derived business/operational criticality of a
    resource -- independent of environment. A dev database seeded
    with production-like data can be more critical than a prod
    static-asset bucket; environment alone cannot express that,
    which is why this is a distinct field rather than inferred from
    Environment.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class ResourceMetadata:
    """
    Tag-derived attributes of a single resource, used as contextual
    input to the direct impact score.

    All three fields are tri-state (a real value, or None). None
    means "no matching tag found on this resource" -- untagged --
    which is NOT the same as an explicit False/LOW/etc. Unknown values
    are handled by the current impact rubric without being converted to
    explicit metadata. The distinction is preserved for reporting and
    future evidence-completeness analysis.
    """

    sensitive_data: Optional[bool] = None
    environment: Optional[Environment] = None

    asset_criticality: Optional[CriticalityLevel] = None

