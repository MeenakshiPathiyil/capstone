from dataclasses import dataclass
from enum import Enum


class NodeType(Enum):
    """
    Types of nodes in the Security State Graph.
    """

    RESOURCE = "resource"
    STATE = "state"
    BOUNDARY = "boundary"


class ReachabilityClass(Enum):
    """
    Classification of how a resource is reachable from the
    external boundary.

    DIRECT:
        The resource is directly reachable from the boundary.

    VIA_PATH:
        The resource is reachable through one or more graph
        relationships without a prior compromised node.

    POST_COMPROMISE:
        The resource becomes reachable after a preceding node
        requiring compromise has been reached.
    """

    DIRECT = "direct"
    VIA_PATH = "via_path"
    POST_COMPROMISE = "post_compromise"


@dataclass(frozen=True)
class GraphNode:
    """
    A typed node in the Security State Graph.

    GraphNode contains intrinsic node-level properties only.

    Graph relationships and reachability are handled by the graph
    and graph-analysis layers. In particular, whether a resource
    is externally reachable is determined by its topology relative
    to the BOUNDARY node rather than stored as a node property.
    """

    id: str
    node_type: NodeType
    requires_compromise: bool

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id.strip():
            raise ValueError(
                "id must not be empty."
            )

        if not isinstance(self.node_type, NodeType):
            raise TypeError(
                "node_type must be a NodeType."
            )

        if not isinstance(self.requires_compromise, bool):
            raise TypeError(
                "requires_compromise must be a bool."
            )

        if (
            self.node_type == NodeType.BOUNDARY
            and self.requires_compromise
        ):
            raise ValueError(
                "BOUNDARY nodes cannot have requires_compromise=True."
            )