import pytest

from risk_scoring.graph_model.graph_node import (
    GraphNode,
    NodeType,
)


class TestGraphNodeConstruction:

    def test_resource_node_constructs_successfully(self):
        node = GraphNode(
            id="bucket-1",
            node_type=NodeType.RESOURCE,
            requires_compromise=False,
        )

        assert node.id == "bucket-1"
        assert node.node_type == NodeType.RESOURCE
        assert node.requires_compromise is False

    def test_state_node_constructs_successfully(self):
        node = GraphNode(
            id="credential-exposed",
            node_type=NodeType.STATE,
            requires_compromise=True,
        )

        assert node.id == "credential-exposed"
        assert node.node_type == NodeType.STATE
        assert node.requires_compromise is True

    def test_boundary_node_constructs_successfully(self):
        node = GraphNode(
            id="internet",
            node_type=NodeType.BOUNDARY,
            requires_compromise=False,
        )

        assert node.id == "internet"
        assert node.node_type == NodeType.BOUNDARY
        assert node.requires_compromise is False

    def test_empty_id_is_rejected(self):
        with pytest.raises(
            ValueError,
            match="id must not be empty",
        ):
            GraphNode(
                id="",
                node_type=NodeType.RESOURCE,
                requires_compromise=False,
            )

    def test_whitespace_only_id_is_rejected(self):
        with pytest.raises(
            ValueError,
            match="id must not be empty",
        ):
            GraphNode(
                id="   ",
                node_type=NodeType.RESOURCE,
                requires_compromise=False,
            )

    def test_invalid_node_type_is_rejected(self):
        with pytest.raises(
            TypeError,
            match="node_type",
        ):
            GraphNode(
                id="bucket-1",
                node_type="resource",
                requires_compromise=False,
            )

    def test_non_boolean_requires_compromise_is_rejected(self):
        with pytest.raises(
            TypeError,
            match="requires_compromise",
        ):
            GraphNode(
                id="bucket-1",
                node_type=NodeType.RESOURCE,
                requires_compromise="false",
            )

    def test_boundary_node_cannot_require_compromise(self):
        with pytest.raises(
            ValueError,
            match="BOUNDARY nodes cannot have requires_compromise=True",
        ):
            GraphNode(
                id="internet",
                node_type=NodeType.BOUNDARY,
                requires_compromise=True,
            )


class TestGraphNodeImmutability:

    def test_graph_node_fields_are_immutable(self):
        node = GraphNode(
            id="bucket-1",
            node_type=NodeType.RESOURCE,
            requires_compromise=False,
        )

        with pytest.raises(AttributeError):
            node.id = "bucket-2"

        with pytest.raises(AttributeError):
            node.node_type = NodeType.STATE

        with pytest.raises(AttributeError):
            node.requires_compromise = True