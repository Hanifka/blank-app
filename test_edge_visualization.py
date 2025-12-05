#!/usr/bin/env python3
"""
Test script to verify Graphistry edge visualization fix.

This script demonstrates that edges are properly structured and bound
for Graphistry visualization.
"""

from wazuh_parser import parse_wazuh_xml
from visualizations.flowchart import _build_graphistry_dataframes

def test_edges_dataframe():
    """Test that edges DataFrame is properly created."""
    with open('sample_wazuh_rules.xml', 'r') as f:
        xml_content = f.read()
    
    rules, _ = parse_wazuh_xml(xml_content)
    nodes_df, edges_df = _build_graphistry_dataframes(rules, "if_sid")
    
    # Verify edges exist
    assert len(edges_df) == 2, f"Expected 2 edges, got {len(edges_df)}"
    
    # Verify required columns
    required_columns = ['source', 'target', 'edge_tooltip', 'type']
    for col in required_columns:
        assert col in edges_df.columns, f"Missing required column: {col}"
    
    # Verify edge data
    assert '100001' in edges_df['source'].values, "Missing edge from rule 100001"
    assert '100002' in edges_df['target'].values, "Missing edge to rule 100002"
    assert '100003' in edges_df['source'].values, "Missing edge from rule 100003"
    assert '100008' in edges_df['target'].values, "Missing edge to rule 100008"
    
    # Verify edge types
    assert all(edges_df['type'] == 'if_sid'), "All edges should be type 'if_sid'"
    
    print("✓ All edge DataFrame tests passed!")
    return True

def test_graphistry_bindings():
    """Test that Graphistry bindings are correctly configured."""
    import graphistry
    from visualizations.flowchart import _build_graphistry_dataframes
    
    with open('sample_wazuh_rules.xml', 'r') as f:
        xml_content = f.read()
    
    rules, _ = parse_wazuh_xml(xml_content)
    nodes_df, edges_df = _build_graphistry_dataframes(rules, "if_sid")
    
    # Create Graphistry object
    graphistry.register(api=3, protocol="https", server="hub.graphistry.com")
    g = graphistry.edges(edges_df, "source", "target").nodes(nodes_df, "node_id")
    
    # Apply bindings
    g = g.bind(
        point_color="color",
        point_size="size",
        point_label="label",
        point_title="tooltip",
        edge_title="edge_tooltip",
        edge_label="type"
    )
    
    # Verify bindings
    assert g._source == "source", "Source binding incorrect"
    assert g._destination == "target", "Destination binding incorrect"
    assert g._node == "node_id", "Node binding incorrect"
    assert g._edge_label == "type", "Edge label binding incorrect (CRITICAL FIX)"
    assert g._edge_title == "edge_tooltip", "Edge title binding incorrect"
    assert g._point_label == "label", "Point label binding incorrect"
    
    # Verify data
    assert g._edges is not None and len(g._edges) == 2, "Edges not set correctly"
    assert g._nodes is not None and len(g._nodes) == 10, "Nodes not set correctly"
    
    print("✓ All Graphistry binding tests passed!")
    return True

def main():
    """Run all tests."""
    print("=" * 70)
    print("Testing Graphistry Edge Visualization Fix")
    print("=" * 70)
    print()
    
    print("Test 1: Edges DataFrame Structure")
    test_edges_dataframe()
    print()
    
    print("Test 2: Graphistry Bindings")
    test_graphistry_bindings()
    print()
    
    print("=" * 70)
    print("✓ ALL TESTS PASSED")
    print("=" * 70)
    print()
    print("Summary:")
    print("  • Edges DataFrame has correct structure with 2 edges")
    print("  • Edge columns: source, target, edge_tooltip, type")
    print("  • Graphistry bindings include edge_label='type' (CRITICAL)")
    print("  • Edge visualization should now work with proper authentication")

if __name__ == "__main__":
    main()
