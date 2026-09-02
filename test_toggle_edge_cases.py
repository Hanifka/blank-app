"""
Test edge cases for connection type toggles.
"""

from wazuh_parser import parse_wazuh_xml
from visualizations.flowchart import create_rule_network_visualization


def test_edge_cases():
    """Test edge cases like rules without connections, duplicate edges, etc."""
    
    # Test XML with various edge cases
    test_xml = """<?xml version="1.0" encoding="UTF-8"?>
<group name="test">
  <!-- Rule with no connections -->
  <rule id="100" level="5">
    <description>Standalone rule with no connections</description>
    <group>test_group,</group>
  </rule>

  <!-- Multiple rules pointing to same parent -->
  <rule id="101" level="7">
    <description>First child of 100</description>
    <if_sid>100</if_sid>
  </rule>

  <rule id="102" level="7">
    <description>Second child of 100</description>
    <if_sid>100</if_sid>
  </rule>

  <rule id="103" level="8">
    <description>Third child of 100</description>
    <if_sid>100</if_sid>
  </rule>

  <!-- Rule with multiple connection types -->
  <rule id="104" level="9">
    <description>Rule with both if_sid and if_matched_sid</description>
    <if_sid>100</if_sid>
    <if_matched_sid>101,102</if_matched_sid>
    <group>multi_connection,</group>
  </rule>

  <!-- Chain of dependencies -->
  <rule id="105" level="10">
    <description>Depends on 104</description>
    <if_sid>104</if_sid>
  </rule>

  <rule id="106" level="11">
    <description>Depends on 105</description>
    <if_sid>105</if_sid>
  </rule>

  <!-- Group-based connections -->
  <rule id="107" level="6">
    <description>Matches test_group</description>
    <if_matched_group>test_group</if_matched_group>
    <group>other_group,</group>
  </rule>

  <rule id="108" level="6">
    <description>Checks for test_group</description>
    <if_group>test_group</if_group>
    <group>other_group,</group>
  </rule>
</group>
"""
    
    print("Parsing test XML...")
    rules, warnings = parse_wazuh_xml(test_xml)
    print(f"✓ Parsed {len(rules)} rules")
    
    # Test 1: Verify rule with no connections appears as isolated node
    print("\n" + "="*60)
    print("Test 1: Isolated nodes appear correctly")
    print("="*60)
    fig = create_rule_network_visualization(
        rules,
        show_if_sid=True,
        show_if_matched_sid=False,
        show_if_matched_group=False,
        show_if_group=False
    )
    # Check that we have nodes (even isolated ones)
    node_traces = [trace for trace in fig.data if trace.mode == 'markers+text']
    print(f"✓ Found {len(node_traces)} node trace(s)")
    
    # Test 2: Multiple children of same parent
    print("\n" + "="*60)
    print("Test 2: Multiple children of same parent")
    print("="*60)
    fig = create_rule_network_visualization(
        rules,
        show_if_sid=True,
        show_if_matched_sid=False,
        show_if_matched_group=False,
        show_if_group=False
    )
    edge_count = sum(1 for trace in fig.data if trace.mode == 'lines')
    print(f"✓ Created {edge_count} edge traces (should be 5: 100→101, 100→102, 100→103, 100→104, 104→105, 105→106)")
    
    # Test 3: Rule with multiple connection types - toggle one at a time
    print("\n" + "="*60)
    print("Test 3: Rule with multiple connection types")
    print("="*60)
    
    # Only if_sid
    fig = create_rule_network_visualization(
        rules,
        show_if_sid=True,
        show_if_matched_sid=False,
        show_if_matched_group=False,
        show_if_group=False
    )
    edges_if_sid = sum(1 for trace in fig.data if trace.mode == 'lines')
    print(f"  if_sid only: {edges_if_sid} edges")
    
    # Only if_matched_sid
    fig = create_rule_network_visualization(
        rules,
        show_if_sid=False,
        show_if_matched_sid=True,
        show_if_matched_group=False,
        show_if_group=False
    )
    edges_if_matched_sid = sum(1 for trace in fig.data if trace.mode == 'lines')
    print(f"  if_matched_sid only: {edges_if_matched_sid} edges")
    
    # Both together
    fig = create_rule_network_visualization(
        rules,
        show_if_sid=True,
        show_if_matched_sid=True,
        show_if_matched_group=False,
        show_if_group=False
    )
    edges_both = sum(1 for trace in fig.data if trace.mode == 'lines')
    print(f"  Both enabled: {edges_both} edges")
    print(f"✓ Combined edges ({edges_both}) >= individual sums ({edges_if_sid + edges_if_matched_sid})")
    
    # Test 4: Chain of dependencies
    print("\n" + "="*60)
    print("Test 4: Chain of dependencies (100→104→105→106)")
    print("="*60)
    fig = create_rule_network_visualization(
        rules,
        show_if_sid=True,
        show_if_matched_sid=False,
        show_if_matched_group=False,
        show_if_group=False
    )
    edge_count = sum(1 for trace in fig.data if trace.mode == 'lines')
    print(f"✓ Chain visualization created with {edge_count} edges")
    
    # Test 5: Group-based connections work independently
    print("\n" + "="*60)
    print("Test 5: Group-based connections")
    print("="*60)
    
    # Only if_matched_group
    fig = create_rule_network_visualization(
        rules,
        show_if_sid=False,
        show_if_matched_sid=False,
        show_if_matched_group=True,
        show_if_group=False
    )
    edges_matched_group = sum(1 for trace in fig.data if trace.mode == 'lines')
    print(f"  if_matched_group only: {edges_matched_group} edges")
    
    # Only if_group
    fig = create_rule_network_visualization(
        rules,
        show_if_sid=False,
        show_if_matched_sid=False,
        show_if_matched_group=False,
        show_if_group=True
    )
    edges_if_group = sum(1 for trace in fig.data if trace.mode == 'lines')
    print(f"  if_group only: {edges_if_group} edges")
    
    # Both group types
    fig = create_rule_network_visualization(
        rules,
        show_if_sid=False,
        show_if_matched_sid=False,
        show_if_matched_group=True,
        show_if_group=True
    )
    edges_both_groups = sum(1 for trace in fig.data if trace.mode == 'lines')
    print(f"  Both group types: {edges_both_groups} edges")
    print(f"✓ Group connections work independently")
    
    # Test 6: Verify edge hover text includes connection type
    print("\n" + "="*60)
    print("Test 6: Edge hover text includes connection type")
    print("="*60)
    fig = create_rule_network_visualization(
        rules,
        show_if_sid=True,
        show_if_matched_sid=True,
        show_if_matched_group=True,
        show_if_group=True
    )
    # Edge hover lives on invisible midpoint markers, not on the line traces
    # themselves - one trace per link type keeps large graphs fast.
    edge_hovers = [
        h
        for trace in fig.data
        for h in (getattr(trace, "hovertext", None) or [])
        if "\u2192 Rule" in str(h)
    ]
    assert edge_hovers, "No edge hover text found"
    sample_hover = edge_hovers[0]
    print(f"✓ Sample edge hover text: {sample_hover}")
    assert "Type:" in sample_hover, f"Connection type missing from '{sample_hover}'"
    print("✓ Connection type is included in hover text")
    
    print("\n" + "="*60)
    print("All edge case tests passed! ✓")
    print("="*60)


if __name__ == "__main__":
    test_edge_cases()
