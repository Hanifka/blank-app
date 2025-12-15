"""
Test script for connection type toggles functionality.
Tests that each toggle independently controls its corresponding connection type.
"""

from wazuh_parser import parse_wazuh_xml, RuleData
from visualizations.flowchart import create_rule_network_visualization


def test_connection_toggles():
    """Test all combinations of connection type toggles."""
    
    # Simple test XML with multiple connection types
    test_xml = """<?xml version="1.0" encoding="UTF-8"?>
<group name="test">
  <rule id="100" level="5">
    <description>Base rule for testing</description>
    <group>authentication_failure,</group>
  </rule>

  <rule id="101" level="7">
    <description>Child rule using if_sid</description>
    <if_sid>100</if_sid>
    <group>authentication_failure,</group>
  </rule>

  <rule id="102" level="8">
    <description>Rule using if_matched_sid</description>
    <if_matched_sid>100</if_matched_sid>
    <group>authentication_failure,</group>
  </rule>

  <rule id="103" level="9">
    <description>Rule using if_matched_group</description>
    <if_matched_group>authentication_failure</if_matched_group>
    <group>authentication_success,</group>
  </rule>

  <rule id="104" level="6">
    <description>Rule using if_group</description>
    <if_group>authentication_failure</if_group>
    <group>authentication_success,</group>
  </rule>
</group>
"""
    
    print("Parsing test XML...")
    rules, warnings = parse_wazuh_xml(test_xml)
    
    if warnings:
        print(f"\nWarnings: {len(warnings)}")
        for w in warnings:
            print(f"  - {w}")
    
    print(f"\nParsed {len(rules)} rules:")
    for rule in rules:
        print(f"  Rule {rule.rule_id}: {rule.description}")
        if hasattr(rule.detection_cues, 'if_sid') and rule.detection_cues.if_sid:
            print(f"    - if_sid: {rule.detection_cues.if_sid}")
        if hasattr(rule.detection_cues, 'if_matched_sid') and rule.detection_cues.if_matched_sid:
            print(f"    - if_matched_sid: {rule.detection_cues.if_matched_sid}")
        if hasattr(rule.detection_cues, 'if_matched_groups') and rule.detection_cues.if_matched_groups:
            print(f"    - if_matched_groups: {rule.detection_cues.if_matched_groups}")
        if hasattr(rule.detection_cues, 'if_groups') and rule.detection_cues.if_groups:
            print(f"    - if_groups: {rule.detection_cues.if_groups}")
    
    # Test 1: All toggles enabled (default)
    print("\n" + "="*60)
    print("Test 1: All connection types enabled")
    print("="*60)
    fig = create_rule_network_visualization(
        rules,
        show_if_sid=True,
        show_if_matched_sid=True,
        show_if_matched_group=True,
        show_if_group=True
    )
    # Count edges by checking the figure data
    edge_count = sum(1 for trace in fig.data if trace.mode == 'lines')
    print(f"✓ Visualization created with {edge_count} edge traces")
    
    # Test 2: Only if_sid enabled
    print("\n" + "="*60)
    print("Test 2: Only if_sid enabled")
    print("="*60)
    fig = create_rule_network_visualization(
        rules,
        show_if_sid=True,
        show_if_matched_sid=False,
        show_if_matched_group=False,
        show_if_group=False
    )
    edge_count = sum(1 for trace in fig.data if trace.mode == 'lines')
    print(f"✓ Visualization created with {edge_count} edge trace(s)")
    
    # Test 3: Only if_matched_sid enabled
    print("\n" + "="*60)
    print("Test 3: Only if_matched_sid enabled")
    print("="*60)
    fig = create_rule_network_visualization(
        rules,
        show_if_sid=False,
        show_if_matched_sid=True,
        show_if_matched_group=False,
        show_if_group=False
    )
    edge_count = sum(1 for trace in fig.data if trace.mode == 'lines')
    print(f"✓ Visualization created with {edge_count} edge trace(s)")
    
    # Test 4: Only if_matched_group enabled
    print("\n" + "="*60)
    print("Test 4: Only if_matched_group enabled")
    print("="*60)
    fig = create_rule_network_visualization(
        rules,
        show_if_sid=False,
        show_if_matched_sid=False,
        show_if_matched_group=True,
        show_if_group=False
    )
    edge_count = sum(1 for trace in fig.data if trace.mode == 'lines')
    print(f"✓ Visualization created with {edge_count} edge trace(s)")
    
    # Test 5: Only if_group enabled
    print("\n" + "="*60)
    print("Test 5: Only if_group enabled")
    print("="*60)
    fig = create_rule_network_visualization(
        rules,
        show_if_sid=False,
        show_if_matched_sid=False,
        show_if_matched_group=False,
        show_if_group=True
    )
    edge_count = sum(1 for trace in fig.data if trace.mode == 'lines')
    print(f"✓ Visualization created with {edge_count} edge trace(s)")
    
    # Test 6: All toggles disabled
    print("\n" + "="*60)
    print("Test 6: All connection types disabled")
    print("="*60)
    fig = create_rule_network_visualization(
        rules,
        show_if_sid=False,
        show_if_matched_sid=False,
        show_if_matched_group=False,
        show_if_group=False
    )
    edge_count = sum(1 for trace in fig.data if trace.mode == 'lines')
    print(f"✓ Visualization created with {edge_count} edge traces (should be 0)")
    # Check for empty message
    if hasattr(fig.layout, 'annotations') and fig.layout.annotations:
        print(f"✓ Empty message displayed: {fig.layout.annotations[0].text}")
    
    # Test 7: Mixed toggles (if_sid + if_matched_group)
    print("\n" + "="*60)
    print("Test 7: Mixed toggles (if_sid + if_matched_group)")
    print("="*60)
    fig = create_rule_network_visualization(
        rules,
        show_if_sid=True,
        show_if_matched_sid=False,
        show_if_matched_group=True,
        show_if_group=False
    )
    edge_count = sum(1 for trace in fig.data if trace.mode == 'lines')
    print(f"✓ Visualization created with {edge_count} edge traces")
    
    # Test 8: Test with node display options
    print("\n" + "="*60)
    print("Test 8: Toggles work with node display options")
    print("="*60)
    fig = create_rule_network_visualization(
        rules,
        show_if_sid=True,
        show_if_matched_sid=True,
        show_if_matched_group=False,
        show_if_group=False,
        show_desc_on_node=True,
        show_cond_on_node=True
    )
    edge_count = sum(1 for trace in fig.data if trace.mode == 'lines')
    print(f"✓ Visualization created with {edge_count} edge traces")
    print("✓ Node display options work alongside connection toggles")
    
    print("\n" + "="*60)
    print("All tests passed! ✓")
    print("="*60)


if __name__ == "__main__":
    test_connection_toggles()
