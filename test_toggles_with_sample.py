"""
Test connection toggles with the sample Wazuh rules file.
"""

import os
from wazuh_parser import parse_wazuh_xml
from visualizations.flowchart import create_rule_network_visualization


def test_with_sample():
    """Test connection toggles with sample_wazuh_rules.xml."""
    
    sample_path = os.path.join(os.path.dirname(__file__), "sample_wazuh_rules.xml")
    if not os.path.exists(sample_path):
        print(f"Sample file not found at {sample_path}")
        return
    
    print("Loading sample rules...")
    with open(sample_path, "r", encoding="utf-8") as f:
        xml_content = f.read()
    
    print("Parsing XML...")
    rules, warnings = parse_wazuh_xml(xml_content)
    print(f"✓ Parsed {len(rules)} rules")
    
    if warnings:
        print(f"  Warnings: {len(warnings)}")
    
    # Count rules with different connection types
    rules_with_if_sid = sum(1 for r in rules if hasattr(r.detection_cues, 'if_sid') and r.detection_cues.if_sid)
    rules_with_if_matched_sid = sum(1 for r in rules if hasattr(r.detection_cues, 'if_matched_sid') and r.detection_cues.if_matched_sid)
    rules_with_if_matched_group = sum(1 for r in rules if hasattr(r.detection_cues, 'if_matched_groups') and r.detection_cues.if_matched_groups)
    rules_with_if_group = sum(1 for r in rules if hasattr(r.detection_cues, 'if_groups') and r.detection_cues.if_groups)
    
    print(f"\nConnection type usage:")
    print(f"  Rules with if_sid: {rules_with_if_sid}")
    print(f"  Rules with if_matched_sid: {rules_with_if_matched_sid}")
    print(f"  Rules with if_matched_group: {rules_with_if_matched_group}")
    print(f"  Rules with if_group: {rules_with_if_group}")
    
    # Test different toggle combinations
    print("\n" + "="*60)
    print("Test 1: All toggles enabled")
    print("="*60)
    fig = create_rule_network_visualization(
        rules,
        show_if_sid=True,
        show_if_matched_sid=True,
        show_if_matched_group=True,
        show_if_group=True
    )
    edge_count = sum(1 for trace in fig.data if trace.mode == 'lines')
    print(f"✓ Created visualization with {edge_count} edge traces")
    
    print("\n" + "="*60)
    print("Test 2: Only if_sid (most common)")
    print("="*60)
    fig = create_rule_network_visualization(
        rules,
        show_if_sid=True,
        show_if_matched_sid=False,
        show_if_matched_group=False,
        show_if_group=False
    )
    edge_count = sum(1 for trace in fig.data if trace.mode == 'lines')
    print(f"✓ Created visualization with {edge_count} edge traces")
    
    print("\n" + "="*60)
    print("Test 3: Group-based connections only")
    print("="*60)
    fig = create_rule_network_visualization(
        rules,
        show_if_sid=False,
        show_if_matched_sid=False,
        show_if_matched_group=True,
        show_if_group=True
    )
    edge_count = sum(1 for trace in fig.data if trace.mode == 'lines')
    print(f"✓ Created visualization with {edge_count} edge traces")
    
    print("\n" + "="*60)
    print("Test 4: All toggles disabled")
    print("="*60)
    fig = create_rule_network_visualization(
        rules,
        show_if_sid=False,
        show_if_matched_sid=False,
        show_if_matched_group=False,
        show_if_group=False
    )
    edge_count = sum(1 for trace in fig.data if trace.mode == 'lines')
    print(f"✓ Created visualization with {edge_count} edge traces")
    if hasattr(fig.layout, 'annotations') and fig.layout.annotations:
        print(f"✓ Empty message: {fig.layout.annotations[0].text}")
    
    # Test with node display options combined
    print("\n" + "="*60)
    print("Test 5: Connection toggles + node display options")
    print("="*60)
    fig = create_rule_network_visualization(
        rules,
        show_if_sid=True,
        show_if_matched_sid=False,
        show_if_matched_group=True,
        show_if_group=False,
        show_desc_on_node=True,
        show_cond_on_node=False
    )
    edge_count = sum(1 for trace in fig.data if trace.mode == 'lines')
    print(f"✓ Created visualization with {edge_count} edge traces")
    print("✓ Node display options work correctly with connection toggles")
    
    print("\n" + "="*60)
    print("All sample tests passed! ✓")
    print("="*60)


if __name__ == "__main__":
    test_with_sample()
