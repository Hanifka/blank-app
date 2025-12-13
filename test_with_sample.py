#!/usr/bin/env python3
"""
Test script to verify the node display toggle functionality with real sample data.
"""

from wazuh_parser import parse_wazuh_xml
from visualizations.flowchart import create_rule_network_visualization

def test_with_sample_data():
    """Test with the actual sample data file."""
    
    # Load sample XML file
    with open("sample_wazuh_rules.xml", "r", encoding="utf-8") as f:
        sample_xml = f.read()

    # Parse rules
    rules, warnings = parse_wazuh_xml(sample_xml)
    
    print(f"✅ Parsed {len(rules)} rules from sample file")
    
    if warnings:
        print(f"⚠️ Warnings: {len(warnings)} warnings")
    
    # Find rules with filter conditions for testing
    rules_with_filters = [r for r in rules if r.filter_conditions]
    print(f"📊 {len(rules_with_filters)} rules have filter conditions")
    
    # Test with description toggle on
    print("\n📋 Testing visualization with description toggle...")
    fig = create_rule_network_visualization(
        rules[:10],  # Use first 10 rules for testing
        connection_type="if_sid",
        show_desc_on_node=True,
        show_cond_on_node=True
    )
    
    # Check node text content by examining the figure data
    if fig.data and len(fig.data) > 0:
        node_trace = fig.data[-1]  # Last trace should be nodes
        if hasattr(node_trace, 'text') and node_trace.text:
            print("✅ Node text generated successfully")
            print(f"📊 Number of nodes: {len(node_trace.text)}")
            
            # Show first node text as example
            if node_trace.text:
                print("📝 Example node text:")
                print(f"   {node_trace.text[0]}")
        
        if hasattr(node_trace, 'hovertext') and node_trace.hovertext:
            print("✅ Hover text generated successfully")
            print("📝 Example hover text:")
            print(f"   {node_trace.hovertext[0][:100]}...")
    
    print("\n🎉 Sample data test completed successfully!")
    
    # Show some example rule details
    print("\n🔍 Sample rule details:")
    for i, rule in enumerate(rules[:3]):
        print(f"Rule {rule.rule_id}: {rule.description[:50]}...")
        if rule.filter_conditions:
            for j, cond in enumerate(rule.filter_conditions[:2]):
                if hasattr(cond, 'field') and cond.field:
                    print(f"  Condition {j+1} field: {cond.field[:30]}")
                if hasattr(cond, 'match') and cond.match:
                    print(f"  Condition {j+1} match: {cond.match[:30]}")

if __name__ == "__main__":
    test_with_sample_data()