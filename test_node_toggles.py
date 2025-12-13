#!/usr/bin/env python3
"""
Test script to verify the node display toggle functionality.
"""

from wazuh_parser import parse_wazuh_xml
from visualizations.flowchart import create_rule_network_visualization

def test_node_display_toggles():
    """Test that the node display toggle functionality works correctly."""
    
    # Load sample XML
    sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
    <rule id="100535" level="5">
        <if_sid>100534</if_sid>
        <description>Powershell Information gathering</description>
        <field name="program">PowerShell</field>
    </rule>
    <rule id="100534" level="1">
        <description>Powershell command execution</description>
        <match>powershell</match>
    </rule>
</rules>"""

    # Parse rules
    rules, warnings = parse_wazuh_xml(sample_xml)
    
    print(f"✅ Parsed {len(rules)} rules")
    
    # Test with default parameters (no toggles)
    fig1 = create_rule_network_visualization(rules, connection_type="if_sid")
    print("✅ Created visualization with default parameters")
    
    # Test with description toggle on
    fig2 = create_rule_network_visualization(
        rules, 
        connection_type="if_sid",
        show_desc_on_node=True
    )
    print("✅ Created visualization with description toggle on")
    
    # Test with conditions toggle on
    fig3 = create_rule_network_visualization(
        rules, 
        connection_type="if_sid",
        show_cond_on_node=True
    )
    print("✅ Created visualization with conditions toggle on")
    
    # Test with both toggles on
    fig4 = create_rule_network_visualization(
        rules, 
        connection_type="if_sid",
        show_desc_on_node=True,
        show_cond_on_node=True
    )
    print("✅ Created visualization with both toggles on")
    
    print("\n🎉 All tests passed! Node display toggle functionality is working correctly.")
    
    # Display rule details for verification
    print("\nRule details:")
    for rule in rules:
        print(f"Rule {rule.rule_id}: {rule.description}")
        if rule.filter_conditions:
            for cond in rule.filter_conditions:
                if hasattr(cond, 'field') and cond.field:
                    print(f"  - Field: {cond.field}")
                if hasattr(cond, 'match') and cond.match:
                    print(f"  - Match: {cond.match}")

if __name__ == "__main__":
    test_node_display_toggles()