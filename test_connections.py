#!/usr/bin/env python3
"""
Test with connection types that will actually create edges.
"""

from wazuh_parser import parse_wazuh_xml
from visualizations.flowchart import create_rule_network_visualization

def test_with_connection_types():
    """Test node display toggles with different connection types."""
    
    with open("sample_wazuh_rules.xml", "r", encoding="utf-8") as f:
        sample_xml = f.read()

    rules, warnings = parse_wazuh_xml(sample_xml)
    
    print(f"📊 Parsed {len(rules)} rules")
    
    # Test different connection types to see which ones create edges
    connection_types = ["if_sid", "if_matched_sid", "if_matched_group", "if_group"]
    
    for conn_type in connection_types:
        print(f"\n🔍 Testing connection type: {conn_type}")
        fig = create_rule_network_visualization(
            rules,
            connection_type=conn_type,
            show_desc_on_node=True,
            show_cond_on_node=True
        )
        
        if fig.data and len(fig.data) > 1:  # Has edges and nodes
            node_count = len(fig.data[-1].text) if hasattr(fig.data[-1], 'text') else 0
            edge_count = len(fig.data) - 1  # All traces except the last (nodes) are edges
            print(f"   ✅ Created visualization with {node_count} nodes and {edge_count} edges")
            
            # Test node display functionality
            if node_count > 0:
                node_text = fig.data[-1].text[0]
                lines = node_text.split("<br>")
                print(f"   📝 Node text: {lines[:3]}...")  # Show first 3 lines
        else:
            print(f"   ❌ No visualization created for {conn_type}")
    
    # Let's create our own test data with clear relationships
    print("\n🧪 Creating test data with clear if_sid relationships")
    test_xml = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
    <rule id="100" level="1">
        <description>Parent rule - web access</description>
        <field name="program">apache</field>
    </rule>
    <rule id="101" level="5">
        <if_sid>100</if_sid>
        <description>Child rule - suspicious web access</description>
        <match>suspicious</match>
    </rule>
    <rule id="102" level="10">
        <if_sid>101</if_sid>
        <description>Grandchild rule - critical web attack</description>
        <field name="user_agent">bot</field>
    </rule>
</rules>"""
    
    test_rules, _ = parse_wazuh_xml(test_xml)
    
    print(f"📊 Created {len(test_rules)} test rules")
    
    # Test with our test data
    fig = create_rule_network_visualization(
        test_rules,
        connection_type="if_sid",
        show_desc_on_node=True,
        show_cond_on_node=True
    )
    
    if fig.data and len(fig.data) > 1:
        node_trace = fig.data[-1]
        print(f"✅ Test visualization created with {len(node_trace.text)} nodes")
        
        # Test all toggle combinations
        for desc_toggle in [False, True]:
            for cond_toggle in [False, True]:
                print(f"\n🔧 Testing desc={desc_toggle}, cond={cond_toggle}")
                
                fig_test = create_rule_network_visualization(
                    test_rules,
                    connection_type="if_sid",
                    show_desc_on_node=desc_toggle,
                    show_cond_on_node=cond_toggle
                )
                
                if fig_test.data and len(fig_test.data) > 1:
                    node_text = fig_test.data[-1].text[0]  # First node
                    lines = node_text.split("<br>")
                    print(f"   📝 Lines: {len(lines)} - {lines}")
                    
                    # Validate line count
                    expected_lines = 1  # Rule ID always
                    if desc_toggle:
                        expected_lines += 1
                    if cond_toggle:
                        expected_lines += 1
                    
                    assert len(lines) == expected_lines, f"Expected {expected_lines} lines, got {len(lines)}"
                    
                    # Validate content
                    assert "100" in lines[0], "Missing Rule ID"
                    if desc_toggle:
                        assert "Parent rule" in lines[1], "Missing description"
                    if cond_toggle:
                        # Should have condition info
                        cond_line = lines[2] if desc_toggle else lines[1]
                        assert "field: apache" in cond_line, f"Missing condition info in '{cond_line}'"
                    
                    print(f"   ✅ Toggle test passed!")
    else:
        print("❌ Test visualization failed")
    
    print("\n🎉 Node display toggle testing completed!")

if __name__ == "__main__":
    test_with_connection_types()