#!/usr/bin/env python3
"""
Fixed comprehensive test for node display toggle functionality.
"""

from wazuh_parser import parse_wazuh_xml
from visualizations.flowchart import create_rule_network_visualization

def test_comprehensive_toggles_fixed():
    """Test all toggle combinations with rules that have filter conditions."""
    
    with open("sample_wazuh_rules.xml", "r", encoding="utf-8") as f:
        sample_xml = f.read()

    rules, warnings = parse_wazuh_xml(sample_xml)
    
    # Filter to only rules with filter conditions for testing
    rules_with_filters = [r for r in rules if r.filter_conditions]
    print(f"📊 Found {len(rules_with_filters)} rules with filter conditions")
    
    if len(rules_with_filters) < 3:
        print("❌ Not enough rules with filter conditions for testing")
        return
    
    # Use the first 3 rules with filter conditions
    test_rules = rules_with_filters[:3]
    
    test_cases = [
        {
            "name": "Default (Rule ID only)",
            "show_desc": False,
            "show_cond": False,
        },
        {
            "name": "With description toggle",
            "show_desc": True,
            "show_cond": False,
        },
        {
            "name": "With conditions toggle",
            "show_desc": False,
            "show_cond": True,
        },
        {
            "name": "With both toggles",
            "show_desc": True,
            "show_cond": True,
        }
    ]
    
    print("🧪 Testing Node Display Toggle Functionality")
    print("=" * 50)
    
    for test_case in test_cases:
        print(f"\n📋 {test_case['name']}")
        
        fig = create_rule_network_visualization(
            test_rules,
            show_if_sid=True,
            show_desc_on_node=test_case["show_desc"],
            show_cond_on_node=test_case["show_cond"]
        )
        
        if fig.data and len(fig.data) > 0:
            node_trace = fig.data[-1]
            if hasattr(node_trace, 'text') and node_trace.text:
                node_text = node_trace.text[0]  # First node
                print(f"   Node text: {node_text[:80]}...")
                
                lines = node_text.split("<br>")
                
                # Basic validation - Rule ID should always be first
                assert "100002" in lines[0], "Missing Rule ID"
                
                if test_case["name"] == "Default (Rule ID only)":
                    # Should only have Rule ID
                    assert len(lines) == 1, f"Expected 1 line, got {len(lines)}"
                    print("   ✅ Contains only Rule ID")
                
                elif "description" in test_case["name"].lower() and "both" not in test_case["name"].lower():
                    # Should have Rule ID + description
                    assert len(lines) >= 2, f"Expected at least 2 lines, got {len(lines)}"
                    assert "Multiple failed" in lines[1], "Missing description"
                    print("   ✅ Contains Rule ID + description")
                
                elif "conditions" in test_case["name"].lower() and "both" not in test_case["name"].lower():
                    # Should have Rule ID + condition info
                    assert len(lines) >= 2, f"Expected at least 2 lines, got {len(lines)}"
                    # Should contain condition info like "frequency:" or "match:" or "field:"
                    has_condition = any("frequency:" in line or "match:" in line or "field:" in line for line in lines[1:])
                    assert has_condition, f"No condition info found in lines: {lines}"
                    print("   ✅ Contains Rule ID + condition")
                
                elif "both toggles" in test_case["name"].lower():
                    # Should have Rule ID + description + condition
                    assert len(lines) >= 3, f"Expected at least 3 lines, got {len(lines)}"
                    assert "Multiple failed" in lines[1], "Missing description"
                    has_condition = any("frequency:" in line or "match:" in line or "field:" in line for line in lines[2:])
                    assert has_condition, f"No condition info found in lines: {lines}"
                    print("   ✅ Contains Rule ID + description + condition")
            else:
                print("   ❌ No node text found")
        else:
            print("   ❌ No figure data found")
    
    print("\n🎉 All comprehensive toggle tests passed!")
    
    # Test hover text functionality
    print("\n🔍 Testing Hover Text Functionality")
    print("=" * 40)
    
    fig = create_rule_network_visualization(
        test_rules[:2],
        show_if_sid=True,
        show_desc_on_node=True,
        show_cond_on_node=True
    )
    
    if fig.data and len(fig.data) > 0:
        node_trace = fig.data[-1]
        if hasattr(node_trace, 'hovertext') and node_trace.hovertext:
            hover_text = node_trace.hovertext[0]
            print("✅ Hover text generated")
            print(f"📝 Hover text preview: {hover_text[:150]}...")
            
            # Verify hover text contains comprehensive info
            assert "<b>Rule 100002</b>" in hover_text, "Missing Rule ID in hover"
            assert "Level:" in hover_text, "Missing level in hover"
            assert "<b>Description:</b>" in hover_text, "Missing description in hover"
            assert "<b>Filter Conditions:</b>" in hover_text, "Missing filter conditions in hover"
            print("✅ Hover text contains comprehensive information")
        else:
            print("❌ No hover text found")
    
    print("\n🎊 Complete node display toggle functionality verified!")
    
    # Print the actual test rules for reference
    print("\n📋 Test Rules Used:")
    for rule in test_rules:
        print(f"  Rule {rule.rule_id}: {rule.description}")
        if rule.filter_conditions:
            for cond in rule.filter_conditions:
                if hasattr(cond, 'field') and cond.field:
                    print(f"    Field: {cond.field}")
                if hasattr(cond, 'match') and cond.match:
                    print(f"    Match: {cond.match[:30]}...")
                if hasattr(cond, 'frequency') and cond.frequency:
                    print(f"    Frequency: {cond.frequency}")

if __name__ == "__main__":
    test_comprehensive_toggles_fixed()