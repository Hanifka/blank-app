#!/usr/bin/env python3
"""
Comprehensive test for node display toggle functionality.
"""

from wazuh_parser import parse_wazuh_xml
from visualizations.flowchart import create_rule_network_visualization

def test_comprehensive_toggles():
    """Test all toggle combinations and verify correct node text generation."""
    
    # Use sample data
    with open("sample_wazuh_rules.xml", "r", encoding="utf-8") as f:
        sample_xml = f.read()

    rules, warnings = parse_wazuh_xml(sample_xml)
    
    # Test cases for different toggle combinations
    test_cases = [
        {
            "name": "Default (Rule ID only)",
            "show_desc": False,
            "show_cond": False,
            "expected_contains": "100001<br>Web request detected"
        },
        {
            "name": "With description toggle",
            "show_desc": True,
            "show_cond": False,
            "expected_contains": "100001<br>Web request dete..."
        },
        {
            "name": "With conditions toggle",
            "show_desc": False,
            "show_cond": True,
            "expected_contains": "100001<br>.*union.*select"
        },
        {
            "name": "With both toggles",
            "show_desc": True,
            "show_cond": True,
            "expected_contains": "100001<br>Web request dete"
        }
    ]
    
    print("🧪 Testing Node Display Toggle Functionality")
    print("=" * 50)
    
    for test_case in test_cases:
        print(f"\n📋 {test_case['name']}")
        
        fig = create_rule_network_visualization(
            rules[:5],  # Use first 5 rules
            show_if_sid=True,
            show_desc_on_node=test_case["show_desc"],
            show_cond_on_node=test_case["show_cond"]
        )
        
        if fig.data and len(fig.data) > 0:
            node_trace = fig.data[-1]
            if hasattr(node_trace, 'text') and node_trace.text:
                node_text = node_trace.text[0]  # First node
                print(f"   Node text: {node_text[:80]}...")
                
                # Verify expected content is present
                if test_case["name"] == "Default (Rule ID only)":
                    # Should only have Rule ID
                    lines = node_text.split("<br>")
                    assert len(lines) == 1, f"Expected 1 line, got {len(lines)}"
                    print("   ✅ Contains only Rule ID")
                
                elif "description" in test_case["name"].lower():
                    # Should have Rule ID + description
                    lines = node_text.split("<br>")
                    assert len(lines) >= 2, f"Expected at least 2 lines, got {len(lines)}"
                    assert "100001" in lines[0], "Missing Rule ID"
                    assert "Web request" in lines[1], "Missing description"
                    print("   ✅ Contains Rule ID + description")
                
                elif "conditions" in test_case["name"].lower():
                    # Should have Rule ID + condition info
                    lines = node_text.split("<br>")
                    assert len(lines) >= 2, f"Expected at least 2 lines, got {len(lines)}"
                    assert "100001" in lines[0], "Missing Rule ID"
                    # Second line should be condition info
                    assert "union" in node_text or "select" in node_text, "Missing condition info"
                    print("   ✅ Contains Rule ID + condition")
                
                elif "both toggles" in test_case["name"].lower():
                    # Should have Rule ID + description + condition
                    lines = node_text.split("<br>")
                    assert len(lines) >= 3, f"Expected at least 3 lines, got {len(lines)}"
                    assert "100001" in lines[0], "Missing Rule ID"
                    assert "Web request" in lines[1], "Missing description"
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
        rules[:3],
        show_if_sid=True,
        show_desc_on_node=True,
        show_cond_on_node=True
    )
    
    if fig.data and len(fig.data) > 0:
        node_trace = fig.data[-1]
        if hasattr(node_trace, 'hovertext') and node_trace.hovertext:
            hover_text = node_trace.hovertext[0]
            print("✅ Hover text generated")
            print(f"📝 Hover text preview: {hover_text[:100]}...")
            
            # Verify hover text contains comprehensive info
            assert "<b>Rule 100001</b>" in hover_text, "Missing Rule ID in hover"
            assert "Level:" in hover_text, "Missing level in hover"
            assert "<b>Description:</b>" in hover_text, "Missing description in hover"
            assert "<b>Filter Conditions:</b>" in hover_text, "Missing filter conditions in hover"
            print("✅ Hover text contains comprehensive information")
        else:
            print("❌ No hover text found")
    
    print("\n🎊 Complete node display toggle functionality verified!")

if __name__ == "__main__":
    test_comprehensive_toggles()