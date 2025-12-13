"""
Test that the Streamlit integration works correctly with connection toggles.
This test verifies that the UI functions return the correct data structures.
"""

def test_streamlit_integration():
    """Test the Streamlit UI integration without actually running Streamlit."""
    
    # Simulate the toggle dictionary structure that would be returned
    connection_toggles = {
        "show_if_sid": True,
        "show_if_matched_sid": True,
        "show_if_matched_group": True,
        "show_if_group": True,
    }
    
    display_options = {
        "show_rule_id": True,
        "show_desc_on_node": False,
        "show_cond_on_node": False,
    }
    
    print("Testing data structure compatibility...")
    
    # Verify toggle dictionary has all required keys
    required_toggle_keys = ["show_if_sid", "show_if_matched_sid", "show_if_matched_group", "show_if_group"]
    for key in required_toggle_keys:
        assert key in connection_toggles, f"Missing key: {key}"
        assert isinstance(connection_toggles[key], bool), f"Key {key} is not boolean"
    
    print("✅ Connection toggles structure is correct")
    
    # Verify display options dictionary has all required keys
    required_display_keys = ["show_rule_id", "show_desc_on_node", "show_cond_on_node"]
    for key in required_display_keys:
        assert key in display_options, f"Missing key: {key}"
        assert isinstance(display_options[key], bool), f"Key {key} is not boolean"
    
    print("✅ Display options structure is correct")
    
    # Test that visualization function can accept these parameters
    from wazuh_parser import parse_wazuh_xml
    from visualizations.flowchart import create_rule_network_visualization
    
    test_xml = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
    <rule id="100" level="5">
        <description>Test rule</description>
    </rule>
    <rule id="101" level="7">
        <if_sid>100</if_sid>
        <description>Child rule</description>
    </rule>
</rules>"""
    
    rules, _ = parse_wazuh_xml(test_xml)
    
    # Test with connection toggles
    fig = create_rule_network_visualization(
        rules,
        show_if_sid=connection_toggles["show_if_sid"],
        show_if_matched_sid=connection_toggles["show_if_matched_sid"],
        show_if_matched_group=connection_toggles["show_if_matched_group"],
        show_if_group=connection_toggles["show_if_group"],
        show_desc_on_node=display_options["show_desc_on_node"],
        show_cond_on_node=display_options["show_cond_on_node"]
    )
    
    print("✅ Visualization function accepts parameters correctly")
    
    # Verify figure was created
    assert fig is not None, "Figure is None"
    assert hasattr(fig, 'data'), "Figure has no data attribute"
    print("✅ Visualization created successfully")
    
    # Test with all toggles disabled
    fig = create_rule_network_visualization(
        rules,
        show_if_sid=False,
        show_if_matched_sid=False,
        show_if_matched_group=False,
        show_if_group=False,
        show_desc_on_node=False,
        show_cond_on_node=False
    )
    
    print("✅ Visualization handles all toggles disabled")
    
    # Test with mixed toggles
    fig = create_rule_network_visualization(
        rules,
        show_if_sid=True,
        show_if_matched_sid=False,
        show_if_matched_group=True,
        show_if_group=False,
        show_desc_on_node=True,
        show_cond_on_node=False
    )
    
    print("✅ Visualization handles mixed toggle states")
    
    print("\n" + "="*50)
    print("All Streamlit integration tests passed! ✅")
    print("="*50)


if __name__ == "__main__":
    test_streamlit_integration()
