#!/usr/bin/env python3
"""
Comprehensive test for node display toggle functionality.

This file is intentionally lightweight and uses the bundled sample XML.
"""

from wazuh_parser import parse_wazuh_xml
from visualizations.flowchart import create_rule_network_visualization


def _get_node_text_for_rule(fig, rule_id: int) -> str:
    """Nodes are split across one trace per severity band, so search them all."""
    for trace in fig.data:
        for text in getattr(trace, "text", None) or []:
            if str(rule_id) == str(text).split("<br>")[0]:
                return text
    raise AssertionError(f"Node text for rule {rule_id} not found")


def _get_node_hover_for_rule(fig, rule_id: int) -> str:
    for trace in fig.data:
        for hover in getattr(trace, "hovertext", None) or []:
            if f"<b>Rule {rule_id}</b>" in str(hover):
                return str(hover)
    raise AssertionError(f"Hover text for rule {rule_id} not found")


def test_comprehensive_toggles():
    """Test all toggle combinations and verify correct node text generation."""

    with open("sample_wazuh_rules.xml", "r", encoding="utf-8") as f:
        sample_xml = f.read()

    rules, warnings = parse_wazuh_xml(sample_xml)
    assert warnings == []

    test_cases = [
        ("Default (Rule ID only)", False, False),
        ("With description toggle", True, False),
        ("With conditions toggle", False, True),
        ("With both toggles", True, True),
    ]

    for name, show_desc, show_cond in test_cases:
        fig = create_rule_network_visualization(
            rules[:5],
            show_if_sid=True,
            show_desc_on_node=show_desc,
            show_cond_on_node=show_cond,
        )

        assert fig.data and len(fig.data) > 0

        if name in {"Default (Rule ID only)", "With description toggle"}:
            node_text = _get_node_text_for_rule(fig, 100001)
            lines = node_text.split("<br>")
            expected_lines = 1 + (1 if show_desc else 0)

            assert len(lines) == expected_lines
            assert lines[0] == "100001"
            if show_desc:
                assert "Web request" in lines[1]

        elif name == "With conditions toggle":
            node_text = _get_node_text_for_rule(fig, 100003)
            lines = node_text.split("<br>")
            assert len(lines) == 2
            assert lines[0] == "100003"
            assert "regex:" in lines[1]
            assert ("union" in lines[1]) or ("select" in lines[1])

        elif name == "With both toggles":
            node_text = _get_node_text_for_rule(fig, 100003)
            lines = node_text.split("<br>")
            assert len(lines) == 3
            assert lines[0] == "100003"
            assert "SQL injection" in lines[1]
            assert "regex:" in lines[2]

    # Hover text: verify it always includes full description and filter conditions when present
    fig = create_rule_network_visualization(
        rules[:5],
        show_if_sid=True,
        show_desc_on_node=True,
        show_cond_on_node=True,
    )
    assert fig.data and len(fig.data) > 0

    hover_text = _get_node_hover_for_rule(fig, 100003)

    assert "<b>Rule 100003</b>" in hover_text
    assert "level 6" in hover_text
    assert "SQL injection attempt detected" in hover_text
    assert "<b>Conditions:</b>" in hover_text
    # The hover also answers "what feeds this rule and what does it feed",
    # which is the whole point of the relationship view.
    assert "<b>Triggered by:</b>" in hover_text
    assert "<b>Feeds:</b>" in hover_text


if __name__ == "__main__":
    test_comprehensive_toggles()
