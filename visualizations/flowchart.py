"""
Flowchart visualization module for Wazuh rules using NetworkX and Plotly.

Provides interactive network visualizations showing rule relationships
with color-coding by severity levels and spring layout for node positioning.

This version:
- Uses a black background for better contrast.
- Shows rule IDs clearly in white.
- Uses real Plotly arrow annotations (vector direction) instead of ">" text.
"""

from typing import List, Optional
from collections import defaultdict

import networkx as nx
import plotly.graph_objects as go
from wazuh_parser import RuleData


def get_severity_color(level: int) -> str:
    """Return color code for severity level."""
    if level >= 10:
        return "red"
    elif level >= 5:
        return "orange"
    else:
        return "green"


def create_rule_network_visualization(
    rules: List[RuleData],
    connection_type: str = "if_sid",
    min_level: int = 0,
    selected_groups: Optional[List[str]] = None,
) -> go.Figure:
    """
    Create an interactive network visualization using NetworkX and Plotly with spring layout.

    Args:
        rules: List of RuleData objects to visualize
        connection_type: Relationship type to visualize ("if_sid", "if_matched_group", or "if_group")
        min_level: Minimum severity level to include
        selected_groups: Optional list of groups to filter by

    Returns:
        Plotly Figure object for interactive visualization
    """

    # ---- Filter rules ----
    filtered_rules = [r for r in rules if r.level >= min_level]

    if selected_groups:
        filtered_rules = [
            r for r in filtered_rules
            if any(g in (r.groups or []) for g in selected_groups)
        ]

    if not filtered_rules:
        return _create_empty_figure("No rules match the selected filters")

    # ---- Build graph ----
    G = nx.DiGraph()
    filtered_rule_ids = {r.rule_id for r in filtered_rules}

    for rule in filtered_rules:
        G.add_node(
            rule.rule_id,
            level=rule.level,
            description=rule.description,
            groups=rule.groups or [],
        )

    # Precompute group -> rules map once
    group_to_rules = defaultdict(list)
    for r in filtered_rules:
        for group in (r.groups or []):
            group_to_rules[group].append(r.rule_id)

    # Add edges based on connection type
    for rule in filtered_rules:
        if connection_type == "if_sid" and rule.detection_cues.if_sid:
            parent_id = rule.detection_cues.if_sid
            if parent_id in filtered_rule_ids:
                G.add_edge(parent_id, rule.rule_id, color="blue")

        elif connection_type == "if_matched_group" and rule.detection_cues.if_matched_groups:
            for matc
