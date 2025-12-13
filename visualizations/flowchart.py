"""
Flowchart visualization module for Wazuh rules using NetworkX and Plotly.

Provides interactive network visualizations showing rule relationships
with color-coding by severity levels and spring layout for node positioning.
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
    connection_type: str = 'if_sid',
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
    filtered_rules = [r for r in rules if r.level >= min_level]

    if selected_groups:
        filtered_rules = [r for r in filtered_rules if any(g in (r.groups or []) for g in selected_groups)]

    if not filtered_rules:
        return _create_empty_figure("No rules match the selected filters")

    G = nx.DiGraph()

    filtered_rule_ids = {r.rule_id for r in filtered_rules}

    for rule in filtered_rules:
        G.add_node(
            rule.rule_id,
            level=rule.level,
            description=rule.description,
            groups=rule.groups or []
        )

    # Precompute group->rules map once (used by if_matched_group / if_group)
    group_to_rules = defaultdict(list)
    for r in filtered_rules:
        for group in (r.groups or []):
            group_to_rules[group].append(r.rule_id)

    # Add edges based on chosen connection type
    for rule in filtered_rules:
        if connection_type == 'if_sid' and rule.detection_cues.if_sid:
            parent_id = rule.detection_cues.if_sid
            if parent_id in filtered_rule_ids:
                G.add_edge(parent_id, rule.rule_id, color='blue')

        elif connection_type == 'if_matched_group' and rule.detection_cues.if_matched_groups:
            for matched_group in rule.detection_cues.if_matched_groups:
                if matched_group in group_to_rules:
                    for source_rule_id in group_to_rules[matched_group]:
                        if source_rule_id != rule.rule_id:
                            G.add_edge(source_rule_id, rule.rule_id, color='green')

        elif connection_type == 'if_group' and getattr(rule.detection_cues, 'if_groups', None):
            for group_name in getattr(rule.detection_cues, 'if_groups', []):
                if group_name in group_to_rules:
                    for source_rule_id in group_to_rules[group_name]:
                        if source_rule_id != rule.rule_id:
                            G.add_edge(source_rule_id, rule.rule_id, color='orange')

    if not G.edges():
        return _create_empty_figure(_format_connection_empty_message(connection_type))

    pos = nx.spring_layout(G, k=2, iterations=50, seed=42)

    # --- EDGE TRACES (lines) ---
    edge_traces = []
    mid_x, mid_y = [], []

    for (source, target, data) in G.edges(data=True):
        x0, y0 = pos[source]
        x1, y1 = pos[target]

        edge_traces.append(
            go.Scatter(
                x=[x0, x1, None],
                y=[y0, y1, None],
                mode='lines',
                line=dict(width=2, color=data.get('color', 'gray')),
                hoverinfo='none',
                showlegend=False
            )
        )

        # midpoint for ">" direction marker
        mid_x.append((x0 + x1) / 2)
        mid_y.append((y0 + y1) / 2)

    # --- DIRECTION MARKERS (">" in the middle of each edge) ---
    direction_trace = go.Scatter(
        x=mid_x,
        y=mid_y,
        mode="text",
        text=[">"] * len(mid_x),
        textfont=dict(size=18, color="black"),
        hoverinfo="none",
        showlegend=False
    )

    # --- NODE TRACES ---
    node_x, node_y, node_text, node_color = [], [], [], []

    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)

        level = G.nodes[node]['level']
        description = G.nodes[node]['description']
        groups = G.nodes[node]['groups']
        groups_str = ', '.join(groups) if groups else 'None'

        node_text.append(f"Rule {node} (Level {level})<br>Description: {description}<br>Groups: {groups_str}")
        node_color.append(get_severity_color(level))

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode='markers+text',
        text=[str(n) for n in G.nodes()],
        textposition='top center',   # show ID above node
        textfont=dict(size=12, color='black'),  # visible on white bg
        hovertext=node_text,
        hoverinfo='text',
        marker=dict(
            size=18,
            color=node_color,
            line=dict(width=2, color='white')
        ),
        showlegend=False
    )

    fig = go.Figure(data=edge_traces + [direction_trace, node_trace])
    fig.update_layout(
        title='Wazuh Rule Relationships',
        showlegend=False,
        hovermode='closest',
        margin=dict(b=0, l=0, r=0, t=40),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        plot_bgcolor='white',
        height=700
    )

    return fig


def _create_empty_figure(message: str) -> go.Figure:
    """
    Create an empty Plotly figure with a message.
    """
    fig = go.Figure()
    fig.add_annotation(
        text=message,
        xref="paper",
        yref="paper",
        x=0.5,
        y=0.5,
        showarrow=False,
        font=dict(size=16, color="gray"),
    )
    fig.update_layout(
        title="No Data to Display",
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        plot_bgcolor="white",
        height=400,
        margin=dict(b=20, l=5, r=5, t=40),
    )
    return fig


def _format_connection_empty_message(connection_type: str) -> str:
    """Format empty message based on connection type."""
    if connection_type == "if_matched_group":
        return "No rules with if_matched_group connections found"
    elif connection_type == "if_group":
        return "No rules with if_group connections found"
    return "No rules with if_sid parent relationships found"
