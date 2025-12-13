"""
Flowchart visualization module for Wazuh rules using NetworkX and Plotly.

- Black background so labels are visible
- Rule IDs in white
- Real arrowheads (vector direction) using Plotly annotations
- Safe getattr() access so missing detection_cues fields won't crash
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
    if level >= 5:
        return "orange"
    return "green"


def create_rule_network_visualization(
    rules: List[RuleData],
    connection_type: str = "if_sid",
    min_level: int = 0,
    selected_groups: Optional[List[str]] = None,
) -> go.Figure:
    # ---- Filter rules ----
    filtered_rules = [r for r in rules if getattr(r, "level", 0) >= min_level]

    if selected_groups:
        filtered_rules = [
            r for r in filtered_rules
            if any(g in (getattr(r, "groups", None) or []) for g in selected_groups)
        ]

    if not filtered_rules:
        return _create_empty_figure("No rules match the selected filters")

    filtered_rule_ids = {r.rule_id for r in filtered_rules}

    # ---- Build graph ----
    G = nx.DiGraph()

    for rule in filtered_rules:
        G.add_node(
            rule.rule_id,
            level=getattr(rule, "level", 0),
            description=getattr(rule, "description", "") or "",
            groups=getattr(rule, "groups", None) or [],
        )

    # Build group_to_rules only if needed
    group_to_rules = None
    if connection_type in ("if_matched_group", "if_group"):
        group_to_rules = defaultdict(list)
        for r in filtered_rules:
            for group in (getattr(r, "groups", None) or []):
                group_to_rules[group].append(r.rule_id)

    # ---- Add edges based on connection type ----
    for rule in filtered_rules:
        cues = getattr(rule, "detection_cues", None)

        if connection_type == "if_sid":
            parent_id = getattr(cues, "if_sid", None) if cues else None
            if parent_id and parent_id in filtered_rule_ids:
                G.add_edge(parent_id, rule.rule_id, color="blue")

        elif connection_type == "if_matched_group":
            matched_groups = getattr(cues, "if_matched_groups", None) if cues else None
            if matched_groups and group_to_rules:
                for mg in matched_groups:
                    if mg in group_to_rules:
                        for src in group_to_rules[mg]:
                            if src != rule.rule_id:
                                G.add_edge(src, rule.rule_id, color="green")

        elif connection_type == "if_group":
            if_groups = getattr(cues, "if_groups", None) if cues else None
            if if_groups and group_to_rules:
                for gname in if_groups:
                    if gname in group_to_rules:
                        for src in group_to_rules[gname]:
                            if src != rule.rule_id:
                                G.add_edge(src, rule.rule_id, color="orange")

    if not G.edges():
        return _create_empty_figure(_format_connection_empty_message(connection_type))

    # ---- Layout ----
    pos = nx.spring_layout(G, k=2, iterations=50, seed=42)

    # ---- Edges (lines) ----
    edge_traces = []
    edges_for_arrows = []  # (x0,y0,x1,y1,color)

    for (source, target, data) in G.edges(data=True):
        x0, y0 = pos[source]
        x1, y1 = pos[target]
        color = data.get("color", "gray")

        edge_traces.append(
            go.Scatter(
                x=[x0, x1, None],
                y=[y0, y1, None],
                mode="lines",
                line=dict(width=2, color=color),
                hoverinfo="none",
                showlegend=False,
            )
        )
        edges_for_arrows.append((x0, y0, x1, y1, color))

    # ---- Nodes ----
    node_x, node_y, node_text, node_color = [], [], [], []

    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)

        level = G.nodes[node].get("level", 0)
        description = G.nodes[node].get("description", "")
        groups = G.nodes[node].get("groups", []) or []
        groups_str = ", ".join(groups) if groups else "None"

        node_text.append(
            f"Rule {node} (Level {level})<br>"
            f"Description: {description}<br>"
            f"Groups: {groups_str}"
        )
        node_color.append(get_severity_color(level))

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode="markers+text",
        text=[str(n) for n in G.nodes()],
        textposition="top center",
        textfont=dict(size=12, color="white"),
        hovertext=node_text,
        hoverinfo="text",
        marker=dict(
            size=16,
            color=node_color,
            line=dict(width=2, color="white"),
        ),
        showlegend=False,
    )

    # ---- Figure ----
    fig = go.Figure(data=edge_traces + [node_trace])
    fig.update_layout(
        title="Wazuh Rule Relationships",
        showlegend=False,
        hovermode="closest",
        margin=dict(b=0, l=0, r=0, t=40),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        plot_bgcolor="black",
        paper_bgcolor="black",
        font=dict(color="white"),
        height=700,
    )

    # ---- Arrowheads (vector direction) ----
    # Put arrowhead near the target, not inside the node marker
    for (x0, y0, x1, y1, color) in edges_for_arrows:
        xa = x0 + 0.90 * (x1 - x0)
        ya = y0 + 0.90 * (y1 - y0)
        xb = x0 + 0.78 * (x1 - x0)
        yb = y0 + 0.78 * (y1 - y0)

        fig.add_annotation(
            x=xa, y=ya,
            ax=xb, ay=yb,
            xref="x", yref="y",
            axref="x", ayref="y",
            showarrow=True,
            arrowhead=3,
            arrowsize=1.2,
            arrowwidth=2,
            arrowcolor="white",  # change to `color` if you want match edge color
            opacity=0.95,
        )

    return fig


def _create_empty_figure(message: str) -> go.Figure:
    """Create an empty Plotly figure with a message."""
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
        plot_bgcolor="black",
        paper_bgcolor="black",
        font=dict(color="white"),
        height=400,
        margin=dict(b=20, l=5, r=5, t=40),
    )
    return fig


def _format_connection_empty_message(connection_type: str) -> str:
    """Format empty message based on connection type."""
    if connection_type == "if_matched_group":
        return "No rules with if_matched_group connections found"
    if connection_type == "if_group":
        return "No rules with if_group connections found"
    return "No rules with if_sid parent relationships found"
