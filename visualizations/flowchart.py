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
    show_if_sid: bool = True,
    show_if_matched_sid: bool = True,
    show_if_matched_group: bool = True,
    show_if_group: bool = True,
    min_level: int = 0,
    selected_groups: Optional[List[str]] = None,
    show_desc_on_node: bool = False,
    show_cond_on_node: bool = False,
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
    if show_if_matched_group or show_if_group:
        group_to_rules = defaultdict(list)
        for r in filtered_rules:
            for group in (getattr(r, "groups", None) or []):
                group_to_rules[group].append(r.rule_id)

    # ---- Add edges based on enabled connection types ----
    for rule in filtered_rules:
        cues = getattr(rule, "detection_cues", None)

        if show_if_sid:
            parent_id = getattr(cues, "if_sid", None) if cues else None
            if parent_id and parent_id in filtered_rule_ids:
                G.add_edge(parent_id, rule.rule_id, color="blue", type="if_sid")

        if show_if_matched_sid:
            matched_sids = getattr(cues, "if_matched_sid", []) if cues else []
            for parent_id in matched_sids:
                if parent_id in filtered_rule_ids:
                    G.add_edge(parent_id, rule.rule_id, color="yellow", type="if_matched_sid")

        if show_if_matched_group:
            matched_groups = getattr(cues, "if_matched_groups", None) if cues else None
            if matched_groups and group_to_rules:
                for mg in matched_groups:
                    if mg in group_to_rules:
                        for src in group_to_rules[mg]:
                            if src != rule.rule_id:
                                G.add_edge(src, rule.rule_id, color="green", type="if_matched_group")

        if show_if_group:
            if_groups = getattr(cues, "if_groups", None) if cues else None
            if if_groups and group_to_rules:
                for gname in if_groups:
                    if gname in group_to_rules:
                        for src in group_to_rules[gname]:
                            if src != rule.rule_id:
                                G.add_edge(src, rule.rule_id, color="orange", type="if_group")

    if not G.edges():
        enabled_types = []
        if show_if_sid:
            enabled_types.append("if_sid")
        if show_if_matched_sid:
            enabled_types.append("if_matched_sid")
        if show_if_matched_group:
            enabled_types.append("if_matched_group")
        if show_if_group:
            enabled_types.append("if_group")
        return _create_empty_figure(_format_connection_empty_message(enabled_types))

    # ---- Layout ----
    pos = nx.spring_layout(G, k=2, iterations=50, seed=42)

    # ---- Edges (lines) ----
    edge_traces = []
    edges_for_arrows = []  # (x0,y0,x1,y1,color)

    for (source, target, data) in G.edges(data=True):
        x0, y0 = pos[source]
        x1, y1 = pos[target]
        color = data.get("color", "gray")
        edge_type = data.get("type", "unknown")
        
        # Create hover text with connection type
        type_labels = {
            "if_sid": "Parent Rule",
            "if_matched_sid": "Matched Rule",
            "if_matched_group": "Group Correlation",
            "if_group": "Group Rule"
        }
        type_label = type_labels.get(edge_type, edge_type)
        hover_text = f"Rule {source} → Rule {target}<br>Type: {type_label}"

        edge_traces.append(
            go.Scatter(
                x=[x0, x1, None],
                y=[y0, y1, None],
                mode="lines",
                line=dict(width=2, color=color),
                hovertext=hover_text,
                hoverinfo="text",
                showlegend=False,
            )
        )
        edges_for_arrows.append((x0, y0, x1, y1, color))

    # ---- Nodes ----
    node_x, node_y, node_text, node_hover_text, node_color = [], [], [], [], []

    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)

        level = G.nodes[node].get("level", 0)
        description = G.nodes[node].get("description", "")
        groups = G.nodes[node].get("groups", []) or []
        
        # Create rule lookup for comprehensive hover text and condition display
        rule = next((r for r in filtered_rules if r.rule_id == node), None)
        
        # Build node text based on toggle settings
        text_lines = [str(node)]  # Rule ID always first
        
        if show_desc_on_node and description:
            desc = description[:20] + "..." if len(description) > 20 else description
            text_lines.append(desc)
        
        if show_cond_on_node and rule and getattr(rule, 'filter_conditions', None):
            conditions = rule.filter_conditions
            if conditions:
                cond = conditions[0]
                if hasattr(cond, 'field') and cond.field:
                    cond_text = f"field: {cond.field[:15]}"
                elif hasattr(cond, 'match') and cond.match:
                    cond_text = f"match: {cond.match[:15]}"
                elif hasattr(cond, 'frequency') and cond.frequency:
                    cond_text = f"frequency: {cond.frequency}"
                else:
                    cond_text = "filter condition"
                text_lines.append(cond_text)
        
        node_display_text = "<br>".join(text_lines)
        node_text.append(node_display_text)
        
        # Create comprehensive hover text (always shows full info)
        if rule:
            hover_text = f"<b>Rule {rule.rule_id}</b><br>"
            hover_text += f"Level: {rule.level}<br>"
            hover_text += f"<b>Description:</b><br>{rule.description}<br>"
            
            if rule.filter_conditions:
                hover_text += "<b>Filter Conditions:</b><br>"
                for cond in rule.filter_conditions[:2]:  # Show up to 2 conditions
                    if hasattr(cond, 'field') and cond.field:
                        hover_text += f"• Field: {cond.field}<br>"
                    if hasattr(cond, 'match') and cond.match:
                        hover_text += f"• Match: {cond.match}<br>"
                    if hasattr(cond, 'frequency') and cond.frequency:
                        hover_text += f"• Frequency: {cond.frequency}<br>"
        else:
            # Fallback hover text if rule lookup fails
            groups_str = ", ".join(groups) if groups else "None"
            hover_text = (
                f"Rule {node} (Level {level})<br>"
                f"Description: {description}<br>"
                f"Groups: {groups_str}"
            )
        
        node_hover_text.append(hover_text)
        node_color.append(get_severity_color(level))

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode="markers+text",
        text=node_text,
        textposition="top center",
        textfont=dict(size=12, color="white"),
        hovertext=node_hover_text,
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


def _format_connection_empty_message(enabled_types: List[str]) -> str:
    """Format empty message based on enabled connection types."""
    if not enabled_types:
        return "No connection types enabled. Please enable at least one connection type."
    
    if len(enabled_types) == 1:
        type_messages = {
            "if_sid": "No rules with if_sid parent relationships found",
            "if_matched_sid": "No rules with if_matched_sid connections found",
            "if_matched_group": "No rules with if_matched_group connections found",
            "if_group": "No rules with if_group connections found"
        }
        return type_messages.get(enabled_types[0], "No rule connections found")
    
    return f"No rules with {', '.join(enabled_types)} connections found"
