"""
Flowchart visualization module for Wazuh rules.

Provides Plotly-based visualizations showing Detection → Filter → Rule Level
transitions with color-coding by severity levels, hover tooltips, and 
interactive controls for layout customization.
"""

from typing import List, Dict, Set, Tuple, Optional, Any
import plotly.graph_objects as go
from wazuh_parser import RuleData, FilterCondition, summarize_filter_logic


def get_severity_color(level: int) -> str:
    """Return color code for severity level."""
    if level == 0:
        return "#808080"
    elif level <= 3:
        return "#28a745"
    elif level <= 6:
        return "#ffc107"
    elif level <= 9:
        return "#fd7e14"
    else:
        return "#dc3545"


def get_severity_label(level: int) -> str:
    """Return severity classification based on Wazuh level."""
    if level == 0:
        return "Ignored"
    elif level <= 3:
        return "Low"
    elif level <= 6:
        return "Medium"
    elif level <= 9:
        return "High"
    else:
        return "Critical"


def create_sankey_diagram(
    rules: List[RuleData],
    min_level: int = 0,
    layout_density: str = "normal",
) -> go.Figure:
    """
    Create a Sankey diagram showing Detection → Filter → Rule Level transitions.
    
    Args:
        rules: List of RuleData objects to visualize
        min_level: Minimum severity level to include (0-15)
        layout_density: Layout density mode ("compact", "normal", "sparse")
    
    Returns:
        Plotly Figure object ready for rendering
    """
    # Filter rules by minimum level
    filtered_rules = [r for r in rules if r.level >= min_level]
    
    if not filtered_rules:
        return _create_empty_figure("No rules match the selected severity level")
    
    # Collect detection sources
    detection_sources: Set[str] = set()
    for rule in filtered_rules:
        if rule.detection_cues.decoded_as:
            detection_sources.add(rule.detection_cues.decoded_as)
        elif rule.detection_cues.if_sid:
            detection_sources.add(f"Rule {rule.detection_cues.if_sid}")
        else:
            detection_sources.add("Pattern Matching")
    
    # Build node and flow structure
    nodes, node_indices = _build_sankey_nodes(
        filtered_rules, detection_sources, layout_density
    )
    source, target, value, colors, hover_text = _build_sankey_flows(
        filtered_rules, nodes, node_indices
    )
    
    # Create Sankey diagram
    fig = go.Figure(
        data=[
            go.Sankey(
                node=dict(
                    pad=15 if layout_density == "sparse" else 10,
                    thickness=20 if layout_density == "compact" else 25,
                    line=dict(color="white", width=1),
                    color=colors["nodes"],
                    customdata=nodes,
                    hovertemplate="%{customdata}<extra></extra>",
                ),
                link=dict(
                    source=source,
                    target=target,
                    value=value,
                    color=colors["links"],
                    customdata=hover_text,
                    hovertemplate="%{customdata}<extra></extra>",
                ),
            )
        ]
    )
    
    height = 600 if layout_density == "compact" else 700
    
    fig.update_layout(
        title="Wazuh Rule Detection Flow: Detection Source → Filters → Severity",
        font=dict(size=11),
        height=height,
        margin=dict(l=10, r=10, t=50, b=10),
        paper_bgcolor="#f8f9fa",
        plot_bgcolor="#f8f9fa",
    )
    
    return fig


def create_node_link_diagram(
    rules: List[RuleData],
    min_level: int = 0,
    layout_type: str = "hierarchical",
) -> go.Figure:
    """
    Create a node-link diagram showing rule relationships.
    
    Args:
        rules: List of RuleData objects to visualize
        min_level: Minimum severity level to include (0-15)
        layout_type: Layout type ("hierarchical", "circular", "radial")
    
    Returns:
        Plotly Figure object ready for rendering
    """
    # Filter rules by minimum level
    filtered_rules = [r for r in rules if r.level >= min_level]
    
    if not filtered_rules:
        return _create_empty_figure("No rules match the selected severity level")
    
    # Build node positions and connections
    nodes_dict, edges = _build_node_link_structure(filtered_rules, layout_type)
    
    # Create coordinates
    pos = _calculate_positions(nodes_dict, layout_type)
    
    # Extract node and edge information
    node_labels = list(nodes_dict.keys())
    node_colors = [nodes_dict[n]["color"] for n in node_labels]
    node_sizes = [nodes_dict[n]["size"] for n in node_labels]
    node_hover = [nodes_dict[n]["hover"] for n in node_labels]
    
    # Create edge traces
    edge_traces = []
    for edge in edges:
        edge_traces.append(
            go.Scatter(
                x=[pos[edge[0]][0], pos[edge[1]][0]],
                y=[pos[edge[0]][1], pos[edge[1]][1]],
                mode="lines",
                line=dict(width=1, color="rgba(125,125,125,0.5)"),
                hoverinfo="none",
                showlegend=False,
            )
        )
    
    # Create node trace
    node_trace = go.Scatter(
        x=[pos[n][0] for n in node_labels],
        y=[pos[n][1] for n in node_labels],
        mode="markers+text",
        hovertext=node_hover,
        hoverinfo="text",
        text=[n.split("|")[0][:15] for n in node_labels],
        textposition="top center",
        textfont=dict(size=9),
        showlegend=False,
        marker=dict(
            size=node_sizes,
            color=node_colors,
            line=dict(width=2, color="white"),
        ),
    )
    
    # Create figure
    fig = go.Figure(data=edge_traces + [node_trace])
    
    fig.update_layout(
        title="Rule Relationship Network",
        showlegend=False,
        hovermode="closest",
        margin=dict(b=0, l=0, r=0, t=40),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        plot_bgcolor="white",
        height=600,
    )
    
    return fig


def _create_empty_figure(message: str) -> go.Figure:
    """Create an empty placeholder figure with a message."""
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
        title="No Data Available",
        height=400,
        showlegend=False,
        hovermode=False,
    )
    return fig


def _build_sankey_nodes(
    rules: List[RuleData],
    detection_sources: Set[str],
    layout_density: str,
) -> Tuple[List[str], Dict[str, int]]:
    """
    Build nodes for Sankey diagram.
    
    Returns:
        Tuple of (node_labels, node_indices_dict)
    """
    nodes = []
    node_indices = {}
    
    # Add detection source nodes
    for source in sorted(detection_sources):
        if source not in node_indices:
            node_indices[source] = len(nodes)
            nodes.append(source)
    
    # Add filter category nodes
    filter_types = set()
    for rule in rules:
        if rule.filter_conditions:
            for cond in rule.filter_conditions:
                if cond.match:
                    filter_types.add("Pattern Match")
                if cond.field:
                    filter_types.add("Field Filter")
                if cond.frequency:
                    filter_types.add("Frequency")
                if cond.no_alert:
                    filter_types.add("No Alert")
                if cond.ignore:
                    filter_types.add("Ignore Pattern")
    
    if layout_density != "compact" or filter_types:
        for filter_type in sorted(filter_types):
            if filter_type not in node_indices:
                node_indices[filter_type] = len(nodes)
                nodes.append(f"Filter: {filter_type}")
    
    # Add severity level nodes
    for rule in rules:
        severity = get_severity_label(rule.level)
        node_label = f"{severity} (L{rule.level})"
        if node_label not in node_indices:
            node_indices[node_label] = len(nodes)
            nodes.append(node_label)
    
    return nodes, node_indices


def _build_sankey_flows(
    rules: List[RuleData],
    nodes: List[str],
    node_indices: Dict[str, int],
) -> Tuple[List[int], List[int], List[int], Dict[str, List], List[str]]:
    """
    Build flows (edges) for Sankey diagram.
    
    Returns:
        Tuple of (source_indices, target_indices, values, colors, hover_texts)
    """
    source = []
    target = []
    value = []
    hover_text = []
    
    # Track flow counts for aggregation
    flow_counts: Dict[Tuple[int, int], int] = {}
    flow_descriptions: Dict[Tuple[int, int], str] = {}
    
    for rule in rules:
        # Determine detection source
        if rule.detection_cues.decoded_as:
            detection = rule.detection_cues.decoded_as
        elif rule.detection_cues.if_sid:
            detection = f"Rule {rule.detection_cues.if_sid}"
        else:
            detection = "Pattern Matching"
        
        detection_idx = node_indices[detection]
        severity = get_severity_label(rule.level)
        severity_node = f"{severity} (L{rule.level})"
        severity_idx = node_indices[severity_node]
        
        # Build flow: detection → filter (if exists) → severity
        if rule.filter_conditions:
            # Route through filter nodes
            filter_summary = summarize_filter_logic(rule.filter_conditions)
            
            for cond in rule.filter_conditions:
                filter_label = None
                if cond.match:
                    filter_label = "Filter: Pattern Match"
                elif cond.field:
                    filter_label = "Filter: Field Filter"
                elif cond.frequency:
                    filter_label = "Filter: Frequency"
                elif cond.no_alert:
                    filter_label = "Filter: No Alert"
                elif cond.ignore:
                    filter_label = "Filter: Ignore Pattern"
                
                if filter_label and filter_label in node_indices:
                    filter_idx = node_indices[filter_label]
                    
                    # Detection → Filter
                    flow_key = (detection_idx, filter_idx)
                    flow_counts[flow_key] = flow_counts.get(flow_key, 0) + 1
                    flow_descriptions[flow_key] = f"{detection} → {filter_label}"
                    
                    # Filter → Severity
                    flow_key = (filter_idx, severity_idx)
                    flow_counts[flow_key] = flow_counts.get(flow_key, 0) + 1
                    flow_descriptions[flow_key] = (
                        f"Rule {rule.rule_id}: {rule.description[:30]}...\n"
                        f"{filter_summary}"
                    )
        else:
            # Direct flow: detection → severity
            flow_key = (detection_idx, severity_idx)
            flow_counts[flow_key] = flow_counts.get(flow_key, 0) + 1
            flow_descriptions[flow_key] = (
                f"Rule {rule.rule_id}: {rule.description[:40]}"
            )
    
    # Convert aggregated flows to lists
    for (src, tgt), count in flow_counts.items():
        source.append(src)
        target.append(tgt)
        value.append(count)
        hover_text.append(flow_descriptions[(src, tgt)])
    
    # Assign colors based on target severity
    link_colors = []
    for tgt_idx in target:
        tgt_node = nodes[tgt_idx]
        try:
            if "(L" in tgt_node and ")" in tgt_node:
                # Extract level from format like "Critical (L15)"
                level_str = tgt_node.split("(L")[1].split(")")[0]
                level = int(level_str)
                color = get_severity_color(level)
                link_colors.append(_hex_to_rgba(color, 0.4))
            else:
                link_colors.append("rgba(100,100,100,0.3)")
        except (ValueError, IndexError):
            link_colors.append("rgba(100,100,100,0.3)")
    
    node_colors = [get_severity_color_for_node(node) for node in nodes]
    
    colors = {"nodes": node_colors, "links": link_colors}
    
    return source, target, value, colors, hover_text


def _build_node_link_structure(
    rules: List[RuleData],
    layout_type: str,
) -> Tuple[Dict[str, Dict[str, Any]], List[Tuple[str, str]]]:
    """
    Build nodes and edges for node-link diagram.
    
    Returns:
        Tuple of (nodes_dict, edges_list)
    """
    nodes_dict = {}
    edges = []
    
    # Add rule nodes
    for rule in rules:
        node_id = f"Rule {rule.rule_id}|{rule.description[:20]}"
        severity = get_severity_label(rule.level)
        color = get_severity_color(rule.level)
        
        nodes_dict[node_id] = {
            "color": color,
            "size": 15 + rule.level,
            "hover": (
                f"<b>Rule {rule.rule_id}</b><br>"
                f"<b>Severity:</b> {severity} (L{rule.level})<br>"
                f"<b>Description:</b> {rule.description[:60]}"
            ),
        }
    
    # Add edges for parent-child relationships
    for rule in rules:
        rule_id = f"Rule {rule.rule_id}|{rule.description[:20]}"
        
        if rule.detection_cues.if_sid:
            parent_id = f"Rule {rule.detection_cues.if_sid}|parent"
            if parent_id not in nodes_dict:
                nodes_dict[parent_id] = {
                    "color": "#cccccc",
                    "size": 12,
                    "hover": f"Parent Rule {rule.detection_cues.if_sid}",
                }
            edges.append((parent_id, rule_id))
    
    return nodes_dict, edges


def _calculate_positions(
    nodes_dict: Dict[str, Dict[str, Any]],
    layout_type: str,
) -> Dict[str, Tuple[float, float]]:
    """Calculate node positions based on layout type."""
    import math
    
    nodes = list(nodes_dict.keys())
    n = len(nodes)
    pos = {}
    
    if layout_type == "circular":
        for i, node in enumerate(nodes):
            angle = 2 * math.pi * i / n
            x = 10 * math.cos(angle)
            y = 10 * math.sin(angle)
            pos[node] = (x, y)
    elif layout_type == "radial":
        # Sort by rule ID for radial
        sorted_nodes = sorted(nodes, key=lambda n: n.split()[1] if len(n.split()) > 1 else "0")
        for i, node in enumerate(sorted_nodes):
            angle = 2 * math.pi * i / n
            radius = 5 + (i % 3) * 3
            x = radius * math.cos(angle)
            y = radius * math.sin(angle)
            pos[node] = (x, y)
    else:  # hierarchical
        # Group by severity level
        severity_groups = {}
        for node in nodes:
            if "parent" in node:
                level = 0
            else:
                level = 1
            if level not in severity_groups:
                severity_groups[level] = []
            severity_groups[level].append(node)
        
        y = 10
        for level in sorted(severity_groups.keys(), reverse=True):
            nodes_at_level = severity_groups[level]
            x_start = -(len(nodes_at_level) - 1) * 2
            for i, node in enumerate(nodes_at_level):
                pos[node] = (x_start + i * 4, y)
            y -= 5
    
    return pos


def _hex_to_rgba(hex_color: str, alpha: float = 1.0) -> str:
    """Convert hex color to rgba string."""
    hex_color = hex_color.lstrip("#")
    r = int(hex_color[0:2], 16)
    g = int(hex_color[2:4], 16)
    b = int(hex_color[4:6], 16)
    return f"rgba({r},{g},{b},{alpha})"


def get_severity_color_for_node(node: str) -> str:
    """Get color for a node based on its label."""
    if "Ignored" in node:
        return get_severity_color(0)
    elif "Low" in node:
        return get_severity_color(3)
    elif "Medium" in node:
        return get_severity_color(6)
    elif "High" in node:
        return get_severity_color(9)
    elif "Critical" in node:
        return get_severity_color(15)
    elif "Filter" in node:
        return "#5dade2"
    else:
        return "#95a5a6"
