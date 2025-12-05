"""
Flowchart visualization module for Wazuh rules using NetworkX and Plotly.

Provides interactive hierarchical network visualizations showing rule relationships
with color-coding by severity levels, hover tooltips, and interactive controls
for exploring rule hierarchies.
"""

from typing import List, Dict, Tuple, Optional, Any
from collections import defaultdict

import networkx as nx
import plotly.graph_objects as go
from wazuh_parser import RuleData, summarize_filter_logic


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


def create_node_link_diagram(
    rules: List[RuleData],
    min_level: int = 0,
    layout_type: str = "hierarchical",
    connection_type: str = "if_sid",
    selected_groups: Optional[List[str]] = None,
) -> go.Figure:
    """
    Create an interactive hierarchical network visualization using NetworkX and Plotly.
    
    Args:
        rules: List of RuleData objects to visualize
        min_level: Minimum severity level to include
        layout_type: Layout type for the network (hierarchical, spring, kamada_kawai)
        connection_type: Relationship type to visualize ("if_sid", "if_matched_group", or "if_group")
        selected_groups: Optional list of groups to filter by
        
    Returns:
        Plotly Figure object for interactive visualization
    """
    filtered_rules = _filter_rules_by_severity_and_groups(
        rules,
        min_level=min_level,
        selected_groups=selected_groups,
    )

    if not filtered_rules:
        return _create_empty_figure("No rules match the selected filters")

    edges = build_edges_by_connection_type(filtered_rules, connection_type)
    
    if not edges:
        return _create_empty_figure(
            _format_connection_empty_message(connection_type)
        )

    G = _build_networkx_graph(filtered_rules, edges)
    
    pos = _compute_hierarchical_layout(G, layout_type)
    
    fig = _create_plotly_figure(G, pos, edges, filtered_rules, connection_type)
    
    return fig


def _build_networkx_graph(
    rules: List[RuleData],
    edges: List[Tuple[str, str, Dict[str, Any]]],
) -> nx.DiGraph:
    """
    Build a NetworkX directed graph from rules and edges.
    
    Args:
        rules: List of RuleData objects
        edges: List of (source, target, metadata) tuples
        
    Returns:
        NetworkX DiGraph with nodes and edges
    """
    G = nx.DiGraph()
    
    nodes_metadata = build_node_metadata(rules)
    
    for rule_id, metadata in nodes_metadata.items():
        G.add_node(
            rule_id,
            level=metadata["level"],
            severity=metadata["severity"],
            description=metadata["color"],
            label=metadata["label"],
            title=metadata["title"],
        )
    
    edge_colors = {
        "if_sid": "#0099ff",
        "if_matched_group": "#00cc00",
        "if_group": "#ff9900",
    }
    
    for source, target, edge_meta in edges:
        relationship_type = edge_meta.get("type", "unknown")
        color = edge_colors.get(relationship_type, "#999999")
        
        G.add_edge(
            source,
            target,
            relationship_type=relationship_type,
            title=edge_meta.get("title", ""),
            color=color,
        )
    
    return G


def _compute_hierarchical_layout(
    G: nx.DiGraph,
    layout_type: str = "hierarchical",
) -> Dict[str, Tuple[float, float]]:
    """
    Compute node positions using hierarchical or spring layout.
    
    Args:
        G: NetworkX graph
        layout_type: Type of layout ("hierarchical", "spring", "kamada_kawai")
        
    Returns:
        Dictionary mapping node IDs to (x, y) positions
    """
    if layout_type == "hierarchical":
        pos = _hierarchy_pos(G)
    elif layout_type == "kamada_kawai":
        pos = nx.kamada_kawai_layout(G, scale=1.0)
    else:
        pos = nx.spring_layout(G, k=2, iterations=50, seed=42)
    
    return pos


def _hierarchy_pos(
    G: nx.DiGraph,
    root: Optional[str] = None,
    width: float = 12.0,
    vert_gap: float = 2.0,
) -> Dict[str, Tuple[float, float]]:
    """
    Create hierarchical positions for tree-like layouts.
    
    Args:
        G: NetworkX graph
        root: Root node ID (if None, find all roots)
        width: Width of the layout
        vert_gap: Vertical gap between levels
        
    Returns:
        Dictionary mapping node IDs to (x, y) positions
    """
    if root is None:
        roots = [n for n in G.nodes() if G.in_degree(n) == 0]
        if not roots:
            roots = [list(G.nodes())[0]] if G.nodes() else []
    else:
        roots = [root]
    
    def _hierarchy_pos_recursive(
        G: nx.DiGraph,
        root: str,
        leftmost: float,
        width: float,
        vert_gap: float,
        pos: Dict[str, Tuple[float, float]],
        xcenter: float,
        rootpos: Optional[Tuple[float, float]] = None,
    ) -> Tuple[float, Dict[str, Tuple[float, float]]]:
        """Recursively calculate hierarchical positions."""
        if rootpos is None:
            rootpos = (xcenter, 0)
        
        pos[root] = rootpos
        neighbors = list(G.neighbors(root))
        
        if not neighbors:
            return leftmost + width, pos
        
        dx = width / len(neighbors)
        nextx = leftmost
        
        for neighbor in neighbors:
            nextx, pos = _hierarchy_pos_recursive(
                G,
                neighbor,
                nextx,
                dx,
                vert_gap,
                pos,
                nextx + dx / 2,
                (nextx + dx / 2, rootpos[1] - vert_gap),
            )
        
        return nextx, pos
    
    pos = {}
    xcenter = width / 2
    
    for root in roots:
        _hierarchy_pos_recursive(
            G,
            root,
            0,
            width,
            vert_gap,
            pos,
            xcenter,
        )
    
    return pos


def _create_plotly_figure(
    G: nx.DiGraph,
    pos: Dict[str, Tuple[float, float]],
    edges: List[Tuple[str, str, Dict[str, Any]]],
    rules: List[RuleData],
    connection_type: str,
) -> go.Figure:
    """
    Create a Plotly figure from NetworkX graph.
    
    Args:
        G: NetworkX graph
        pos: Node positions dictionary
        edges: List of edges with metadata
        rules: List of RuleData objects
        connection_type: Type of connection being visualized
        
    Returns:
        Plotly Figure object
    """
    nodes_metadata = build_node_metadata(rules)
    
    edge_traces = []
    
    for source, target, edge_meta in edges:
        if source not in pos or target not in pos:
            continue
        
        x0, y0 = pos[source]
        x1, y1 = pos[target]
        
        relationship_type = edge_meta.get("type", "unknown")
        
        edge_color_map = {
            "if_sid": "#0099ff",
            "if_matched_group": "#00cc00",
            "if_group": "#ff9900",
        }
        edge_color = edge_color_map.get(relationship_type, "#999999")
        
        edge_trace = go.Scatter(
            x=[x0, x1, None],
            y=[y0, y1, None],
            mode="lines",
            line=dict(width=2, color=edge_color),
            hovertext=edge_meta.get("title", f"{source} → {target}"),
            hoverinfo="text",
            showlegend=False,
            name="",
        )
        edge_traces.append(edge_trace)
    
    node_x = []
    node_y = []
    node_labels = []
    node_colors = []
    node_sizes = []
    node_hovers = []
    
    for node in G.nodes():
        if node in pos:
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            
            metadata = nodes_metadata.get(node, {})
            node_labels.append(metadata.get("label", node))
            node_colors.append(metadata.get("color", "#808080"))
            node_sizes.append(metadata.get("size", 20))
            node_hovers.append(metadata.get("title", node))
    
    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode="markers+text",
        text=node_labels,
        textposition="top center",
        hovertext=node_hovers,
        hoverinfo="text",
        marker=dict(
            size=node_sizes,
            color=node_colors,
            line=dict(width=2, color="white"),
        ),
        showlegend=False,
        name="",
    )
    
    fig = go.Figure(
        data=edge_traces + [node_trace],
        layout=go.Layout(
            title=dict(
                text=f"Wazuh Rule Relationships ({connection_type})",
                x=0.5,
                xanchor="center",
            ),
            showlegend=False,
            hovermode="closest",
            margin=dict(b=20, l=5, r=5, t=40),
            xaxis=dict(
                showgrid=False,
                zeroline=False,
                showticklabels=False,
            ),
            yaxis=dict(
                showgrid=False,
                zeroline=False,
                showticklabels=False,
            ),
            plot_bgcolor="rgba(240, 240, 240, 0.5)",
            height=max(600, len(G.nodes()) * 15),
            dragmode="zoom",
        ),
    )
    
    return fig


def _create_empty_figure(message: str) -> go.Figure:
    """
    Create an empty Plotly figure with a message.
    
    Args:
        message: Message to display
        
    Returns:
        Plotly Figure object with message
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
        plot_bgcolor="rgba(240, 240, 240, 0.5)",
        height=400,
        margin=dict(b=20, l=5, r=5, t=40),
    )
    return fig


def filter_rules_by_severity_and_groups(
    rules: List[RuleData],
    min_level: int = 0,
    max_level: int = 15,
    groups: Optional[List[str]] = None,
) -> List[RuleData]:
    """
    Filter rules by severity level and/or group membership.
    
    Args:
        rules: List of RuleData objects to filter
        min_level: Minimum severity level (inclusive)
        max_level: Maximum severity level (inclusive)
        groups: Optional list of group names to filter by (OR logic)
    
    Returns:
        Filtered list of RuleData objects
    """
    filtered = []
    
    for rule in rules:
        if not (min_level <= rule.level <= max_level):
            continue
        
        if groups:
            if not any(g in rule.groups for g in groups):
                continue
        
        filtered.append(rule)
    
    return filtered


def build_edges_by_connection_type(
    rules: List[RuleData],
    connection_type: str = "if_sid",
) -> List[Tuple[str, str, Dict[str, Any]]]:
    """
    Construct edges between rules based on explicit relationship types.
    
    Args:
        rules: List of RuleData objects
        connection_type: Either "if_sid", "if_matched_group", or "if_group"
    
    Returns:
        List of (source_id, target_id, edge_metadata) tuples
    """
    edges = []
    rule_lookup = {rule.rule_id: rule for rule in rules}
    
    if connection_type == "if_sid":
        for rule in rules:
            if rule.detection_cues.if_sid:
                parent_id = rule.detection_cues.if_sid
                if parent_id in rule_lookup:
                    edges.append((
                        str(parent_id),
                        str(rule.rule_id),
                        {
                            "type": "if_sid",
                            "label": "if_sid",
                            "title": f"Rule {parent_id} → Rule {rule.rule_id} (parent→child)",
                        }
                    ))
    
    elif connection_type == "if_matched_group":
        group_to_rules = defaultdict(list)
        for rule in rules:
            for group in rule.groups:
                group_to_rules[group].append(rule.rule_id)
        
        for rule in rules:
            if rule.detection_cues.if_matched_groups:
                for matched_group in rule.detection_cues.if_matched_groups:
                    if matched_group in group_to_rules:
                        for source_rule_id in group_to_rules[matched_group]:
                            if source_rule_id != rule.rule_id:
                                edges.append((
                                    str(source_rule_id),
                                    str(rule.rule_id),
                                    {
                                        "type": "if_matched_group",
                                        "label": f"if_matched_group:{matched_group}",
                                        "title": f"Group '{matched_group}': Rule {source_rule_id} → Rule {rule.rule_id}",
                                    }
                                ))
    
    elif connection_type == "if_group":
        group_to_rules = defaultdict(list)
        for rule in rules:
            for group in rule.groups:
                group_to_rules[group].append(rule.rule_id)
        
        for rule in rules:
            if getattr(rule.detection_cues, 'if_groups', []):
                for group_name in getattr(rule.detection_cues, 'if_groups', []):
                    if group_name in group_to_rules:
                        for source_rule_id in group_to_rules[group_name]:
                            if source_rule_id != rule.rule_id:
                                edges.append((
                                    str(source_rule_id),
                                    str(rule.rule_id),
                                    {
                                        "type": "if_group",
                                        "label": f"if_group:{group_name}",
                                        "title": f"Group correlation '{group_name}': Rule {source_rule_id} → Rule {rule.rule_id}",
                                    }
                                ))
    
    return edges


def build_node_metadata(
    rules: List[RuleData],
) -> Dict[str, Dict[str, Any]]:
    """
    Assemble metadata for each rule node.
    
    Args:
        rules: List of RuleData objects
    
    Returns:
        Dictionary mapping rule_id to node metadata including:
        - label: Display label
        - color: Hex color code based on severity
        - title: HTML hover tooltip
        - size: Node size
        - level: Severity level
        - severity: Severity classification
        - groups: List of groups
    """
    nodes = {}
    
    for rule in rules:
        severity = get_severity_label(rule.level)
        color = get_severity_color(rule.level)
        
        groups_str = ", ".join(rule.groups) if rule.groups else "None"
        filter_summary = summarize_filter_logic(rule.filter_conditions)
        
        title_html = f"""Rule {rule.rule_id}
Description: {rule.description}
Severity: {severity} (Level {rule.level})
Groups: {groups_str}
Filters: {filter_summary}"""
        
        nodes[str(rule.rule_id)] = {
            "label": f"Rule {rule.rule_id}",
            "color": color,
            "title": title_html.strip(),
            "size": 20 + (rule.level * 2),
            "level": rule.level,
            "severity": severity,
            "groups": rule.groups,
        }
    
    return nodes


def _filter_rules_by_severity_and_groups(
    rules: List[RuleData],
    min_level: int = 0,
    selected_groups: Optional[List[str]] = None,
) -> List[RuleData]:
    """Filter rules by severity and optional group selection."""
    filtered = [r for r in rules if r.level >= min_level]
    
    if selected_groups:
        filtered = [r for r in filtered if any(g in r.groups for g in selected_groups)]
    
    return filtered


def _format_connection_empty_message(connection_type: str) -> str:
    """Format empty message based on connection type."""
    if connection_type == "if_matched_group":
        return "No rules with if_matched_group connections found"
    elif connection_type == "if_group":
        return "No rules with if_group connections found"
    return "No rules with if_sid parent relationships found"
