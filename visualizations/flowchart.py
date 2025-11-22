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
    connection_type: str = "if_sid",
    selected_groups: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Create an interactive node-link network artifact.
    
    Args:
        rules: List of RuleData objects to visualize
        min_level: Minimum severity level to include
        layout_type: Layout type for the network
        connection_type: Relationship type to visualize ("if_sid", "if_matched_group", or "if_group")
        selected_groups: Optional list of groups to filter by
        
    Returns:
        Dictionary with network HTML, height, and metadata
    """
    filtered_rules = _filter_rules_by_severity_and_groups(
        rules,
        min_level=min_level,
        selected_groups=selected_groups,
    )

    if not filtered_rules:
        message = "No rules match the selected filters"
        return {
            "html": _create_empty_network_html(message),
            "height": 420,
            "is_empty": True,
            "message": message,
        }

    nodes_metadata = _build_node_metadata(filtered_rules)
    edges = _build_edges_by_connection_type(
        filtered_rules,
        connection_type=connection_type,
        nodes_metadata=nodes_metadata,
    )

    if not edges:
        message = _format_connection_empty_message(connection_type)
        return {
            "html": _create_empty_network_html(message),
            "height": _determine_network_height(len(nodes_metadata)),
            "is_empty": True,
            "message": message,
        }

    height_px = _determine_network_height(len(nodes_metadata))
    network_html = _render_pyvis_network(
        nodes_metadata,
        edges,
        layout_type=layout_type,
        height=height_px,
    )

    return {
        "html": network_html,
        "height": height_px,
        "is_empty": False,
        "message": "",
    }


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
    from collections import defaultdict
    
    edges = []
    rule_lookup = {rule.rule_id: rule for rule in rules}
    
    if connection_type == "if_sid":
        # Create parent->child edges for if_sid relationships
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
        # Create edges from rules in matched groups to the rule that references them
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
        # Create edges for if_group relationships (similar to if_matched_group but different semantics)
        group_to_rules = defaultdict(list)
        for rule in rules:
            for group in rule.groups:
                group_to_rules[group].append(rule.rule_id)
        
        for rule in rules:
            if rule.detection_cues.if_groups:
                for group_name in rule.detection_cues.if_groups:
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
    from html import escape
    
    nodes = {}
    
    for rule in rules:
        severity = get_severity_label(rule.level)
        color = get_severity_color(rule.level)
        
        groups_str = ", ".join(rule.groups) if rule.groups else "None"
        filter_summary = summarize_filter_logic(rule.filter_conditions)
        
        title_html = f"""
        <b>Rule {rule.rule_id}</b><br>
        <b>Description:</b> {escape(rule.description)}<br>
        <b>Severity:</b> {severity} (Level {rule.level})<br>
        <b>Groups:</b> {escape(groups_str)}<br>
        <b>Filters:</b> {escape(filter_summary)}
        """
        
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


def create_interactive_network(
    rules: List[RuleData],
    connection_type: str = "if_sid",
    min_level: int = 0,
    max_level: int = 15,
    groups_filter: Optional[List[str]] = None,
    height: str = "600px",
    width: str = "100%",
    physics_enabled: bool = True,
) -> str:
    """
    Create an interactive PyVis network visualization.
    
    Args:
        rules: List of RuleData objects to visualize
        connection_type: "if_sid" or "if_matched_group"
        min_level: Minimum severity level to include
        max_level: Maximum severity level to include
        groups_filter: Optional list of groups to filter by
        height: Network height (CSS string, e.g., "600px")
        width: Network width (CSS string, e.g., "100%")
        physics_enabled: Whether to enable physics simulation
    
    Returns:
        HTML string containing the interactive network
    """
    from pyvis.network import Network
    import tempfile
    import os
    from html import escape
    
    filtered_rules = filter_rules_by_severity_and_groups(
        rules, min_level, max_level, groups_filter
    )
    
    if not filtered_rules:
        return _create_empty_network_html(
            "No rules match the selected filters",
            height,
            width
        )
    
    net = Network(
        height=height,
        width=width,
        bgcolor="#ffffff",
        font_color="#000000",
        notebook=False,
        directed=True,
    )
    
    if physics_enabled:
        net.set_options("""
        {
          "physics": {
            "enabled": true,
            "barnesHut": {
              "gravitationalConstant": -8000,
              "centralGravity": 0.3,
              "springLength": 150,
              "springConstant": 0.04,
              "damping": 0.09,
              "avoidOverlap": 0.1
            },
            "stabilization": {
              "enabled": true,
              "iterations": 200
            }
          },
          "interaction": {
            "hover": true,
            "tooltipDelay": 100,
            "navigationButtons": true,
            "keyboard": true
          },
          "manipulation": {
            "enabled": false
          }
        }
        """)
    else:
        net.toggle_physics(False)
    
    node_metadata = build_node_metadata(filtered_rules)
    
    for rule_id, metadata in node_metadata.items():
        net.add_node(
            rule_id,
            label=metadata["label"],
            color=metadata["color"],
            title=metadata["title"],
            size=metadata["size"],
        )
    
    edges = build_edges_by_connection_type(filtered_rules, connection_type)
    
    for source, target, edge_meta in edges:
        if source in node_metadata and target in node_metadata:
            net.add_edge(
                source,
                target,
                title=edge_meta.get("title", ""),
                label=edge_meta.get("label", ""),
                color={"color": "#888888", "highlight": "#000000"},
                arrows="to",
            )
    
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
            temp_path = f.name
        
        net.save_graph(temp_path)
        
        with open(temp_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        os.unlink(temp_path)
        
        return html_content
    
    except Exception as e:
        return _create_empty_network_html(
            f"Error generating network: {str(e)}",
            height,
            width
        )


def _create_empty_network_html(
    message: str,
    height: str = "600px",
    width: str = "100%"
) -> str:
    """Create an empty network HTML with a message."""
    from html import escape
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{
                margin: 0;
                padding: 0;
                font-family: Arial, sans-serif;
            }}
            .empty-network {{
                width: {width};
                height: {height};
                display: flex;
                align-items: center;
                justify-content: center;
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 4px;
            }}
            .message {{
                font-size: 18px;
                color: #6c757d;
                text-align: center;
                padding: 20px;
            }}
        </style>
    </head>
    <body>
        <div class="empty-network">
            <div class="message">{escape(message)}</div>
        </div>
    </body>
    </html>
    """


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


def _build_node_metadata(rules: List[RuleData]) -> Dict[str, Dict[str, Any]]:
    """Build metadata for each rule node."""
    return build_node_metadata(rules)


def _build_edges_by_connection_type(
    rules: List[RuleData],
    connection_type: str,
    nodes_metadata: Dict[str, Dict[str, Any]],
) -> List[Tuple[str, str, Dict[str, Any]]]:
    """Build edges based on connection type."""
    return build_edges_by_connection_type(rules, connection_type)


def _format_connection_empty_message(connection_type: str) -> str:
    """Format empty message based on connection type."""
    if connection_type == "if_matched_group":
        return "No rules with if_matched_group connections found"
    elif connection_type == "if_group":
        return "No rules with if_group connections found"
    return "No rules with if_sid parent relationships found"


def _determine_network_height(node_count: int) -> int:
    """Determine network height based on node count."""
    base_height = 600
    return min(base_height + (node_count * 10), 1200)


def _render_pyvis_network(
    nodes_metadata: Dict[str, Dict[str, Any]],
    edges: List[Tuple[str, str, Dict[str, Any]]],
    layout_type: str,
    height: int,
) -> str:
    """Render PyVis network to HTML."""
    from pyvis.network import Network
    import tempfile
    import os
    
    net = Network(
        height=f"{height}px",
        width="100%",
        bgcolor="#ffffff",
        font_color="#000000",
        notebook=False,
        directed=True,
    )
    
    net.set_options("""
    {
      "physics": {
        "enabled": true,
        "barnesHut": {
          "gravitationalConstant": -8000,
          "centralGravity": 0.3,
          "springLength": 150,
          "springConstant": 0.04,
          "damping": 0.09,
          "avoidOverlap": 0.1
        },
        "stabilization": {
          "enabled": true,
          "iterations": 200
        }
      },
      "interaction": {
        "hover": true,
        "tooltipDelay": 100,
        "navigationButtons": true,
        "keyboard": true
      },
      "manipulation": {
        "enabled": false
      }
    }
    """)
    
    for rule_id, metadata in nodes_metadata.items():
        net.add_node(
            rule_id,
            label=metadata["label"],
            color=metadata["color"],
            title=metadata["title"],
            size=metadata["size"],
        )
    
    for source, target, edge_meta in edges:
        if source in nodes_metadata and target in nodes_metadata:
            net.add_edge(
                source,
                target,
                title=edge_meta.get("title", ""),
                label=edge_meta.get("label", ""),
                color={"color": "#888888", "highlight": "#000000"},
                arrows="to",
            )
    
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
            temp_path = f.name
        
        net.save_graph(temp_path)
        
        with open(temp_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        os.unlink(temp_path)
        
        return html_content
    
    except Exception as e:
        from html import escape
        return _create_empty_network_html(
            f"Error generating network: {escape(str(e))}",
            height=f"{height}px"
        )
