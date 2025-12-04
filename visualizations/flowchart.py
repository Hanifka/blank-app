"""
Flowchart visualization module for Wazuh rules using Graphistry.

Provides interactive network visualizations showing rule relationships
with color-coding by severity levels, hover tooltips, and interactive 
controls for exploring rule hierarchies.
"""

import os
from functools import lru_cache
from typing import List, Dict, Tuple, Optional, Any

import pandas as pd

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
) -> Dict[str, Any]:
    """
    Create an interactive node-link network artifact using Graphistry.
    
    Args:
        rules: List of RuleData objects to visualize
        min_level: Minimum severity level to include
        layout_type: Layout type for the network (kept for compatibility, not used by Graphistry)
        connection_type: Relationship type to visualize ("if_sid", "if_matched_group", or "if_group")
        selected_groups: Optional list of groups to filter by
        
    Returns:
        Dictionary with Graphistry URL, height, and metadata
    """
    filtered_rules = _filter_rules_by_severity_and_groups(
        rules,
        min_level=min_level,
        selected_groups=selected_groups,
    )

    if not filtered_rules:
        message = "No rules match the selected filters"
        return {
            "url": None,
            "height": 420,
            "is_empty": True,
            "message": message,
        }

    nodes_df, edges_df = _build_graphistry_dataframes(
        filtered_rules,
        connection_type=connection_type,
    )

    if edges_df.empty:
        message = _format_connection_empty_message(connection_type)
        return {
            "url": None,
            "height": _determine_network_height(len(nodes_df)),
            "is_empty": True,
            "message": message,
        }

    try:
        import graphistry
        
        graphistry.register(api=3, protocol="https", server="hub.graphistry.com")
        
        g = graphistry.edges(edges_df, "source", "target").nodes(nodes_df, "node_id")
        
        g = g.bind(
            point_color="color",
            point_size="size",
            point_title="tooltip",
            edge_title="edge_tooltip"
        )
        
        url = g.plot(render=False)
        
        height_px = _determine_network_height(len(nodes_df))

        return {
            "url": url,
            "height": height_px,
            "is_empty": False,
            "message": "",
        }
    except Exception as e:
        return {
            "url": None,
            "height": 600,
            "is_empty": True,
            "message": f"Graphistry initialization failed: {str(e)}. Please configure GRAPHISTRY_API_KEY or use personal authentication.",
        }


def _build_graphistry_dataframes(
    rules: List[RuleData],
    connection_type: str,
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Build pandas DataFrames for Graphistry nodes and edges.
    
    Args:
        rules: List of RuleData objects
        connection_type: Relationship type to visualize
        
    Returns:
        Tuple of (nodes_df, edges_df)
    """
    nodes_data = []
    edges_data = []
    
    nodes_metadata = build_node_metadata(rules)
    
    for rule_id, metadata in nodes_metadata.items():
        nodes_data.append({
            "node_id": rule_id,
            "label": metadata["label"],
            "color": _hex_to_rgb(metadata["color"]),
            "size": metadata["size"],
            "tooltip": metadata["title"],
            "level": metadata["level"],
            "severity": metadata["severity"],
        })
    
    edges = build_edges_by_connection_type(rules, connection_type)
    
    for source, target, edge_meta in edges:
        if source in nodes_metadata and target in nodes_metadata:
            edges_data.append({
                "source": source,
                "target": target,
                "edge_tooltip": edge_meta.get("title", ""),
                "type": edge_meta.get("type", ""),
            })
    
    nodes_df = pd.DataFrame(nodes_data)
    edges_df = pd.DataFrame(edges_data)
    
    return nodes_df, edges_df


def _hex_to_rgb(hex_color: str) -> int:
    """Convert hex color to RGB integer for Graphistry."""
    hex_color = hex_color.lstrip("#")
    r = int(hex_color[0:2], 16)
    g = int(hex_color[2:4], 16)
    b = int(hex_color[4:6], 16)
    return (r << 16) + (g << 8) + b


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
    from html import escape
    
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
    Create an interactive Graphistry network visualization.
    
    Args:
        rules: List of RuleData objects to visualize
        connection_type: "if_sid", "if_matched_group", or "if_group"
        min_level: Minimum severity level to include
        max_level: Maximum severity level to include
        groups_filter: Optional list of groups to filter by
        height: Network height (CSS string, e.g., "600px")
        width: Network width (CSS string, e.g., "100%")
        physics_enabled: Whether to enable physics simulation (kept for compatibility)
    
    Returns:
        HTML string containing the interactive network
    """
    result = create_node_link_diagram(
        rules=rules,
        min_level=min_level,
        layout_type="hierarchical",
        connection_type=connection_type,
        selected_groups=groups_filter,
    )
    
    if result.get("is_empty"):
        return result
    
    return result


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


def _determine_network_height(node_count: int) -> int:
    """Determine network height based on node count."""
    base_height = 600
    return min(base_height + (node_count * 10), 1200)
