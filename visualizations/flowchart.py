"""
Relationship visualisations for Wazuh rules.

What changed against the old spring-layout version:

* Hierarchy layout - parents sit above their children, so an if_sid chain reads
  top to bottom instead of as a hairball.
* Curved edges - two rules pointing at each other no longer draw one line.
* A real legend - edge colours and severity bands are labelled instead of
  guessed.
* Ghost nodes - an if_sid pointing at a rule that is not in the file used to
  drop the edge silently. It now draws as a dashed grey node, which is how you
  spot a broken chain.
* Focus mode - pick a rule and everything outside its ancestor/descendant path
  dims out.
* Multi-parent support - the old code read only ``if_sid`` (the first parent)
  and lost every other edge.
"""

from __future__ import annotations

import math
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import networkx as nx
import plotly.graph_objects as go

from severity import (
    SEVERITY_ORDER,
    band_range,
    color_for_label,
    get_severity_level,
    node_size,
)
from wazuh_parser import RuleData

# --------------------------------------------------------------------------
# Palette
# --------------------------------------------------------------------------

EDGE_STYLES: Dict[str, Dict[str, str]] = {
    "if_sid": {
        "color": "#38bdf8",
        "label": "Parent rule (if_sid)",
        "desc": "child fires only after the parent matched",
    },
    "if_matched_sid": {
        "color": "#f472b6",
        "label": "Correlation (if_matched_sid)",
        "desc": "counts repeats of the referenced rule",
    },
    "if_matched_group": {
        "color": "#4ade80",
        "label": "Group correlation (if_matched_group)",
        "desc": "counts repeats across a whole group",
    },
    "if_group": {
        "color": "#fbbf24",
        "label": "Group parent (if_group)",
        "desc": "child fires after any rule in the group matched",
    },
}

GHOST_COLOR = "#475569"

THEMES = {
    "dark": {
        "paper": "#0b1220",
        "plot": "#0b1220",
        "font": "#e2e8f0",
        "muted": "#64748b",
        "node_edge": "#0b1220",
        "grid": "#1e293b",
    },
    "light": {
        "paper": "#ffffff",
        "plot": "#f8fafc",
        "font": "#0f172a",
        "muted": "#94a3b8",
        "node_edge": "#ffffff",
        "grid": "#e2e8f0",
    },
}

# One group with 200 rules would draw 40 000 edges. Cap it.
MAX_GROUP_FANOUT = 30


# --------------------------------------------------------------------------
# Graph construction
# --------------------------------------------------------------------------

def _parent_ids(rule: RuleData) -> List[int]:
    """Every if_sid parent, not just the first one."""
    cues = getattr(rule, "detection_cues", None)
    if cues is None:
        return []
    sids = list(getattr(cues, "if_sids", None) or [])
    if not sids:
        single = getattr(cues, "if_sid", None)
        if single is not None:
            sids = [single]
    return sids


def build_rule_graph(
    rules: Sequence[RuleData],
    show_if_sid: bool = True,
    show_if_matched_sid: bool = True,
    show_if_matched_group: bool = True,
    show_if_group: bool = True,
    show_external: bool = True,
) -> Tuple[nx.DiGraph, Dict[str, Any]]:
    """
    Build the relationship graph.

    ``show_external`` keeps if_sid targets that are not defined in this file as
    ghost nodes, so a broken chain is visible instead of invisible.
    """
    graph = nx.DiGraph()
    known_ids = {r.rule_id for r in rules}
    by_id = {r.rule_id: r for r in rules}
    meta: Dict[str, Any] = {
        "external_ids": set(),
        "truncated_groups": [],
        "edge_counts": defaultdict(int),
    }

    for rule in rules:
        graph.add_node(
            rule.rule_id,
            level=getattr(rule, "level", 0) or 0,
            description=getattr(rule, "description", "") or "",
            groups=list(getattr(rule, "groups", None) or []),
            mitre=list(getattr(rule, "mitre_techniques", None) or []),
            external=False,
        )

    group_to_rules: Dict[str, List[int]] = defaultdict(list)
    if show_if_matched_group or show_if_group:
        for rule in rules:
            for group in (getattr(rule, "groups", None) or []):
                group_to_rules[group].append(rule.rule_id)

    def add_ghost(node_id: int) -> None:
        if node_id in graph:
            return
        graph.add_node(
            node_id,
            level=0,
            description="Not defined in this file. Either a rule from Wazuh's "
                        "bundled ruleset or a broken reference.",
            groups=[],
            mitre=[],
            external=True,
        )
        meta["external_ids"].add(node_id)

    def link(src: int, dst: int, kind: str) -> None:
        graph.add_edge(src, dst, kind=kind, color=EDGE_STYLES[kind]["color"])
        meta["edge_counts"][kind] += 1

    for rule in rules:
        cues = getattr(rule, "detection_cues", None)

        if show_if_sid:
            for parent in _parent_ids(rule):
                if parent in known_ids:
                    link(parent, rule.rule_id, "if_sid")
                elif show_external:
                    add_ghost(parent)
                    link(parent, rule.rule_id, "if_sid")

        if show_if_matched_sid:
            for parent in (getattr(cues, "if_matched_sid", None) or []):
                if parent in known_ids:
                    link(parent, rule.rule_id, "if_matched_sid")
                elif show_external:
                    add_ghost(parent)
                    link(parent, rule.rule_id, "if_matched_sid")

        for enabled, attr, kind in (
            (show_if_matched_group, "if_matched_groups", "if_matched_group"),
            (show_if_group, "if_groups", "if_group"),
        ):
            if not enabled:
                continue
            for gname in (getattr(cues, attr, None) or []):
                members = [m for m in group_to_rules.get(gname, []) if m != rule.rule_id]
                if len(members) > MAX_GROUP_FANOUT:
                    meta["truncated_groups"].append((gname, len(members)))
                    members = members[:MAX_GROUP_FANOUT]
                for src in members:
                    link(src, rule.rule_id, kind)

    meta["edge_counts"] = dict(meta["edge_counts"])
    meta["by_id"] = by_id
    return graph, meta


# --------------------------------------------------------------------------
# Layouts
# --------------------------------------------------------------------------

def _hierarchy_depths(graph: nx.DiGraph) -> Dict[Any, int]:
    """BFS depth from every root. Tolerates cycles."""
    depth: Dict[Any, int] = {}
    roots = [n for n in graph.nodes if graph.in_degree(n) == 0]
    if not roots:
        roots = [min(graph.nodes, key=lambda n: graph.in_degree(n))]

    queue = deque((r, 0) for r in roots)
    for r in roots:
        depth[r] = 0
    while queue:
        node, d = queue.popleft()
        for child in graph.successors(node):
            if child not in depth or depth[child] < d + 1:
                if depth.get(child) == d + 1:
                    continue
                depth[child] = d + 1
                queue.append((child, d + 1))

    for node in graph.nodes:
        depth.setdefault(node, 0)
    return depth


def _layout_hierarchy(graph: nx.DiGraph) -> Dict[Any, Tuple[float, float]]:
    depth = _hierarchy_depths(graph)
    rows: Dict[int, List[Any]] = defaultdict(list)
    for node, d in depth.items():
        rows[d].append(node)

    pos: Dict[Any, Tuple[float, float]] = {}
    max_row = max((len(v) for v in rows.values()), default=1)
    for d in sorted(rows):
        row = sorted(rows[d])
        span = max(len(row), 1)
        for i, node in enumerate(row):
            # centre each row, and spread wide rows across the same width
            x = (i + 0.5) / span * max(max_row, 4)
            # slight zig-zag stops long rows from overlapping their labels
            y = -d * 2.2 + (0.35 if i % 2 else 0.0)
            pos[node] = (x, y)
    return pos


def _layout_groups(graph: nx.DiGraph) -> Dict[Any, Tuple[float, float]]:
    """Cluster rules by their first group, laid out on a ring of clusters."""
    clusters: Dict[str, List[Any]] = defaultdict(list)
    for node, data in graph.nodes(data=True):
        groups = data.get("groups") or []
        clusters[groups[0] if groups else "ungrouped"].append(node)

    pos: Dict[Any, Tuple[float, float]] = {}
    names = sorted(clusters)
    ring = max(len(names), 1)
    for ci, name in enumerate(names):
        angle = 2 * math.pi * ci / ring
        cx, cy = math.cos(angle) * ring * 0.9, math.sin(angle) * ring * 0.9
        members = sorted(clusters[name])
        inner = max(len(members), 1)
        radius = 0.45 * math.sqrt(inner)
        for mi, node in enumerate(members):
            a = 2 * math.pi * mi / inner
            pos[node] = (cx + math.cos(a) * radius, cy + math.sin(a) * radius)
    return pos


def compute_layout(graph: nx.DiGraph, layout: str) -> Dict[Any, Tuple[float, float]]:
    if layout == "hierarchy":
        return _layout_hierarchy(graph)
    if layout == "groups":
        return _layout_groups(graph)
    if layout == "circular":
        return nx.circular_layout(graph, scale=2)
    if layout == "shell":
        return nx.shell_layout(graph, scale=2)
    k = 2.5 / math.sqrt(max(graph.number_of_nodes(), 1))
    return nx.spring_layout(graph, k=max(k, 0.35), iterations=80, seed=42, scale=2)


# --------------------------------------------------------------------------
# Focus
# --------------------------------------------------------------------------

def related_nodes(graph: nx.DiGraph, node: Any) -> Set[Any]:
    """The node plus everything upstream and downstream of it."""
    if node not in graph:
        return set()
    up = nx.ancestors(graph, node)
    down = nx.descendants(graph, node)
    return {node} | up | down


# --------------------------------------------------------------------------
# Drawing helpers
# --------------------------------------------------------------------------

def _bezier(p0: Tuple[float, float], p1: Tuple[float, float],
            curvature: float, steps: int = 18
            ) -> Tuple[List[float], List[float]]:
    """Quadratic bezier between two points, bulged perpendicular to the line."""
    (x0, y0), (x1, y1) = p0, p1
    dx, dy = x1 - x0, y1 - y0
    dist = math.hypot(dx, dy) or 1.0
    mx, my = (x0 + x1) / 2, (y0 + y1) / 2
    cx = mx - dy / dist * curvature * dist
    cy = my + dx / dist * curvature * dist

    xs, ys = [], []
    for i in range(steps + 1):
        t = i / steps
        u = 1 - t
        xs.append(u * u * x0 + 2 * u * t * cx + t * t * x1)
        ys.append(u * u * y0 + 2 * u * t * cy + t * t * y1)
    return xs, ys


def _shorten(xs: List[float], ys: List[float], frac: float
             ) -> Tuple[List[float], List[float]]:
    """Trim the tail of a path so the arrowhead lands outside the node marker."""
    keep = max(2, int(len(xs) * frac))
    return xs[:keep], ys[:keep]


def _hover_card(node: Any, data: Dict[str, Any], graph: nx.DiGraph,
                rule: Optional[RuleData]) -> str:
    if data.get("external"):
        children = list(graph.successors(node))
        return (
            f"<b>Rule {node}</b>  <i>(not in this file)</i><br>"
            f"<span style='color:#94a3b8'>Referenced by: "
            f"{', '.join(str(c) for c in children[:8]) or 'nothing'}</span><br>"
            f"Either a bundled Wazuh rule or a broken if_sid reference."
        )

    level = data.get("level", 0)
    label = get_severity_level(level)
    parts = [
        f"<b>Rule {node}</b> &nbsp; <b>level {level}</b> ({label})",
        f"<br>{data.get('description') or '<i>no description</i>'}",
    ]

    parents = list(graph.predecessors(node))
    children = list(graph.successors(node))
    parents_txt = ", ".join(str(p) for p in parents[:6]) or "none (root rule)"
    children_txt = ", ".join(str(c) for c in children[:6]) or "none (leaf rule)"
    if len(parents) > 6:
        parents_txt += f" +{len(parents) - 6}"
    if len(children) > 6:
        children_txt += f" +{len(children) - 6}"
    parts.append(f"<br><br><b>Triggered by:</b> {parents_txt}")
    parts.append(f"<br><b>Feeds:</b> {children_txt}")

    if rule is not None and getattr(rule, "filter_conditions", None):
        conds = []
        for cond in rule.filter_conditions[:3]:
            if getattr(cond, "field", None):
                conds.append(f"field {cond.field}")
            elif getattr(cond, "match", None):
                conds.append(f"match {cond.match}")
            elif getattr(cond, "regex", None):
                engine = "pcre2" if getattr(cond, "regex_type", None) == "pcre2" else "os_regex"
                conds.append(f"regex ({engine}) {cond.regex}")
            elif getattr(cond, "frequency", None):
                window = f"/{cond.timeframe}s" if getattr(cond, "timeframe", None) else ""
                conds.append(f"frequency {cond.frequency}{window}")
        if conds:
            shown = "<br>&nbsp;&nbsp;• ".join(c[:70] for c in conds)
            parts.append(f"<br><br><b>Conditions:</b><br>&nbsp;&nbsp;• {shown}")

    groups = data.get("groups") or []
    if groups:
        parts.append(f"<br><br><b>Groups:</b> {', '.join(groups[:5])}")
    mitre = data.get("mitre") or []
    if mitre:
        parts.append(f"<br><b>MITRE:</b> {', '.join(mitre[:5])}")
    return "".join(parts)


# --------------------------------------------------------------------------
# Main figure
# --------------------------------------------------------------------------

def create_rule_network_visualization(
    rules: Sequence[RuleData],
    show_if_sid: bool = True,
    show_if_matched_sid: bool = True,
    show_if_matched_group: bool = True,
    show_if_group: bool = True,
    min_level: int = 0,
    selected_groups: Optional[List[str]] = None,
    show_desc_on_node: bool = False,
    show_cond_on_node: bool = False,
    layout: str = "hierarchy",
    theme: str = "dark",
    focus_rule_id: Optional[int] = None,
    show_external: bool = True,
    show_isolated: bool = True,
    curvature: float = 0.12,
    height: int = 760,
) -> go.Figure:
    """Interactive relationship graph for a set of Wazuh rules."""
    palette = THEMES.get(theme, THEMES["dark"])

    filtered = [r for r in rules if (getattr(r, "level", 0) or 0) >= min_level]
    if selected_groups:
        wanted = set(selected_groups)
        filtered = [
            r for r in filtered
            if wanted & set(getattr(r, "groups", None) or [])
        ]

    if not filtered:
        return _empty_figure("No rules match the current filters.",
                             "Lower the minimum level or clear the group filter.",
                             palette, height)

    graph, meta = build_rule_graph(
        filtered, show_if_sid, show_if_matched_sid,
        show_if_matched_group, show_if_group, show_external,
    )

    if not show_isolated:
        isolated = [n for n in graph.nodes if graph.degree(n) == 0]
        graph.remove_nodes_from(isolated)

    if graph.number_of_nodes() == 0:
        return _empty_figure(
            "Every rule was filtered out.",
            "Turn 'Hide unconnected rules' off to see standalone rules.",
            palette, height,
        )

    if graph.number_of_edges() == 0:
        enabled = [
            EDGE_STYLES[k]["label"] for k, on in (
                ("if_sid", show_if_sid),
                ("if_matched_sid", show_if_matched_sid),
                ("if_matched_group", show_if_matched_group),
                ("if_group", show_if_group),
            ) if on
        ]
        hint = (
            "No connection types are enabled. Switch at least one on."
            if not enabled else
            "These rules define no links of the enabled types. "
            "Add <if_sid> to a child rule to build a chain, or enable "
            "'Show rules not in this file' so external parents appear."
        )
        # still draw the nodes, an unconnected ruleset is a finding in itself
        return _nodes_only_figure(graph, meta, filtered, palette, hint,
                                  layout, show_desc_on_node, show_cond_on_node,
                                  height)

    pos = compute_layout(graph, layout)
    focus_set = related_nodes(graph, focus_rule_id) if focus_rule_id in graph else None
    big = graph.number_of_edges() > 600

    fig = go.Figure()

    # ---- edges, one trace per type so the legend means something ----
    for kind, style in EDGE_STYLES.items():
        edges = [(u, v) for u, v, d in graph.edges(data=True) if d.get("kind") == kind]
        if not edges:
            continue
        for dimmed in (True, False):
            xs: List[Optional[float]] = []
            ys: List[Optional[float]] = []
            bucket = [
                (u, v) for u, v in edges
                if (focus_set is not None and not (u in focus_set and v in focus_set)) == dimmed
            ]
            if focus_set is None and dimmed:
                continue
            if not bucket:
                continue
            mid_x: List[float] = []
            mid_y: List[float] = []
            mid_hover: List[str] = []
            for u, v in bucket:
                if big:
                    ex, ey = [pos[u][0], pos[v][0]], [pos[u][1], pos[v][1]]
                else:
                    ex, ey = _bezier(pos[u], pos[v], curvature)
                xs.extend(ex + [None])
                ys.extend(ey + [None])
                half = len(ex) // 2
                mid_x.append(ex[half])
                mid_y.append(ey[half])
                mid_hover.append(
                    f"<b>Rule {u} \u2192 Rule {v}</b><br>"
                    f"Type: {style['label']}<br>"
                    f"<span style='color:#94a3b8'>{style['desc']}</span>"
                )
            fig.add_trace(go.Scatter(
                x=xs, y=ys, mode="lines",
                line=dict(width=1.1 if dimmed else 1.9,
                          color=style["color"], shape="spline"),
                opacity=0.12 if dimmed else 0.75,
                hoverinfo="skip",
                name=f"{style['label']}  ({len(edges)})",
                legendgroup=kind,
                showlegend=not dimmed,
            ))
            # Invisible midpoint markers give each edge a hover target without
            # paying for one trace per edge.
            if not dimmed:
                fig.add_trace(go.Scatter(
                    x=mid_x, y=mid_y, mode="markers",
                    marker=dict(size=10, color=style["color"], opacity=0.001),
                    hovertext=mid_hover, hoverinfo="text",
                    legendgroup=kind, showlegend=False,
                ))

    # ---- arrowheads ----
    if not big:
        for u, v, data in graph.edges(data=True):
            if focus_set is not None and not (u in focus_set and v in focus_set):
                continue
            ex, ey = _bezier(pos[u], pos[v], curvature)
            ex, ey = _shorten(ex, ey, 0.88)
            fig.add_annotation(
                x=ex[-1], y=ey[-1], ax=ex[-3], ay=ey[-3],
                xref="x", yref="y", axref="x", ayref="y",
                showarrow=True, arrowhead=2, arrowsize=1.4, arrowwidth=1.6,
                arrowcolor=data.get("color", palette["muted"]),
                opacity=0.9,
            )

    # ---- nodes, one trace per severity band plus one for ghosts ----
    buckets: Dict[str, List[Any]] = defaultdict(list)
    for node, data in graph.nodes(data=True):
        key = "External" if data.get("external") else get_severity_level(data.get("level", 0))
        buckets[key].append(node)

    by_id = meta["by_id"]
    for key in SEVERITY_ORDER + ["External"]:
        nodes = buckets.get(key)
        if not nodes:
            continue
        external = key == "External"
        xs, ys, labels, hovers, sizes, opacities, text_colors = [], [], [], [], [], [], []
        for node in sorted(nodes):
            data = graph.nodes[node]
            x, y = pos[node]
            xs.append(x)
            ys.append(y)

            lines = [str(node)]
            if not external:
                rule = by_id.get(node)
                if show_desc_on_node and data.get("description"):
                    desc = data["description"]
                    lines.append(desc[:26] + "…" if len(desc) > 26 else desc)
                if show_cond_on_node and rule is not None:
                    for cond in (getattr(rule, "filter_conditions", None) or [])[:1]:
                        if getattr(cond, "field", None):
                            lines.append(f"field: {str(cond.field)[:22]}")
                        elif getattr(cond, "match", None):
                            lines.append(f"match: {str(cond.match)[:22]}")
                        elif getattr(cond, "regex", None):
                            lines.append(f"regex: {str(cond.regex)[:22]}")
                        elif getattr(cond, "frequency", None):
                            lines.append(f"freq: {cond.frequency}")
            labels.append("<br>".join(lines))
            hovers.append(_hover_card(node, data, graph, by_id.get(node)))
            sizes.append(13.0 if external else node_size(data.get("level", 0)))

            in_focus = focus_set is None or node in focus_set
            opacities.append(1.0 if in_focus else 0.15)
            text_colors.append(palette["font"] if in_focus else palette["muted"])

        fig.add_trace(go.Scatter(
            x=xs, y=ys,
            mode="markers+text",
            text=labels,
            textposition="bottom center",
            textfont=dict(size=10, color=text_colors),
            hovertext=hovers,
            hoverinfo="text",
            marker=dict(
                size=sizes,
                color=GHOST_COLOR if external else color_for_label(key),
                opacity=opacities,
                symbol="circle-open" if external else "circle",
                line=dict(
                    width=2 if external else 1.5,
                    color=GHOST_COLOR if external else palette["node_edge"],
                ),
            ),
            name=(f"Not in this file ({len(nodes)})" if external
                  else f"{key} · level {band_range(key)} ({len(nodes)})"),
            legendgroup=key,
            showlegend=True,
        ))

    subtitle = (
        f"{graph.number_of_nodes() - len(meta['external_ids'])} rules · "
        f"{graph.number_of_edges()} links"
    )
    if meta["external_ids"]:
        subtitle += f" · {len(meta['external_ids'])} external reference(s)"
    if focus_set is not None:
        subtitle += f" · focused on rule {focus_rule_id}"

    fig.update_layout(
        title=dict(
            text=f"Rule relationships<br><span style='font-size:12px;"
                 f"color:{palette['muted']}'>{subtitle}</span>",
            x=0.01, xanchor="left",
        ),
        showlegend=True,
        legend=dict(
            orientation="h", yanchor="bottom", y=1.01,
            xanchor="right", x=1, font=dict(size=11),
            bgcolor="rgba(0,0,0,0)",
        ),
        hovermode="closest",
        hoverlabel=dict(align="left", bgcolor=palette["paper"],
                        bordercolor=palette["muted"],
                        font=dict(color=palette["font"], size=12)),
        margin=dict(b=10, l=10, r=10, t=90),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        plot_bgcolor=palette["plot"],
        paper_bgcolor=palette["paper"],
        font=dict(color=palette["font"]),
        height=height,
        dragmode="pan",
    )
    return fig


def _nodes_only_figure(graph, meta, rules, palette, hint, layout,
                       show_desc, show_cond, height) -> go.Figure:
    """Draw the rules with no edges, plus an explanation of why."""
    pos = compute_layout(graph, "circular" if layout == "hierarchy" else layout)
    fig = go.Figure()
    by_id = meta["by_id"]
    buckets: Dict[str, List[Any]] = defaultdict(list)
    for node, data in graph.nodes(data=True):
        buckets[get_severity_level(data.get("level", 0))].append(node)

    for key in SEVERITY_ORDER:
        nodes = buckets.get(key)
        if not nodes:
            continue
        xs = [pos[n][0] for n in nodes]
        ys = [pos[n][1] for n in nodes]
        fig.add_trace(go.Scatter(
            x=xs, y=ys, mode="markers+text",
            text=[str(n) for n in nodes], textposition="bottom center",
            textfont=dict(size=10, color=palette["font"]),
            hovertext=[_hover_card(n, graph.nodes[n], graph, by_id.get(n)) for n in nodes],
            hoverinfo="text",
            marker=dict(size=[node_size(graph.nodes[n].get("level", 0)) for n in nodes],
                        color=color_for_label(key),
                        line=dict(width=1.5, color=palette["node_edge"])),
            name=f"{key} · level {band_range(key)} ({len(nodes)})",
        ))

    fig.update_layout(
        title=dict(
            text=f"Rule relationships<br><span style='font-size:12px;"
                 f"color:{palette['muted']}'>{graph.number_of_nodes()} rules, "
                 f"no links to draw — {hint}</span>",
            x=0.01, xanchor="left",
        ),
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=1.01,
                    xanchor="right", x=1, font=dict(size=11)),
        margin=dict(b=10, l=10, r=10, t=100),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        plot_bgcolor=palette["plot"], paper_bgcolor=palette["paper"],
        font=dict(color=palette["font"]), height=height, dragmode="pan",
    )
    return fig


def _empty_figure(message: str, hint: str, palette: Dict[str, str],
                  height: int = 420) -> go.Figure:
    fig = go.Figure()
    fig.add_annotation(text=f"<b>{message}</b><br><span style='font-size:13px'>{hint}</span>",
                       xref="paper", yref="paper", x=0.5, y=0.5,
                       showarrow=False, align="center",
                       font=dict(size=16, color=palette["muted"]))
    fig.update_layout(
        xaxis=dict(visible=False), yaxis=dict(visible=False),
        plot_bgcolor=palette["plot"], paper_bgcolor=palette["paper"],
        font=dict(color=palette["font"]), height=height,
        margin=dict(b=20, l=10, r=10, t=20),
    )
    return fig
