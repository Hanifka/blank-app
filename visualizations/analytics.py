"""
Supporting charts: where the ruleset spends its severity, and what it covers.

These answer questions the network graph cannot: which groups carry the risk,
whether severity is skewed, and how much MITRE ATT&CK the ruleset touches.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Dict, List, Optional, Sequence

import plotly.graph_objects as go

from severity import SEVERITY_ORDER, color_for_label, get_severity_level
from visualizations.flowchart import THEMES
from wazuh_parser import RuleData


def _base_layout(fig: go.Figure, title: str, theme: str, height: int) -> go.Figure:
    palette = THEMES.get(theme, THEMES["dark"])
    fig.update_layout(
        title=dict(text=title, x=0.01, xanchor="left", font=dict(size=15)),
        paper_bgcolor=palette["paper"],
        plot_bgcolor=palette["plot"],
        font=dict(color=palette["font"], size=12),
        margin=dict(t=50, b=30, l=10, r=10),
        height=height,
    )
    return fig


def create_group_treemap(rules: Sequence[RuleData], theme: str = "dark",
                         height: int = 520) -> go.Figure:
    """Group -> severity -> rule. Big red blocks are where the risk sits."""
    palette = THEMES.get(theme, THEMES["dark"])
    labels: List[str] = ["Ruleset"]
    parents: List[str] = [""]
    values: List[float] = [0]
    colors: List[str] = [palette["plot"]]
    hovers: List[str] = ["All rules"]

    by_group: Dict[str, List[RuleData]] = defaultdict(list)
    for rule in rules:
        for group in (rule.groups or ["ungrouped"]):
            by_group[group].append(rule)

    if not by_group:
        return _base_layout(go.Figure(), "No groups to chart", theme, height)

    for group, members in sorted(by_group.items(), key=lambda kv: -len(kv[1])):
        labels.append(group)
        parents.append("Ruleset")
        values.append(0)
        colors.append(palette["grid"])
        hovers.append(f"{len(members)} rule(s) in {group}")

        by_sev: Dict[str, List[RuleData]] = defaultdict(list)
        for rule in members:
            by_sev[get_severity_level(rule.level)].append(rule)

        for label in SEVERITY_ORDER:
            bucket = by_sev.get(label)
            if not bucket:
                continue
            node = f"{group} · {label}"
            labels.append(node)
            parents.append(group)
            values.append(len(bucket))
            colors.append(color_for_label(label))
            ids = ", ".join(str(r.rule_id) for r in bucket[:10])
            if len(bucket) > 10:
                ids += f" +{len(bucket) - 10}"
            hovers.append(f"{len(bucket)} {label} rule(s)<br>{ids}")

    fig = go.Figure(go.Treemap(
        labels=labels, parents=parents, values=values,
        marker=dict(colors=colors, line=dict(width=1, color=palette["paper"])),
        hovertext=hovers, hoverinfo="text",
        textinfo="label+value",
        branchvalues="remainder",
        tiling=dict(pad=2),
    ))
    return _base_layout(fig, "Severity by rule group", theme, height)


def create_severity_bar(rules: Sequence[RuleData], theme: str = "dark",
                        height: int = 300) -> go.Figure:
    """Count of rules per severity band."""
    counts = Counter(get_severity_level(r.level) for r in rules)
    order = [s for s in SEVERITY_ORDER if counts.get(s)]
    fig = go.Figure(go.Bar(
        x=[counts[s] for s in order],
        y=order,
        orientation="h",
        marker=dict(color=[color_for_label(s) for s in order]),
        text=[counts[s] for s in order],
        textposition="outside",
        hovertemplate="%{y}: %{x} rule(s)<extra></extra>",
    ))
    fig = _base_layout(fig, "Rules per severity band", theme, height)
    fig.update_layout(
        xaxis=dict(showgrid=False, zeroline=False),
        yaxis=dict(showgrid=False, autorange="reversed"),
        showlegend=False,
    )
    return fig


def create_mitre_chart(rules: Sequence[RuleData], theme: str = "dark",
                       top_n: int = 20, height: int = 460) -> Optional[go.Figure]:
    """MITRE ATT&CK techniques covered, most covered first."""
    counts = Counter()
    for rule in rules:
        for technique in (rule.mitre_techniques or []):
            counts[technique] += 1
    if not counts:
        return None

    top = counts.most_common(top_n)
    techniques = [t for t, _ in top][::-1]
    values = [c for _, c in top][::-1]

    fig = go.Figure(go.Bar(
        x=values, y=techniques, orientation="h",
        marker=dict(color="#8b5cf6"),
        text=values, textposition="outside",
        hovertemplate="%{y}: %{x} rule(s)<extra></extra>",
    ))
    title = f"MITRE ATT&CK coverage · {len(counts)} technique(s)"
    fig = _base_layout(fig, title, theme, max(height, 24 * len(top) + 90))
    fig.update_layout(
        xaxis=dict(showgrid=False, zeroline=False),
        yaxis=dict(showgrid=False),
        showlegend=False,
    )
    return fig


def create_chain_figure(rules: Sequence[RuleData], graph, rule_id: int,
                        theme: str = "dark", height: int = 340) -> go.Figure:
    """
    The ancestry of one rule as a straight left-to-right chain, so an analyst
    can read 'what has to happen before this fires' in one line.
    """
    palette = THEMES.get(theme, THEMES["dark"])
    by_id = {r.rule_id: r for r in rules}

    if rule_id not in graph:
        fig = go.Figure()
        fig.add_annotation(text="Rule not in the current graph", xref="paper",
                           yref="paper", x=0.5, y=0.5, showarrow=False,
                           font=dict(color=palette["muted"], size=15))
        return _base_layout(fig, "Trigger chain", theme, height)

    # Walk up the longest parent chain, then down the longest child chain.
    def walk(node, step, seen):
        chain = [node]
        while True:
            nxt = [n for n in step(node) if n not in seen]
            if not nxt:
                break
            node = sorted(nxt)[0]
            seen.add(node)
            chain.append(node)
        return chain

    up = walk(rule_id, graph.predecessors, {rule_id})[1:][::-1]
    down = walk(rule_id, graph.successors, {rule_id})[1:]
    chain = up + [rule_id] + down

    xs = list(range(len(chain)))
    ys = [0] * len(chain)
    colors, sizes, labels, hovers = [], [], [], []
    for node in chain:
        data = graph.nodes[node]
        if data.get("external"):
            colors.append("#475569")
        else:
            colors.append(color_for_label(get_severity_level(data.get("level", 0))))
        sizes.append(44 if node == rule_id else 34)
        rule = by_id.get(node)
        desc = (rule.description if rule else data.get("description", "")) or ""
        labels.append(f"<b>{node}</b>")
        hovers.append(f"<b>Rule {node}</b><br>level {data.get('level', 0)}<br>{desc[:140]}")

    fig = go.Figure()
    if len(chain) > 1:
        fig.add_trace(go.Scatter(
            x=xs, y=ys, mode="lines",
            line=dict(color="#38bdf8", width=3), hoverinfo="skip",
            showlegend=False,
        ))
    fig.add_trace(go.Scatter(
        x=xs, y=ys, mode="markers+text",
        marker=dict(size=sizes, color=colors,
                    line=dict(width=2, color=palette["paper"])),
        text=labels, textposition="bottom center",
        textfont=dict(color=palette["font"], size=12),
        hovertext=hovers, hoverinfo="text", showlegend=False,
    ))
    for i in range(len(chain) - 1):
        fig.add_annotation(x=xs[i + 1] - 0.12, y=0, ax=xs[i] + 0.12, ay=0,
                           xref="x", yref="y", axref="x", ayref="y",
                           showarrow=True, arrowhead=2, arrowsize=1.5,
                           arrowwidth=2, arrowcolor="#38bdf8")

    fig = _base_layout(fig, f"Trigger chain for rule {rule_id}", theme, height)
    fig.update_layout(
        xaxis=dict(visible=False, range=[-0.6, len(chain) - 0.4]),
        yaxis=dict(visible=False, range=[-1, 1]),
    )
    return fig
