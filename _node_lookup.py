"""
Shared test helper.

Nodes are drawn as one Plotly trace per severity band (that is what makes the
graph legend work), so no single trace holds every node. Tests must search all
of them instead of indexing into fig.data.
"""


def node_text_for_rule(fig, rule_id) -> str:
    """The node label whose first line is this rule id."""
    for trace in fig.data:
        for text in getattr(trace, "text", None) or []:
            if str(rule_id) == str(text).split("<br>")[0]:
                return str(text)
    raise AssertionError(f"Node text for rule {rule_id} not found")


def node_hover_for_rule(fig, rule_id) -> str:
    """The hover card for this rule id."""
    for trace in fig.data:
        for hover in getattr(trace, "hovertext", None) or []:
            if f"<b>Rule {rule_id}</b>" in str(hover):
                return str(hover)
    raise AssertionError(f"Hover text for rule {rule_id} not found")


def all_node_texts(fig):
    """Every node label in the figure, across all severity traces."""
    texts = []
    for trace in fig.data:
        if getattr(trace, "mode", "") and "markers" in trace.mode:
            for text in getattr(trace, "text", None) or []:
                texts.append(str(text))
    return texts
