"""
Wazuh Rule Visualizer.

Load a Wazuh rules XML file and get three things:

* a health check that finds what would break wazuh-manager, with the fix
* a cleaned copy of the XML you can drop straight into etc/rules/
* a relationship graph that shows how the rules chain together
"""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple
from xml.dom import minidom

import streamlit as st

from severity import (
    SEVERITY_ORDER,
    color_for_label,
    get_severity_glyph,
    get_severity_level,
)
from visualizations.analytics import (
    create_chain_figure,
    create_group_treemap,
    create_mitre_chart,
    create_severity_bar,
)
from visualizations.flowchart import (
    EDGE_STYLES,
    build_rule_graph,
    create_rule_network_visualization,
)
from wazuh_linter import (
    LintReport,
    clean_wazuh_xml,
    format_report_text,
    issues_to_rows,
    lint_with_recovery,
)
from wazuh_parser import (
    RuleData,
    generate_debug_log,
    parse_wazuh_xml,
    summarize_filter_logic,
)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
MAX_UPLOAD_BYTES = 20 * 1024 * 1024

st.set_page_config(
    page_title="Wazuh Rule Visualizer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

SEVERITY_BADGE_CSS = """
<style>
  .wz-banner {padding:14px 18px;border-radius:10px;margin:4px 0 14px 0;
              border-left:5px solid;font-size:0.95rem;}
  .wz-ok   {background:rgba(34,197,94,.10);border-color:#22c55e;}
  .wz-bad  {background:rgba(239,68,68,.10);border-color:#ef4444;}
  .wz-warn {background:rgba(234,179,8,.10);border-color:#eab308;}
  .wz-pill {display:inline-block;padding:2px 10px;border-radius:999px;
            font-size:.75rem;font-weight:600;color:#fff;margin-right:6px;}
  .wz-fix  {background:rgba(56,189,248,.10);border-left:3px solid #38bdf8;
            padding:8px 12px;border-radius:6px;margin-top:6px;}
  .wz-legend span {margin-right:16px;font-size:.85rem;}
</style>
"""

SEVERITY_UI = {
    "error": ("🛑", "#ef4444", "Blocks the manager or the rule can never fire"),
    "warning": ("⚠️", "#eab308", "Loads, but almost certainly not what you meant"),
    "info": ("💡", "#38bdf8", "Convention and readability"),
}


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------

def _read_bundled(filename: str) -> str:
    path = os.path.join(APP_DIR, filename)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    return ""


@st.cache_data(show_spinner=False)
def parse_xml_cached(xml_content: str, source: str) -> Tuple[List[RuleData], List[str]]:
    return parse_wazuh_xml(xml_content)


@st.cache_data(show_spinner=False)
def lint_cached(xml_content: str, source: str) -> Tuple[LintReport, Optional[str], List[str]]:
    return lint_with_recovery(xml_content)


@st.cache_data(show_spinner=False)
def clean_cached(xml_content: str, source: str, reformat: bool) -> Tuple[str, List[str]]:
    return clean_wazuh_xml(xml_content, reformat=reformat)


@st.cache_data(show_spinner=False)
def extract_raw_rule_xml(xml_content: str) -> Dict[int, str]:
    """Pretty-printed XML for each rule, keyed by rule id."""
    rule_xml_map: Dict[int, str] = {}
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        return rule_xml_map

    for rule_elem in root.findall(".//rule"):
        rule_id_str = rule_elem.get("id")
        if not rule_id_str:
            continue
        try:
            rule_id = int(rule_id_str)
        except ValueError:
            continue

        xml_string = ET.tostring(rule_elem, encoding="unicode")
        try:
            pretty = minidom.parseString(xml_string).toprettyxml(indent="  ")
            lines = [line for line in pretty.split("\n") if line.strip()]
            if lines and lines[0].startswith("<?xml"):
                lines = lines[1:]
            rule_xml_map[rule_id] = "\n".join(lines)
        except Exception:
            rule_xml_map[rule_id] = xml_string
    return rule_xml_map


def _set_source(content: str, identifier: str, name: str) -> None:
    st.session_state.xml_content = content
    st.session_state.source_id = identifier
    st.session_state.source_name = name


def render_loader() -> None:
    """Sidebar data loader. Writes into session state, returns nothing."""
    st.sidebar.subheader("📁 Load rules")

    uploaded = st.sidebar.file_uploader(
        "Wazuh rules XML",
        type=["xml"],
        help="Any file with <rule> elements — local_rules.xml, a Sysmon "
             "ruleset, anything you copied out of /var/ossec/etc/rules/. "
             "Upload it here; this app never reads the manager itself.",
    )
    if uploaded is not None:
        if uploaded.size > MAX_UPLOAD_BYTES:
            st.sidebar.error(
                f"File is {uploaded.size / 1_048_576:.1f} MB. The limit is "
                f"{MAX_UPLOAD_BYTES // 1_048_576} MB — split the ruleset first."
            )
        else:
            raw = uploaded.read()
            try:
                content = raw.decode("utf-8")
            except UnicodeDecodeError:
                content = raw.decode("utf-8", errors="replace")
                st.sidebar.warning(
                    "The file is not valid UTF-8. Undecodable bytes were "
                    "replaced — Wazuh expects UTF-8, so re-save it."
                )
            identifier = f"upload:{uploaded.name}:{uploaded.size}"
            if st.session_state.get("source_id") != identifier:
                _set_source(content, identifier, uploaded.name)

    col_a, col_b = st.sidebar.columns(2)
    if col_a.button("Sample", width="stretch",
                    help="Bundled example ruleset"):
        content = _read_bundled("sample_wazuh_rules.xml")
        if content:
            _set_source(content, "sample", "sample_wazuh_rules.xml")
        else:
            st.sidebar.error("sample_wazuh_rules.xml is missing.")
    if col_b.button("Sysmon", width="stretch",
                    help="Sysmon ruleset with a real if_sid chain"):
        content = _read_bundled("sysmon_sample.xml")
        if content:
            _set_source(content, "sysmon", "sysmon_sample.xml")
        else:
            st.sidebar.error("sysmon_sample.xml is missing.")

    with st.sidebar.expander("Or paste XML"):
        pasted = st.text_area(
            "XML", height=180, label_visibility="collapsed",
            placeholder='<group name="custom,">\n  <rule id="100001" level="5">\n'
                        '    ...\n  </rule>\n</group>',
        )
        if st.button("Parse pasted XML", width="stretch"):
            if pasted.strip():
                _set_source(pasted, f"paste:{hash(pasted)}", "pasted rules")
            else:
                st.warning("Nothing to parse.")

    if st.session_state.get("xml_content"):
        st.sidebar.caption(
            f"Loaded **{st.session_state.source_name}** · "
            f"{len(st.session_state.xml_content):,} bytes"
        )
        if st.sidebar.button("Clear", width="stretch"):
            for key in ("xml_content", "source_id", "source_name"):
                st.session_state.pop(key, None)
            st.rerun()


# --------------------------------------------------------------------------
# Header
# --------------------------------------------------------------------------

def render_header(rules: List[RuleData], report: LintReport) -> None:
    counts = report.by_severity()
    score = report.health_score()
    cols = st.columns(5)
    cols[0].metric("Rules", len(rules))
    cols[1].metric("Health score", f"{score}/100")
    cols[2].metric("Errors", counts["error"],
                   delta=None if not counts["error"] else "blocks the manager",
                   delta_color="inverse")
    cols[3].metric("Warnings", counts["warning"])
    cols[4].metric("MITRE techniques",
                   len({t for r in rules for t in (r.mitre_techniques or [])}))

    if not report.parsed:
        st.markdown(
            "<div class='wz-banner wz-bad'><b>This file does not parse.</b> "
            "wazuh-manager would refuse to load it. The Health check tab has "
            "the exact line and the fix.</div>", unsafe_allow_html=True)
    elif counts["error"]:
        st.markdown(
            f"<div class='wz-banner wz-bad'><b>{counts['error']} blocking "
            f"error(s).</b> Deploying this ruleset would stop wazuh-manager "
            f"from starting, or leave rules that can never fire. See the "
            f"Health check tab.</div>", unsafe_allow_html=True)
    elif counts["warning"]:
        st.markdown(
            f"<div class='wz-banner wz-warn'><b>Loads cleanly, with "
            f"{counts['warning']} warning(s).</b> The manager will accept this "
            f"file, but some rules probably do not match what you expect."
            f"</div>", unsafe_allow_html=True)
    else:
        st.markdown(
            "<div class='wz-banner wz-ok'><b>Clean.</b> Nothing here would stop "
            "wazuh-manager loading this ruleset.</div>", unsafe_allow_html=True)


# --------------------------------------------------------------------------
# Tab: relationships
# --------------------------------------------------------------------------

def render_graph_tab(rules: List[RuleData]) -> None:
    if not rules:
        st.info("No rules parsed, so there is nothing to draw.")
        return

    controls = st.container()
    with controls:
        row1 = st.columns([1.3, 1, 1, 1.4])
        layout = row1[0].selectbox(
            "Layout",
            ["hierarchy", "force", "groups", "circular", "shell"],
            format_func=lambda v: {
                "hierarchy": "Hierarchy (parents on top)",
                "force": "Force directed",
                "groups": "Clustered by group",
                "circular": "Circle",
                "shell": "Shells",
            }[v],
            help="Hierarchy is the one to use for reading if_sid chains.",
        )
        theme = row1[1].selectbox("Theme", ["dark", "light"], index=0)
        min_level = row1[2].slider("Min level", 0, 16, 0,
                                   help="Hide rules below this Wazuh level.")
        all_groups = sorted({g for r in rules for g in (r.groups or [])})
        picked_groups = row1[3].multiselect(
            "Groups", all_groups, default=[],
            help="Empty means every group.",
        )

        row2 = st.columns(4)
        show_if_sid = row2[0].checkbox("Parent (if_sid)", value=True)
        show_if_matched_sid = row2[1].checkbox("Correlation (if_matched_sid)", value=True)
        show_if_matched_group = row2[2].checkbox("Group correlation", value=True)
        show_if_group = row2[3].checkbox("Group parent (if_group)", value=True)

        row3 = st.columns([1.6, 1, 1, 1])
        rule_ids = sorted(r.rule_id for r in rules)
        focus = row3[0].selectbox(
            "Focus on a rule",
            ["(none)"] + [str(r) for r in rule_ids],
            help="Dims everything outside that rule's ancestors and descendants.",
        )
        show_external = row3[1].checkbox(
            "Show rules not in this file", value=True,
            help="Draws if_sid targets that this file does not define, as "
                 "hollow grey nodes. That is how you spot a broken chain.")
        hide_isolated = row3[2].checkbox(
            "Hide unconnected rules", value=False,
            help="Removes rules with no links at all.")
        row4 = st.columns([1, 1, 2])
        show_desc = row4[0].checkbox("Description on node", value=False)
        show_cond = row4[1].checkbox("Condition on node", value=False)

    focus_id = None if focus == "(none)" else int(focus)

    fig = create_rule_network_visualization(
        rules,
        show_if_sid=show_if_sid,
        show_if_matched_sid=show_if_matched_sid,
        show_if_matched_group=show_if_matched_group,
        show_if_group=show_if_group,
        min_level=min_level,
        selected_groups=picked_groups or None,
        show_desc_on_node=show_desc,
        show_cond_on_node=show_cond,
        layout=layout,
        theme=theme,
        focus_rule_id=focus_id,
        show_external=show_external,
        show_isolated=not hide_isolated,
    )
    st.plotly_chart(fig, width="stretch",
                    config={"scrollZoom": True, "displaylogo": False})

    st.caption(
        "Drag to pan, scroll to zoom, click a legend entry to hide that link "
        "type, double-click to reset. Hover a node for its conditions, "
        "parents and children."
    )

    graph, meta = build_rule_graph(
        rules, show_if_sid, show_if_matched_sid,
        show_if_matched_group, show_if_group, show_external,
    )

    if focus_id is not None and focus_id in graph:
        st.plotly_chart(
            create_chain_figure(rules, graph, focus_id, theme=theme),
            width="stretch", config={"displaylogo": False},
        )

    with st.expander("What the colours mean"):
        legend = ["**Links**"]
        for kind, style in EDGE_STYLES.items():
            count = meta["edge_counts"].get(kind, 0)
            legend.append(
                f"- <span style='color:{style['color']}'>▬</span> "
                f"**{style['label']}** — {style['desc']} · {count} in this file"
            )
        legend.append("")
        legend.append("**Nodes** — size and colour follow the Wazuh level")
        for label in SEVERITY_ORDER:
            legend.append(
                f"- <span style='color:{color_for_label(label)}'>●</span> {label}"
            )
        legend.append(
            "- <span style='color:#475569'>○</span> Hollow grey — referenced "
            "but not defined in this file"
        )
        st.markdown("\n".join(legend), unsafe_allow_html=True)

    if meta["external_ids"]:
        ext = sorted(meta["external_ids"])
        st.warning(
            f"**{len(ext)} referenced rule(s) are not in this file:** "
            f"{', '.join(str(e) for e in ext[:20])}"
            f"{' …' if len(ext) > 20 else ''}. "
            "If they exist in Wazuh's bundled ruleset the chain works on the "
            "manager. If not, every child of them is dead code — check with "
            "`/var/ossec/bin/wazuh-logtest`."
        )
    if meta["truncated_groups"]:
        names = ", ".join(f"{g} ({n} rules)" for g, n in meta["truncated_groups"][:5])
        st.info(
            f"Group links were capped at 30 edges per group to keep the graph "
            f"readable: {names}."
        )


# --------------------------------------------------------------------------
# Tab: health check
# --------------------------------------------------------------------------

def render_health_tab(xml_content: str, source_id: str, report: LintReport,
                      repaired: Optional[str], recovery_fixes: List[str]) -> None:
    counts = report.by_severity()

    if repaired:
        st.info(
            "The file has a syntax error, so it was auto-cleaned before the "
            "deeper checks could run. The cleaned XML is at the bottom of this "
            "tab."
        )

    if not report.issues:
        st.success("No issues found. This ruleset is clean.")
    else:
        pick = st.multiselect(
            "Show",
            ["error", "warning", "info"],
            default=[s for s in ("error", "warning", "info") if counts[s]],
            format_func=lambda s: f"{SEVERITY_UI[s][0]} {s} ({counts[s]})",
        )

        for severity in ("error", "warning", "info"):
            if severity not in pick:
                continue
            bucket = [i for i in report.issues if i.severity == severity]
            if not bucket:
                continue
            glyph, colour, blurb = SEVERITY_UI[severity]
            st.markdown(
                f"### {glyph} {severity.title()}s · {len(bucket)}"
                f"<br><span style='color:#94a3b8;font-size:.85rem'>{blurb}</span>",
                unsafe_allow_html=True,
            )
            for issue in bucket:
                header = f"{issue.title} — {issue.location()}  ·  `{issue.code}`"
                with st.expander(header, expanded=severity == "error" and len(bucket) <= 5):
                    st.markdown(issue.detail.replace("\n", "  \n"))
                    st.markdown(
                        f"<div class='wz-fix'><b>How to fix</b><br>"
                        f"{issue.recommendation}</div>",
                        unsafe_allow_html=True,
                    )

    st.divider()
    st.subheader("🧹 Clean the XML")
    st.caption(
        "Repairs the mechanical problems: encoding, bare `&`, illegal `--` in "
        "comments, tabs, trailing whitespace, missing group commas and "
        "indentation. It never rewrites your detection logic — level, id, "
        "regex and description are left exactly as you wrote them."
    )

    reformat = st.checkbox(
        "Also reindent and normalise the document", value=True,
        help="Re-serialises the XML with two-space indentation. Turn this off "
             "to keep your original formatting byte for byte and only fix the "
             "characters that break the parser.",
    )

    cleaned, fixes = clean_cached(xml_content, source_id, reformat)

    if not fixes:
        st.success("Nothing to clean — the file is already tidy.")
    else:
        st.markdown("**Applied:**")
        for fix in fixes:
            st.markdown(f"- {fix}")

    after = lint_cached(cleaned, f"{source_id}:cleaned:{reformat}")[0]
    delta_cols = st.columns(3)
    delta_cols[0].metric("Health score", f"{after.health_score()}/100",
                         delta=after.health_score() - report.health_score())
    delta_cols[1].metric("Errors after cleaning", len(after.errors),
                         delta=len(after.errors) - len(report.errors),
                         delta_color="inverse")
    delta_cols[2].metric("Warnings after cleaning", len(after.warnings),
                         delta=len(after.warnings) - len(report.warnings),
                         delta_color="inverse")

    if after.errors:
        st.warning(
            f"{len(after.errors)} error(s) still need a human. Cleaning only "
            "fixes syntax and formatting — duplicate ids, bad levels, missing "
            "descriptions and broken if_sid chains are decisions, not typos."
        )

    dl = st.columns(2)
    dl[0].download_button(
        "⬇️ Download cleaned XML",
        data=cleaned,
        file_name="cleaned_rules.xml",
        mime="application/xml",
        width="stretch",
    )
    dl[1].download_button(
        "⬇️ Download health report",
        data=format_report_text(report),
        file_name="wazuh_health_report.txt",
        mime="text/plain",
        width="stretch",
    )

    with st.expander("Preview cleaned XML"):
        st.code(cleaned, language="xml")

    with st.expander("Findings as a table"):
        rows = issues_to_rows(report)
        if rows:
            st.dataframe(rows, width="stretch", hide_index=True)
        else:
            st.write("Nothing to show.")

    with st.expander("Optional: what to do on the manager after this"):
        st.markdown(
            """
These steps run on your Wazuh manager, by hand, once you are happy with the
cleaned file. Nothing here is required to use this app.

1. Copy the cleaned file to `/var/ossec/etc/rules/local_rules.xml` on the manager.
2. Dry-run it before restarting anything:
   ```bash
   /var/ossec/bin/wazuh-logtest -t
   ```
   That validates the whole ruleset and prints the first rule it cannot load.
3. Restart and watch the log:
   ```bash
   systemctl restart wazuh-manager
   tail -f /var/ossec/logs/ossec.log
   ```
4. If the manager will not start, the error is almost always one of the
   blocking errors above: a duplicated rule id, a missing description, an
   `if_sid` pointing at a rule that does not exist, or invalid XML.
"""
        )


# --------------------------------------------------------------------------
# Tab: coverage
# --------------------------------------------------------------------------

def render_coverage_tab(rules: List[RuleData], report: LintReport) -> None:
    if not rules:
        st.info("No rules parsed.")
        return

    top = st.columns([1, 1])
    with top[0]:
        st.plotly_chart(create_severity_bar(rules), width="stretch",
                        config={"displaylogo": False})
    with top[1]:
        stats = report.stats or {}
        st.markdown("**Structure**")
        st.markdown(
            f"- Rule groups: **{len(stats.get('known_groups', []))}**\n"
            f"- Rules nothing builds on and that build on nothing: "
            f"**{len(stats.get('orphan_rules', []))}**\n"
            f"- References to rules outside this file: "
            f"**{len(stats.get('dangling_parents', []))}**\n"
            f"- Circular if_sid chains: **{len(stats.get('cycles', []))}**"
        )
        orphans = stats.get("orphan_rules", [])
        if orphans:
            with st.expander(f"Unconnected rules ({len(orphans)})"):
                st.write(", ".join(str(o) for o in sorted(orphans)))
                st.caption(
                    "Standalone rules are fine when they match raw events "
                    "directly. They are a problem when you meant them to sit "
                    "under a parent — add an <if_sid>."
                )

    st.plotly_chart(create_group_treemap(rules), width="stretch",
                    config={"displaylogo": False})

    mitre_fig = create_mitre_chart(rules)
    if mitre_fig is not None:
        st.plotly_chart(mitre_fig, width="stretch",
                        config={"displaylogo": False})
    else:
        st.info(
            "No MITRE ATT&CK techniques in this ruleset. Add "
            "`<mitre><id>T1059.001</id></mitre>` to your rules so alerts map "
            "onto the ATT&CK matrix in the dashboard."
        )


# --------------------------------------------------------------------------
# Tab: rule browser
# --------------------------------------------------------------------------

def render_rules_tab(rules: List[RuleData], rule_xml_map: Dict[int, str]) -> None:
    if not rules:
        st.info("No rules parsed.")
        return

    row = st.columns([2, 1.4, 1])
    query = row[0].text_input(
        "Search", placeholder="rule id, description, group or MITRE technique",
        label_visibility="collapsed",
    )
    picked = row[1].multiselect("Severity", SEVERITY_ORDER, default=[],
                                label_visibility="collapsed",
                                placeholder="Any severity")
    order = row[2].selectbox("Sort", ["Level, high first", "Rule id"],
                             label_visibility="collapsed")

    shown = rules
    if query:
        q = query.lower()
        shown = [
            r for r in shown
            if q in str(r.rule_id)
            or q in (r.description or "").lower()
            or any(q in g.lower() for g in (r.groups or []))
            or any(q in m.lower() for m in (r.mitre_techniques or []))
        ]
    if picked:
        shown = [r for r in shown if get_severity_level(r.level) in picked]

    if order == "Rule id":
        shown = sorted(shown, key=lambda r: r.rule_id)
    else:
        shown = sorted(shown, key=lambda r: (r.level, r.rule_id), reverse=True)

    st.caption(f"{len(shown)} of {len(rules)} rules")

    for rule in shown[:300]:
        label = get_severity_level(rule.level)
        desc = (rule.description or "").strip()
        preview = desc[:90] + "…" if len(desc) > 90 else desc
        header = (f"{get_severity_glyph(rule.level)} **{rule.rule_id}** · "
                  f"level {rule.level} · {preview or 'no description'}")

        with st.expander(header):
            left, right = st.columns([2, 1])
            with left:
                st.markdown(f"**Description** — {desc or '_none_'}")
                if rule.filter_conditions:
                    st.markdown("**Filter logic**")
                    st.code(summarize_filter_logic(rule.filter_conditions), language=None)
                parents = list(getattr(rule.detection_cues, "if_sids", None) or [])
                if not parents and rule.detection_cues.if_sid is not None:
                    parents = [rule.detection_cues.if_sid]
                if parents:
                    st.markdown(f"**Parent rules** — {', '.join(str(p) for p in parents)}")
                if rule.detection_cues.if_matched_sid:
                    st.markdown(
                        "**Correlates on** — "
                        + ", ".join(str(s) for s in rule.detection_cues.if_matched_sid)
                    )
                if rule.detection_cues.decoded_as:
                    st.markdown(f"**Decoded as** — `{rule.detection_cues.decoded_as}`")
            with right:
                st.markdown(
                    f"<div style='padding:8px;background:{color_for_label(label)};"
                    f"color:#fff;border-radius:6px;text-align:center;"
                    f"font-weight:600'>{label}</div>",
                    unsafe_allow_html=True,
                )
                if rule.groups:
                    st.markdown("**Groups**")
                    st.markdown("\n".join(f"- {g}" for g in rule.groups))
                if rule.mitre_techniques:
                    st.markdown("**MITRE ATT&CK**")
                    st.markdown("\n".join(
                        f"- [{t}](https://attack.mitre.org/techniques/{t.replace('.', '/')})"
                        for t in rule.mitre_techniques
                    ))
                for title, values in (("CIS", rule.cis_controls),
                                      ("NIST", rule.nist_controls)):
                    if values:
                        st.markdown(f"**{title}**")
                        st.markdown("\n".join(f"- {v}" for v in values))

            if rule.rule_id in rule_xml_map:
                st.markdown("**XML**")
                st.code(rule_xml_map[rule.rule_id], language="xml")

    if len(shown) > 300:
        st.info(f"Showing the first 300 of {len(shown)} matches. Narrow the search.")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def render_about() -> None:
    st.sidebar.divider()
    with st.sidebar.expander("ℹ️ About"):
        st.markdown(
            "Loads a Wazuh rules file, checks it for anything that would break "
            "`wazuh-manager`, hands back a cleaned copy, and draws how the "
            "rules chain together.\n\n"
            "**Runs standalone.** You upload the XML; the app never connects to "
            "a Wazuh manager, reads `/var/ossec`, or needs to sit on the "
            "manager host. Deploy it on any machine."
        )
    with st.sidebar.expander("📬 Contact / feedback"):
        st.markdown(
            "🛡️ [Hanif Kurniawan Atmanto]"
            "(https://wazuh.com/ambassadors/hanif-kurniawan-atmanto/)"
        )
        st.markdown("💬 [Wazuh Community Slack](https://wazuh.com/community/)")
        st.caption(
            'Search "Hanif K" and DM me. Include the error, what you clicked, '
            'and the rule XML if you can share it.'
        )


def main() -> None:
    st.markdown(SEVERITY_BADGE_CSS, unsafe_allow_html=True)
    st.title("🛡️ Wazuh Rule Visualizer")
    st.caption(
        "Check a ruleset before it reaches the manager, clean it up, and see "
        "how the rules connect."
    )

    render_loader()
    render_about()

    xml_content = st.session_state.get("xml_content")
    if not xml_content:
        st.info("Load a rules file from the sidebar, or hit **Sample** to try it.")
        left, right = st.columns(2)
        left.markdown(
            "#### What this finds\n"
            "- XML that `wazuh-manager` refuses to load, with the line number\n"
            "- Duplicate rule ids, levels outside 0-16, missing descriptions\n"
            "- `if_sid` pointing at a rule that does not exist\n"
            "- Circular rule chains\n"
            "- PCRE syntax handed to OS_Regex, so the rule silently never matches\n"
            "- `frequency` with no `timeframe` or no `if_matched_*` anchor\n"
            "- Rules with no condition at all, which match every event"
        )
        right.markdown(
            "#### What you get back\n"
            "- A cleaned XML file you can drop into `etc/rules/`\n"
            "- A plain-text health report with a fix for every finding\n"
            "- A relationship graph you can focus on one rule at a time\n"
            "- Severity and MITRE ATT&CK coverage for the whole ruleset"
        )
        return

    source_id = st.session_state.get("source_id", "unknown")
    report, repaired, recovery_fixes = lint_cached(xml_content, source_id)

    parse_source = repaired or xml_content
    rules, warnings = parse_xml_cached(parse_source, source_id + (":r" if repaired else ""))
    rule_xml_map = extract_raw_rule_xml(parse_source)

    render_header(rules, report)

    if warnings:
        with st.expander(f"Parser notes ({len(warnings)})"):
            for warning in warnings:
                st.write(f"- {warning}")

    tabs = st.tabs([
        "🕸️ Relationships",
        f"🩺 Health check ({len(report.errors) + len(report.warnings)})",
        "📊 Coverage",
        "📋 Rules",
        "🐛 Debug",
    ])

    with tabs[0]:
        render_graph_tab(rules)
    with tabs[1]:
        render_health_tab(xml_content, source_id, report, repaired, recovery_fixes)
    with tabs[2]:
        render_coverage_tab(rules, report)
    with tabs[3]:
        render_rules_tab(rules, rule_xml_map)
    with tabs[4]:
        st.caption("Everything the parser pulled out of the XML, rule by rule.")
        if rules:
            log = generate_debug_log(rules)
            st.download_button("⬇️ Download debug log", data=log,
                               file_name="wazuh_debug_log.txt", mime="text/plain")
            st.code(log, language=None)
        else:
            st.write("No rules parsed.")


if __name__ == "__main__":
    main()
