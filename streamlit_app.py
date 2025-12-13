import streamlit as st
import os
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional
from xml.dom import minidom

from wazuh_parser import parse_wazuh_xml, RuleData, summarize_filter_logic
from visualizations.flowchart import create_rule_network_visualization

st.set_page_config(
    page_title="Wazuh Rule Visualizer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def load_sample_xml() -> str:
    """Load the bundled sample XML file."""
    sample_path = os.path.join(os.path.dirname(__file__), "sample_wazuh_rules.xml")
    if os.path.exists(sample_path):
        with open(sample_path, "r", encoding="utf-8") as f:
            return f.read()
    return ""


def load_sysmon_sample() -> str:
    """Load the Sysmon sample XML file for testing relationships."""
    sysmon_path = os.path.join(os.path.dirname(__file__), "sysmon_sample.xml")
    if os.path.exists(sysmon_path):
        with open(sysmon_path, "r", encoding="utf-8") as f:
            return f.read()
    return ""


def extract_raw_rule_xml(xml_content: str) -> Dict[int, str]:
    """
    Extract the raw XML string for each rule from the original XML content.

    Args:
        xml_content: Original XML content string

    Returns:
        Dictionary mapping rule_id -> raw_xml_string
    """
    rule_xml_map: Dict[int, str] = {}

    try:
        root = ET.fromstring(xml_content)
        rule_elements = root.findall(".//rule")

        for rule_elem in rule_elements:
            rule_id_str = rule_elem.get("id")
            if not rule_id_str:
                continue

            try:
                rule_id = int(rule_id_str)
            except ValueError:
                continue

            xml_string = ET.tostring(rule_elem, encoding="unicode")

            try:
                dom = minidom.parseString(xml_string)
                pretty_xml = dom.toprettyxml(indent="  ")
                lines = [line for line in pretty_xml.split("\n") if line.strip()]
                if lines and lines[0].startswith("<?xml"):
                    lines = lines[1:]
                rule_xml_map[rule_id] = "\n".join(lines)
            except Exception:
                rule_xml_map[rule_id] = xml_string

    except Exception:
        pass

    return rule_xml_map


@st.cache_data
def parse_xml_cached(xml_content: str, source: str) -> tuple:
    """
    Parse XML content with caching for performance.
    The source parameter ensures different uploads are treated separately.
    """
    return parse_wazuh_xml(xml_content)


def get_severity_level(level: int) -> str:
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


def render_instructions():
    """Render the instruction and context section."""
    st.title("🛡️ Wazuh Rule Visualizer")
    st.markdown(
        "Simple visualization of Wazuh XML security rules with interactive network graphs showing rule relationships."
    )


def render_file_upload():
    """Render the file upload section and return XML content."""
    st.subheader("📁 Load Wazuh Rules")

    col1, col2, col3, col4 = st.columns([2, 1, 1, 1])

    with col1:
        uploaded_file = st.file_uploader(
            "Upload Wazuh XML rule file",
            type=["xml"],
            help="Select a Wazuh XML file containing rule definitions",
        )

    with col2:
        st.write("")
        st.write("")
        load_sample = st.button("📋 Sample", use_container_width=True, help="Load bundled sample rules")

    with col3:
        st.write("")
        st.write("")
        load_sysmon = st.button("🖥️ Sysmon", use_container_width=True, help="Load Sysmon relationship sample")

    with col4:
        st.write("")
        st.write("")
        show_paste = st.button("📝 Paste", use_container_width=True, help="Paste XML rules directly")

    xml_content = None
    source_identifier = None

    if uploaded_file is not None:
        xml_content = uploaded_file.read().decode("utf-8", errors="replace")
        source_identifier = f"uploaded_{uploaded_file.name}_{uploaded_file.size}"
        st.success(f"✅ Loaded: {uploaded_file.name} ({len(xml_content)} bytes)")

    elif load_sample:
        xml_content = load_sample_xml()
        if xml_content:
            source_identifier = "sample_bundled"
            st.info("✅ Loaded bundled sample rules")
        else:
            st.error("❌ Sample file not found. Please upload an XML file.")

    elif load_sysmon:
        xml_content = load_sysmon_sample()
        if xml_content:
            source_identifier = "sysmon_sample"
            st.info("✅ Loaded Sysmon relationship sample")
        else:
            st.error("❌ Sysmon sample file not found. Please upload an XML file.")

    elif show_paste:
        st.session_state.show_paste_input = True

    if st.session_state.get("show_paste_input", False):
        st.markdown("**Paste Wazuh XML Rules:**")
        pasted_xml = st.text_area(
            "XML Content",
            placeholder='Paste your Wazuh rules XML here (e.g., <rules><rule id="1" level="3">...</rule></rules>)',
            height=200,
            label_visibility="collapsed",
        )

        col_submit, col_cancel = st.columns([1, 1])
        with col_submit:
            if st.button("✅ Parse Pasted Rules", use_container_width=True):
                if pasted_xml.strip():
                    xml_content = pasted_xml
                    source_identifier = f"pasted_{hash(pasted_xml) % 10000000}"
                    st.success(f"✅ Loaded pasted XML ({len(xml_content)} bytes)")
                    st.session_state.show_paste_input = False
                else:
                    st.error("❌ Please paste some XML content")

        with col_cancel:
            if st.button("❌ Cancel", use_container_width=True):
                st.session_state.show_paste_input = False

    return xml_content, source_identifier


def render_metadata_summary(rules: List[RuleData], warnings: List[str]):
    """Render key metadata and statistics."""
    if warnings:
        st.warning("⚠️ **Parsing Warnings:**")
        for warning in warnings:
            st.warning(f"• {warning}")

    if not rules:
        st.info("👆 Upload a Wazuh XML file or load the sample to get started")
        return

    st.success(f"✅ Successfully parsed **{len(rules)}** rules")
    st.subheader("📊 Rule Statistics")

    col1, col2, col3, col4 = st.columns(4)

    severity_counts: Dict[str, int] = {}
    for rule in rules:
        severity = get_severity_level(rule.level)
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    with col1:
        st.metric("Total Rules", len(rules))

    with col2:
        critical_count = severity_counts.get("Critical", 0)
        high_count = severity_counts.get("High", 0)
        st.metric("Critical + High", critical_count + high_count)

    with col3:
        rules_with_mitre = sum(1 for r in rules if r.mitre_techniques)
        st.metric("With MITRE ATT&CK", rules_with_mitre)

    with col4:
        rules_with_filters = sum(1 for r in rules if r.filter_conditions)
        st.metric("With Filters", rules_with_filters)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**Severity Distribution:**")
        for severity in ["Critical", "High", "Medium", "Low", "Ignored"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                percentage = (count / len(rules)) * 100
                st.markdown(f"• {severity}: **{count}** ({percentage:.1f}%)")

    with col2:
        all_groups = set()
        for rule in rules:
            all_groups.update(rule.groups)

        st.markdown(f"**Rule Groups ({len(all_groups)}):**")
        sorted_groups = sorted(all_groups)[:10]
        for group in sorted_groups:
            group_count = sum(1 for r in rules if group in r.groups)
            st.markdown(f"• {group}: **{group_count}**")
        if len(all_groups) > 10:
            st.markdown(f"_...and {len(all_groups) - 10} more_")


def render_connection_type_selector() -> str:
    """Render the connection type selector for the visualization."""
    st.subheader("Connection Type")
    return st.radio(
        "Connection Type",
        options=["if_sid", "if_matched_group", "if_group"],
        format_func=lambda x: {
            "if_sid": "🔗 Parent Rules (if_sid)",
            "if_matched_group": "🔀 Group Correlations (if_matched_group)",
            "if_group": "📦 Group Rules (if_group)",
        }[x],
        horizontal=True,
        label_visibility="collapsed",
        help="Choose which rule relationships to visualize",
    )


def render_rule_filters(rules: List[RuleData]) -> List[RuleData]:
    """Render global rule filters and return the filtered rule set."""
    if not rules:
        return []

    st.subheader("Filters")
    col1, col2 = st.columns(2)

    with col1:
        min_level = st.slider(
            "Min Rule Level",
            min_value=0,
            max_value=15,
            value=0,
            help="Only show rules with level greater than or equal to the selected minimum",
        )

    with col2:
        search_rule_id = st.text_input(
            "Search Rule ID",
            value="",
            placeholder="e.g., 102101, 100002",
            help="Filter and highlight specific rules by their ID",
        )

    filtered_rules = [r for r in rules if r.level >= min_level]
    if search_rule_id:
        filtered_rules = [r for r in filtered_rules if search_rule_id in str(r.rule_id)]

    st.caption(f"Showing {len(filtered_rules)} of {len(rules)} rules")
    return filtered_rules


def render_flowchart_visualization(rules: List[RuleData], connection_type: str):
    """Render network visualization for the filtered rules."""
    st.subheader("📊 Rule Relationship Network")

    if not rules:
        st.info("No rules match the current filters.")
        return

    try:
        fig = create_rule_network_visualization(rules, connection_type=connection_type)
        st.plotly_chart(fig, use_container_width=True)
    except Exception as e:
        st.error(f"❌ Error creating visualization: {str(e)}")


def render_rule_details(rules: List[RuleData], rule_xml_map: Optional[Dict[int, str]] = None):
    """Render detailed rule information in tabular/accordion format."""
    if not rules:
        st.info("No rules match the current filters.")
        return

    st.subheader("🔍 Rule Details & XML")
    st.caption("Expand a rule to inspect metadata and view its original XML definition.")

    search_query = st.text_input(
        "🔎 Search rules",
        placeholder="Search by ID, description, group, or MITRE technique...",
        help="Filter rules by any text in their ID, description, groups, or MITRE techniques",
    )

    severity_filter = st.multiselect(
        "Filter by severity",
        options=["Critical", "High", "Medium", "Low", "Ignored"],
        default=[],
        help="Select one or more severity levels to filter",
    )

    filtered_rules = rules

    if search_query:
        query_lower = search_query.lower()
        filtered_rules = [
            r for r in filtered_rules
            if (query_lower in str(r.rule_id)
                or query_lower in (r.description or "").lower()
                or any(query_lower in g.lower() for g in r.groups)
                or any(query_lower in m.lower() for m in r.mitre_techniques))
        ]

    if severity_filter:
        filtered_rules = [r for r in filtered_rules if get_severity_level(r.level) in severity_filter]

    st.caption(f"Showing {len(filtered_rules)} of {len(rules)} rules")

    sorted_rules = sorted(filtered_rules, key=lambda r: (r.level, r.rule_id), reverse=True)

    for rule in sorted_rules:
        severity = get_severity_level(rule.level)
        color = get_severity_color(rule.level)

        desc_preview = (rule.description or "").strip()
        if len(desc_preview) > 80:
            desc_preview = desc_preview[:80].rstrip() + "…"

        header_text = f"Rule {rule.rule_id} - Level {rule.level} ({severity})"
        if desc_preview:
            header_text = f"{header_text} • {desc_preview}"

        with st.expander(header_text):
            col1, col2 = st.columns([2, 1])

            with col1:
                st.markdown("**Description:**")
                st.write(rule.description if rule.description else "_No description_")

                if rule.filter_conditions:
                    st.markdown("**Filter Logic:**")
                    filter_summary = summarize_filter_logic(rule.filter_conditions)
                    st.code(filter_summary, language=None)

                if rule.detection_cues.if_sid:
                    st.markdown(f"**Parent Rule:** {rule.detection_cues.if_sid}")

                if rule.detection_cues.decoded_as:
                    st.markdown(f"**Decoded As:** `{rule.detection_cues.decoded_as}`")

            with col2:
                st.markdown(
                    f"<div style='padding: 8px; background-color: {color}; color: white; border-radius: 4px; text-align: center; font-weight: bold;'>{severity}</div>",
                    unsafe_allow_html=True,
                )

                if rule.groups:
                    st.markdown("**Groups:**")
                    for group in rule.groups:
                        st.markdown(f"• {group}")

                if rule.mitre_techniques:
                    st.markdown("**MITRE ATT&CK:**")
                    for technique in rule.mitre_techniques:
                        st.markdown(
                            f"• [{technique}](https://attack.mitre.org/techniques/{technique.replace('.', '/')})"
                        )

                if rule.cis_controls:
                    st.markdown("**CIS Controls:**")
                    for control in rule.cis_controls:
                        st.markdown(f"• {control}")

                if rule.nist_controls:
                    st.markdown("**NIST Controls:**")
                    for control in rule.nist_controls:
                        st.markdown(f"• {control}")

            if rule_xml_map and rule.rule_id in rule_xml_map:
                st.divider()
                st.markdown("**📄 Full XML Definition:**")
                st.code(rule_xml_map[rule.rule_id], language="xml")
            elif rule_xml_map is not None:
                st.divider()
                st.markdown("**📄 Full XML Definition:**")
                st.info("Original XML content not available for this rule.")


def main():
    """Main application entry point."""
    if "rules" not in st.session_state:
        st.session_state.rules = None
    if "warnings" not in st.session_state:
        st.session_state.warnings = None
    if "xml_content" not in st.session_state:
        st.session_state.xml_content = None
    if "rule_xml_map" not in st.session_state:
        st.session_state.rule_xml_map = {}
    if "show_paste_input" not in st.session_state:
        st.session_state.show_paste_input = False

    render_instructions()
    st.divider()

    xml_content, source_identifier = render_file_upload()

    if xml_content and source_identifier:
        try:
            rules, warnings = parse_xml_cached(xml_content, source_identifier)
            st.session_state.rules = rules
            st.session_state.warnings = warnings
            st.session_state.xml_content = xml_content
            st.session_state.rule_xml_map = extract_raw_rule_xml(xml_content)
        except Exception as e:
            st.error(f"❌ **Parsing Error:** {str(e)}")
            st.session_state.rules = None
            st.session_state.warnings = None
            st.session_state.xml_content = None
            st.session_state.rule_xml_map = {}

    st.divider()

    if st.session_state.rules is not None:
        render_metadata_summary(st.session_state.rules, st.session_state.warnings or [])
        st.divider()

        connection_type = render_connection_type_selector()
        st.divider()

        filtered_rules = render_rule_filters(st.session_state.rules)
        st.divider()

        render_flowchart_visualization(filtered_rules, connection_type)
        st.divider()

        render_rule_details(filtered_rules, st.session_state.rule_xml_map)
    else:
        st.info("👆 Upload a Wazuh XML file, load the sample, or paste rules to get started")

    with st.sidebar:
        st.header("ℹ️ About")
        st.markdown(
            """
            **Wazuh Rule Visualizer**

            Simple visualization of Wazuh XML security rules with network relationships.

            """
        )
        st.info("🧪 If you’re willing, please help me by trying this tool and sharing any feedback or issues you find. You can reach me here anytime.")

        if st.session_state.rules:
            st.divider()
            st.caption(f"📦 Rules: {len(st.session_state.rules)}")
            st.caption(f"⚠️ Warnings: {len(st.session_state.warnings or [])}")


if __name__ == "__main__":
    main()
