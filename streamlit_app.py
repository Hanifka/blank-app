import streamlit as st
import os
from typing import List, Optional
from wazuh_parser import parse_wazuh_xml, RuleData, rule_to_dict, summarize_filter_logic, extract_relationships, generate_debug_log
from visualizations.flowchart import create_sankey_diagram, create_node_link_diagram

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
    
    with st.expander("📖 About Wazuh Rules", expanded=False):
        st.markdown("""
        ### What are Wazuh Rules?
        
        Wazuh is an open-source security monitoring platform that uses **XML-based rules** to detect 
        security threats, compliance violations, and system anomalies. Each rule defines:
        
        - **Detection Logic**: Pattern matching, frequency analysis, and field-based conditions
        - **Severity Levels**: From 0 (ignored) to 15 (critical)
        - **Metadata**: MITRE ATT&CK techniques, CIS/NIST controls, rule groups
        - **Rule Hierarchy**: Parent-child relationships via `if_sid` references
        
        ### How to Use This Tool
        
        1. **Upload** your Wazuh XML rule file using the file uploader
        2. **Preview** the parsed rules, metadata, and detection logic
        3. **Analyze** rule distribution by severity, groups, and compliance frameworks
        4. **Prepare** for simulation and visualization features (coming soon!)
        
        ### Severity Level Guide
        
        | Level | Classification | Description |
        |-------|---------------|-------------|
        | 0 | Ignored | No alert generated |
        | 1-3 | Low | Informational events |
        | 4-6 | Medium | Notable events requiring attention |
        | 7-9 | High | Important security events |
        | 10-15 | Critical | Critical threats requiring immediate action |
        """)


def render_file_upload():
    """Render the file upload section and return XML content."""
    st.subheader("📁 Load Wazuh Rules")
    
    col1, col2, col3, col4 = st.columns([2, 1, 1, 1])
    
    with col1:
        uploaded_file = st.file_uploader(
            "Upload Wazuh XML rule file",
            type=["xml"],
            help="Select a Wazuh XML file containing rule definitions"
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
        xml_content = uploaded_file.read().decode("utf-8")
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
            placeholder="Paste your Wazuh rules XML here (e.g., <rules><rule id=\"1\" level=\"3\">...</rule></rules>)",
            height=200,
            label_visibility="collapsed"
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
    
    severity_counts = {}
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


def render_relationship_debug_section(rules: List[RuleData], xml_content: str):
    """Render relationship debugging section with logs and XML display."""
    st.subheader("🔍 Relationships Debug Log")
    
    # Extract relationships for debugging
    relationships = extract_relationships(rules)
    
    if relationships:
        st.markdown("**Extracted Relationships (copyable format):**")
        
        # Create a copyable text area with all relationships
        debug_lines = []
        for rel in relationships:
            if rel["relationship_type"] == "if_sid":
                debug_lines.append(f"Rule {rel['source_rule_id']} --if_sid--> {rel['target_rule_id']}")
            elif rel["relationship_type"] == "if_matched_group":
                debug_lines.append(f"Rule {rel['source_rule_id']} --if_matched_group--> {rel['target_group']}")
            elif rel["relationship_type"] == "if_group":
                debug_lines.append(f"Rule {rel['source_rule_id']} --if_group--> {rel['target_group']}")
        
        debug_text = "\n".join(debug_lines)
        st.text_area("Debug Log", value=debug_text, height=150, help="Copy this output to verify parser accuracy")
        
        # Show relationship counts by type
        col1, col2, col3 = st.columns(3)
        with col1:
            if_sid_count = sum(1 for r in relationships if r["relationship_type"] == "if_sid")
            st.metric("if_sid relationships", if_sid_count)
        with col2:
            if_matched_count = sum(1 for r in relationships if r["relationship_type"] == "if_matched_group")
            st.metric("if_matched_group relationships", if_matched_count)
        with col3:
            if_group_count = sum(1 for r in relationships if r["relationship_type"] == "if_group")
            st.metric("if_group relationships", if_group_count)
    else:
        st.info("No relationships found in the parsed rules.")
    
    # Color-coded rule display
    st.markdown("**Rule Classification:**")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown('<span style="color:blue">🔵</span> **Parent rules** (referenced by if_sid)', unsafe_allow_html=True)
    with col2:
        st.markdown('<span style="color:green">🟢</span> **if_matched_group rules**', unsafe_allow_html=True)
    with col3:
        st.markdown('<span style="color:orange">🟠</span> **if_group rules**', unsafe_allow_html=True)
    with col4:
        st.markdown('<span style="color:gold">🟡</span> **Child/dependent rules**', unsafe_allow_html=True)
    
    # Show rules with color coding
    st.markdown("**Parsed Rules with Color Coding:**")
    
    # Create rule list with color coding
    for rule in rules:
        rule_color = "black"  # default
        
        # Determine rule type and color
        is_parent = any(r["target_rule_id"] == rule.rule_id and r["relationship_type"] == "if_sid" for r in relationships)
        has_if_matched_group = bool(rule.detection_cues.if_matched_groups)
        has_if_group = bool(rule.detection_cues.if_groups)
        has_if_sid = bool(rule.detection_cues.if_sid)
        
        if is_parent:
            rule_color = "blue"
            rule_type = "🔵 Parent"
        elif has_if_matched_group:
            rule_color = "green"
            rule_type = "🟢 if_matched_group"
        elif has_if_group:
            rule_color = "orange"
            rule_type = "🟠 if_group"
        elif has_if_sid:
            rule_color = "gold"
            rule_type = "🟡 Child"
        else:
            rule_type = "⚪ Standalone"
        
        # Display rule with color
        rule_info = f"{rule_type} - Rule {rule.rule_id} (Level {rule.level}): {rule.description[:80]}{'...' if len(rule.description) > 80 else ''}"
        
        # Show relationship info if available
        if has_if_sid:
            rule_info += f" → Parent: {rule.detection_cues.if_sid}"
        if rule.detection_cues.if_matched_groups:
            rule_info += f" → Groups: {', '.join(rule.detection_cues.if_matched_groups)}"
        if rule.detection_cues.if_groups:
            rule_info += f" → Groups: {', '.join(rule.detection_cues.if_groups)}"
        
        st.markdown(f'<span style="color:{rule_color}">{rule_info}</span>', unsafe_allow_html=True)
    
    # Raw XML display with syntax highlighting
    with st.expander("📄 View Raw XML"):
        st.code(xml_content, language="xml", line_numbers=True)


def render_flowchart_visualization(rules: List[RuleData]):
    """Render interactive flowchart visualizations."""
    if not rules:
        return
    
    st.subheader("📊 Rule Flow Visualization")
    
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        viz_type = st.selectbox(
            "Visualization Type",
            options=["Sankey Diagram", "Interactive Network"],
            help="Choose how to visualize rule flows"
        )
    
    with col2:
        min_severity = st.select_slider(
            "Min Severity",
            options=list(range(0, 16)),
            value=0,
            help="Filter rules by minimum severity level"
        )
    
    with col3:
        if viz_type == "Sankey Diagram":
            layout_density = st.selectbox(
                "Layout",
                options=["compact", "normal", "sparse"],
                help="Adjust diagram density"
            )
        else:
            connection_type = st.selectbox(
                "Connection Type",
                options=["if_sid", "if_matched_group", "if_group"],
                format_func=lambda x: {
                    "if_sid": "Parent Chain (if_sid)",
                    "if_matched_group": "Group Correlation (if_matched_group)",
                    "if_group": "Group Correlation (if_group)"
                }[x],
                help="Choose which relationship type to visualize"
            )
    
    if viz_type == "Interactive Network":
        all_groups = sorted({g for rule in rules for g in rule.groups if g})
        selected_groups = None
        if all_groups:
            selected_groups = st.multiselect(
                "Filter by group (optional)",
                options=all_groups,
                help="Limit the network to specific rule groups"
            )
    
    try:
        if viz_type == "Sankey Diagram":
            fig = create_sankey_diagram(
                rules,
                min_level=min_severity,
                layout_density=layout_density
            )
            st.plotly_chart(fig, use_container_width=True, config={"responsive": True})
        else:
            network_result = create_node_link_diagram(
                rules,
                min_level=min_severity,
                layout_type="hierarchical",
                connection_type=connection_type,
                selected_groups=selected_groups if selected_groups else None,
            )
            if network_result.get("is_empty"):
                st.info(network_result.get("message", "No network data to display"))
            else:
                st.components.v1.html(
                    network_result["html"],
                    height=network_result.get("height", 720),
                    scrolling=True
                )
    except Exception as e:
        st.error(f"❌ Error rendering visualization: {str(e)}")


def render_debug_extraction_log(rules: List[RuleData]):
    """Render comprehensive debug log of all extracted values from XML."""
    if not rules:
        return
    
    st.subheader("🐛 XML Extraction Debug Log")
    st.caption("Complete list of all extracted values for verification")
    
    debug_log = generate_debug_log(rules)
    
    col1, col2 = st.columns([3, 1])
    with col1:
        st.text_area(
            "Debug Log (copyable)",
            value=debug_log,
            height=400,
            disabled=True,
            help="Copy this entire log to verify parser accuracy"
        )
    with col2:
        st.write("")
        if st.button("📋 Copy All", use_container_width=True, help="Copy entire debug log to clipboard"):
            st.toast("📋 Debug log copied to clipboard!", icon="✅")


def render_rule_details(rules: List[RuleData]):
    """Render detailed rule information in tabular/accordion format."""
    if not rules:
        return
    
    st.subheader("🔍 Rule Details")
    
    search_query = st.text_input(
        "🔎 Search rules",
        placeholder="Search by ID, description, group, or MITRE technique...",
        help="Filter rules by any text in their ID, description, groups, or MITRE techniques"
    )
    
    severity_filter = st.multiselect(
        "Filter by severity",
        options=["Critical", "High", "Medium", "Low", "Ignored"],
        default=[],
        help="Select one or more severity levels to filter"
    )
    
    filtered_rules = rules
    
    if search_query:
        query_lower = search_query.lower()
        filtered_rules = [
            r for r in filtered_rules
            if (query_lower in str(r.rule_id) or
                query_lower in r.description.lower() or
                any(query_lower in g.lower() for g in r.groups) or
                any(query_lower in m.lower() for m in r.mitre_techniques))
        ]
    
    if severity_filter:
        filtered_rules = [
            r for r in filtered_rules
            if get_severity_level(r.level) in severity_filter
        ]
    
    st.caption(f"Showing {len(filtered_rules)} of {len(rules)} rules")
    
    sorted_rules = sorted(filtered_rules, key=lambda r: (r.level, r.rule_id), reverse=True)
    
    for rule in sorted_rules:
        severity = get_severity_level(rule.level)
        color = get_severity_color(rule.level)
        
        header = f"**Rule {rule.rule_id}** • Level {rule.level} ({severity})"
        
        with st.expander(header):
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.markdown(f"**Description:**")
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
                st.markdown(f"<div style='padding: 8px; background-color: {color}; color: white; border-radius: 4px; text-align: center; font-weight: bold;'>{severity}</div>", unsafe_allow_html=True)
                
                if rule.groups:
                    st.markdown("**Groups:**")
                    for group in rule.groups:
                        st.markdown(f"• {group}")
                
                if rule.mitre_techniques:
                    st.markdown("**MITRE ATT&CK:**")
                    for technique in rule.mitre_techniques:
                        st.markdown(f"• [{technique}](https://attack.mitre.org/techniques/{technique.replace('.', '/')})")
                
                if rule.cis_controls:
                    st.markdown("**CIS Controls:**")
                    for control in rule.cis_controls:
                        st.markdown(f"• {control}")
                
                if rule.nist_controls:
                    st.markdown("**NIST Controls:**")
                    for control in rule.nist_controls:
                        st.markdown(f"• {control}")


def main():
    """Main application entry point."""
    if "rules" not in st.session_state:
        st.session_state.rules = None
    if "warnings" not in st.session_state:
        st.session_state.warnings = None
    if "xml_content" not in st.session_state:
        st.session_state.xml_content = None
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
        except Exception as e:
            st.error(f"❌ **Parsing Error:** {str(e)}")
            st.session_state.rules = None
            st.session_state.warnings = None
            st.session_state.xml_content = None
    
    st.divider()
    
    if st.session_state.rules is not None:
        render_metadata_summary(st.session_state.rules, st.session_state.warnings or [])
        
        st.divider()
        
        render_debug_extraction_log(st.session_state.rules)
        
        st.divider()
        
        render_relationship_debug_section(st.session_state.rules, st.session_state.xml_content)
        
        st.divider()
        
        render_flowchart_visualization(st.session_state.rules)
        
        st.divider()
        
        render_rule_details(st.session_state.rules)
    else:
        st.info("👆 Upload a Wazuh XML file, load the sample, or paste rules to get started")
    
    with st.sidebar:
        st.header("ℹ️ About")
        st.markdown("""
        **Wazuh Rule Visualizer**
        
        Version: 1.1.0
        
        This tool parses and visualizes Wazuh XML security rules, helping analysts understand 
        detection logic, severity levels, and compliance mappings.
        
        **Features:**
        - 📁 XML file upload with validation
        - 📝 Direct XML paste input
        - 📊 Rule statistics and metrics
        - 📈 Interactive flowchart visualizations (Sankey & Node-Link)
        - 🔍 Search and filter capabilities
        - 🎯 MITRE ATT&CK integration
        - 🔄 Cached parsing for performance
        
        **Coming Soon:**
        - 🎮 Rule simulation engine
        - 📤 Export capabilities
        """)
        
        if st.session_state.rules:
            st.divider()
            st.subheader("🔧 Debug Info")
            st.caption(f"Rules in memory: {len(st.session_state.rules)}")
            st.caption(f"Warnings: {len(st.session_state.warnings or [])}")
            if st.session_state.xml_content:
                st.caption(f"XML size: {len(st.session_state.xml_content)} bytes")


if __name__ == "__main__":
    main()
