"""
Example Streamlit integration with the Wazuh XML parser.

This file demonstrates how to integrate the wazuh_parser module into a Streamlit
application for uploading, parsing, and visualizing Wazuh XML rules.

To use this as a reference, examine the key patterns and adapt them to your
specific Streamlit app requirements.
"""

import streamlit as st
from wazuh_parser import (
    parse_wazuh_xml,
    summarize_filter_logic,
    rule_to_dict,
)
import json


def main():
    """Main Streamlit app demonstrating parser integration."""
    st.set_page_config(
        page_title="Wazuh Rule Visualizer",
        page_icon="🔍",
        layout="wide",
    )

    st.title("🔍 Wazuh Rule Parser & Visualizer")
    st.write(
        "Upload Wazuh XML rule files to parse, validate, and visualize detection rules."
    )

    # Sidebar controls
    st.sidebar.header("Upload Rules")
    uploaded_files = st.sidebar.file_uploader(
        "Select Wazuh XML files",
        type=["xml"],
        accept_multiple_files=True,
        help="Upload one or more Wazuh rule XML files",
    )

    if not uploaded_files:
        st.info("👈 Upload a Wazuh XML file to get started")
        return

    # Parse all uploaded files
    all_rules = []
    all_warnings = []

    progress_bar = st.progress(0)
    for idx, uploaded_file in enumerate(uploaded_files):
        try:
            xml_content = uploaded_file.read().decode("utf-8")
            rules, warnings = parse_wazuh_xml(xml_content)

            all_rules.extend(rules)
            all_warnings.extend(
                [f"{uploaded_file.name}: {w}" for w in warnings]
            )

            progress_bar.progress((idx + 1) / len(uploaded_files))
        except Exception as e:
            st.error(f"Error processing {uploaded_file.name}: {str(e)}")

    if not all_rules:
        st.error("❌ No valid rules found in uploaded files")
        if all_warnings:
            st.subheader("Parsing Issues")
            for warning in all_warnings:
                st.warning(warning)
        return

    # Display summary
    st.success(f"✅ Successfully parsed {len(all_rules)} rules")

    # Display warnings if any
    if all_warnings:
        st.subheader("⚠️ Parsing Warnings")
        with st.expander("View warnings", expanded=False):
            for warning in all_warnings:
                st.write(f"• {warning}")

    # Main content tabs
    tab1, tab2, tab3, tab4 = st.tabs(
        ["Overview", "Rules Detail", "Filters", "Export"]
    )

    # Tab 1: Overview
    with tab1:
        st.subheader("Summary Statistics")
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("Total Rules", len(all_rules))

        with col2:
            avg_level = sum(r.level for r in all_rules) / len(all_rules)
            st.metric("Average Level", f"{avg_level:.1f}")

        with col3:
            max_level = max(r.level for r in all_rules)
            st.metric("Max Level", max_level)

        with col4:
            all_groups = set(g for r in all_rules for g in r.groups)
            st.metric("Rule Groups", len(all_groups))

        # Level distribution
        st.subheader("Alert Level Distribution")
        level_dist = {}
        for rule in all_rules:
            level_dist[rule.level] = level_dist.get(rule.level, 0) + 1

        st.bar_chart(level_dist)

    # Tab 2: Rules Detail
    with tab2:
        st.subheader("Rules List")

        # Sorting and filtering options
        col1, col2 = st.columns(2)
        with col1:
            sort_by = st.selectbox(
                "Sort by",
                ["Rule ID", "Level (Low→High)", "Level (High→Low)"],
            )
        with col2:
            min_level = st.slider("Minimum alert level", 0, 15, 0)

        # Apply filtering
        filtered_rules = [r for r in all_rules if r.level >= min_level]

        # Apply sorting
        if sort_by == "Rule ID":
            filtered_rules.sort(key=lambda r: r.rule_id)
        elif sort_by == "Level (Low→High)":
            filtered_rules.sort(key=lambda r: r.level)
        else:
            filtered_rules.sort(key=lambda r: r.level, reverse=True)

        st.write(f"Showing {len(filtered_rules)} rules")

        # Display rules as expandable cards
        for rule in filtered_rules:
            with st.expander(
                f"Rule {rule.rule_id}: {rule.description} (Level {rule.level})"
            ):
                col1, col2, col3 = st.columns(3)

                with col1:
                    st.metric("Rule ID", rule.rule_id)
                with col2:
                    st.metric("Alert Level", rule.level)
                with col3:
                    st.metric("Parent Rule", rule.detection_cues.if_sid or "None")

                if rule.detection_cues.decoded_as:
                    st.write(
                        f"**Decoder:** {rule.detection_cues.decoded_as}"
                    )

                if rule.filter_conditions:
                    st.write("**Filter Logic:**")
                    st.write(summarize_filter_logic(rule.filter_conditions))

                if rule.groups:
                    st.write(
                        f"**Groups:** {', '.join(rule.groups)}"
                    )

                if rule.mitre_techniques:
                    st.write(
                        f"**MITRE Techniques:** {', '.join(rule.mitre_techniques)}"
                    )

    # Tab 3: Filters and Search
    with tab3:
        st.subheader("Filter Rules")

        col1, col2, col3 = st.columns(3)

        with col1:
            # Filter by group
            all_groups = sorted(set(g for r in all_rules for g in r.groups))
            selected_groups = st.multiselect(
                "Filter by group",
                options=all_groups,
            )

        with col2:
            # Filter by MITRE technique
            all_techniques = sorted(
                set(t for r in all_rules for t in r.mitre_techniques)
            )
            selected_techniques = st.multiselect(
                "Filter by MITRE technique",
                options=all_techniques,
            )

        with col3:
            # Search by description
            search_text = st.text_input(
                "Search in description",
                placeholder="Enter search term...",
            )

        # Apply all filters
        filtered_rules = all_rules

        if selected_groups:
            filtered_rules = [
                r for r in filtered_rules
                if any(g in selected_groups for g in r.groups)
            ]

        if selected_techniques:
            filtered_rules = [
                r for r in filtered_rules
                if any(t in selected_techniques for t in r.mitre_techniques)
            ]

        if search_text:
            search_lower = search_text.lower()
            filtered_rules = [
                r for r in filtered_rules
                if search_lower in r.description.lower()
            ]

        st.write(f"Found {len(filtered_rules)} matching rules")

        # Display filtered rules as table
        if filtered_rules:
            rule_data = []
            for rule in filtered_rules:
                rule_data.append({
                    "ID": rule.rule_id,
                    "Level": rule.level,
                    "Description": rule.description[:50] + "...",
                    "Groups": ", ".join(rule.groups[:2]),
                    "Has MITRE": "Yes" if rule.mitre_techniques else "No",
                })

            st.table(rule_data)

    # Tab 4: Export
    with tab4:
        st.subheader("Export Parsed Rules")

        export_format = st.radio(
            "Select export format",
            ["JSON", "CSV"],
        )

        if export_format == "JSON":
            # Convert rules to JSON
            rule_dicts = [rule_to_dict(r) for r in all_rules]
            json_str = json.dumps(rule_dicts, indent=2)

            st.download_button(
                label="Download as JSON",
                data=json_str,
                file_name="wazuh_rules.json",
                mime="application/json",
            )

        else:  # CSV
            # Simple CSV export
            csv_lines = ["ID,Level,Description,Groups,Filter Count"]
            for rule in all_rules:
                groups_str = ";".join(rule.groups)
                csv_lines.append(
                    f'{rule.rule_id},{rule.level},'
                    f'"{rule.description}",{groups_str},'
                    f'{len(rule.filter_conditions)}'
                )

            csv_str = "\n".join(csv_lines)

            st.download_button(
                label="Download as CSV",
                data=csv_str,
                file_name="wazuh_rules.csv",
                mime="text/csv",
            )

        # JSON preview
        st.subheader("Data Preview")
        if st.checkbox("Show first rule as JSON"):
            if all_rules:
                st.json(rule_to_dict(all_rules[0]))


if __name__ == "__main__":
    main()
