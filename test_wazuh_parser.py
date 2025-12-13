"""
Unit tests for the Wazuh XML parser module.

Tests cover:
- Basic rule parsing
- Malformed XML handling
- Detection cues extraction
- Filter condition parsing
- Reference extraction
- Filter summary generation
"""

import unittest
from wazuh_parser import (
    parse_wazuh_xml,
    RuleData,
    DetectionCues,
    FilterCondition,
    summarize_filter_logic,
    rule_to_dict,
    extract_relationships,
)


SAMPLE_VALID_XML = """<?xml version="1.0" encoding="UTF-8"?>
<ruleset version="1" name="Test Rules">
    <rule id="1001" level="3">
        <description>Test rule with basic fields</description>
    </rule>
    <rule id="1002" level="5">
        <description>Rule with parent</description>
        <if_sid>1001</if_sid>
    </rule>
    <rule id="1003" level="7">
        <description>Rule referencing matched group</description>
        <if_matched_group>web</if_matched_group>
        <group>web</group>
    </rule>
    <rule id="1004" level="6">
        <description>Rule referencing if_group</description>
        <if_group>sysmon_event3</if_group>
        <group>sysmon, network</group>
    </rule>
    <rule id="1005" level="4">
        <description>Rule with match condition</description>
        <match>.*error.*</match>
    </rule>
    <rule id="1006" level="6">
        <description>Rule with no alert</description>
        <no_alert/>
    </rule>
</ruleset>
"""

SAMPLE_WITH_IF_MATCHED_SID = """<?xml version="1.0" encoding="UTF-8"?>
<ruleset>
    <rule id="100537" level="4">
        <description>Suspicious pattern detected</description>
    </rule>
    <rule id="100539" level="12" frequency="8" timeframe="60">
        <description>Frequency-based alert: 8 matches in 60 seconds</description>
        <if_matched_sid>100537</if_matched_sid>
    </rule>
</ruleset>
"""

SAMPLE_WITH_REFERENCES = """<?xml version="1.0" encoding="UTF-8"?>
<ruleset>
    <rule id="2001" level="8">
        <description>Rule with MITRE references</description>
        <reference>
            <type>attack</type>
            <technique>T1234.001</technique>
        </reference>
        <reference>
            <type>attack</type>
            <technique>T5678</technique>
        </reference>
    </rule>
</ruleset>
"""

SAMPLE_WITH_GROUPS = """<?xml version="1.0" encoding="UTF-8"?>
<ruleset>
    <rule id="3001" level="4">
        <description>Rule with groups</description>
        <group>web, http, access_control</group>
    </rule>
</ruleset>
"""

SAMPLE_MALFORMED_XML = """<?xml version="1.0" encoding="UTF-8"?>
<ruleset>
    <rule id="4001" level="3">
        <description>Unclosed tag
</ruleset>
"""

SAMPLE_MISSING_ATTRIBUTES = """<?xml version="1.0" encoding="UTF-8"?>
<ruleset>
    <rule>
        <description>Rule without id or level</description>
    </rule>
</ruleset>
"""

SAMPLE_EMPTY_XML = """<?xml version="1.0" encoding="UTF-8"?>
<ruleset>
</ruleset>
"""


class TestWazuhParserBasic(unittest.TestCase):
    """Test basic rule parsing functionality."""

    def test_parse_valid_rules(self):
        """Test parsing a valid XML document with multiple rules."""
        rules, warnings = parse_wazuh_xml(SAMPLE_VALID_XML)

        self.assertEqual(len(rules), 6)
        self.assertEqual(len(warnings), 0)

        # Verify first rule
        rule = rules[0]
        self.assertEqual(rule.rule_id, 1001)
        self.assertEqual(rule.level, 3)
        self.assertEqual(rule.description, "Test rule with basic fields")

    def test_parse_rule_with_parent(self):
        """Test parsing a rule with if_sid (parent rule reference)."""
        rules, warnings = parse_wazuh_xml(SAMPLE_VALID_XML)

        rule = [r for r in rules if r.rule_id == 1002][0]
        self.assertEqual(rule.detection_cues.if_sid, 1001)

    def test_parse_rule_with_matched_group(self):
        """Test parsing if_matched_group conditions."""
        rules, warnings = parse_wazuh_xml(SAMPLE_VALID_XML)

        rule = [r for r in rules if r.rule_id == 1003][0]
        self.assertEqual(len(rule.detection_cues.if_matched_groups), 1)
        self.assertIn("web", rule.detection_cues.if_matched_groups)

    def test_parse_rule_with_if_group(self):
        """Test parsing if_group conditions."""
        rules, warnings = parse_wazuh_xml(SAMPLE_VALID_XML)

        rule = [r for r in rules if r.rule_id == 1004][0]
        self.assertEqual(len(rule.detection_cues.if_groups), 1)
        self.assertIn("sysmon_event3", rule.detection_cues.if_groups)

    def test_parse_rule_with_match(self):
        """Test parsing match conditions."""
        rules, warnings = parse_wazuh_xml(SAMPLE_VALID_XML)

        rule = [r for r in rules if r.rule_id == 1005][0]
        self.assertEqual(len(rule.filter_conditions), 1)
        self.assertEqual(rule.filter_conditions[0].match, ".*error.*")

    def test_parse_rule_with_no_alert(self):
        """Test parsing no_alert conditions."""
        rules, warnings = parse_wazuh_xml(SAMPLE_VALID_XML)

        rule = [r for r in rules if r.rule_id == 1006][0]
        self.assertEqual(len(rule.filter_conditions), 1)
        self.assertTrue(rule.filter_conditions[0].no_alert)


class TestWazuhParserReferences(unittest.TestCase):
    """Test reference extraction (MITRE, CIS, NIST)."""

    def test_extract_mitre_techniques(self):
        """Test extracting MITRE ATT&CK technique references."""
        rules, warnings = parse_wazuh_xml(SAMPLE_WITH_REFERENCES)

        self.assertEqual(len(rules), 1)
        rule = rules[0]
        self.assertEqual(len(rule.mitre_techniques), 2)
        self.assertIn("T1234.001", rule.mitre_techniques)
        self.assertIn("T5678", rule.mitre_techniques)


class TestWazuhParserGroups(unittest.TestCase):
    """Test group parsing."""

    def test_extract_groups(self):
        """Test extracting rule groups."""
        rules, warnings = parse_wazuh_xml(SAMPLE_WITH_GROUPS)

        self.assertEqual(len(rules), 1)
        rule = rules[0]
        self.assertEqual(len(rule.groups), 3)
        self.assertIn("web", rule.groups)
        self.assertIn("http", rule.groups)
        self.assertIn("access_control", rule.groups)


class TestWazuhParserErrorHandling(unittest.TestCase):
    """Test error handling for malformed XML."""

    def test_malformed_xml(self):
        """Test graceful handling of malformed XML."""
        rules, warnings = parse_wazuh_xml(SAMPLE_MALFORMED_XML)

        self.assertEqual(len(rules), 0)
        self.assertGreater(len(warnings), 0)
        self.assertIn("XML parsing error", warnings[0])

    def test_missing_required_attributes(self):
        """Test handling of rules missing required attributes."""
        rules, warnings = parse_wazuh_xml(SAMPLE_MISSING_ATTRIBUTES)

        self.assertEqual(len(rules), 0)
        self.assertGreater(len(warnings), 0)

    def test_empty_xml(self):
        """Test handling of XML with no rules."""
        rules, warnings = parse_wazuh_xml(SAMPLE_EMPTY_XML)

        self.assertEqual(len(rules), 0)
        self.assertEqual(len(warnings), 1)
        self.assertIn("No <rule> elements found", warnings[0])

    def test_invalid_xml_string(self):
        """Test handling of completely invalid XML."""
        rules, warnings = parse_wazuh_xml("not valid xml at all")

        self.assertEqual(len(rules), 0)
        self.assertGreater(len(warnings), 0)


class TestFilterLogicSummary(unittest.TestCase):
    """Test filter condition summarization."""

    def test_empty_conditions(self):
        """Test summary generation for empty condition list."""
        summary = summarize_filter_logic([])
        self.assertEqual(summary, "No filter conditions")

    def test_match_condition_summary(self):
        """Test summary for match conditions."""
        conditions = [FilterCondition(match=".*error.*")]
        summary = summarize_filter_logic(conditions)
        self.assertIn("Match: .*error.*", summary)

    def test_frequency_condition_summary(self):
        """Test summary for frequency conditions."""
        conditions = [FilterCondition(frequency=5, timeframe=60, same_field="user")]
        summary = summarize_filter_logic(conditions)
        self.assertIn("Frequency: 5 occurrences", summary)
        self.assertIn("60s", summary)
        self.assertIn("user", summary)

    def test_no_alert_condition_summary(self):
        """Test summary for no_alert conditions."""
        conditions = [FilterCondition(no_alert=True)]
        summary = summarize_filter_logic(conditions)
        self.assertIn("No alert: True", summary)

    def test_multiple_conditions_summary(self):
        """Test summary with multiple condition types."""
        conditions = [
            FilterCondition(match=".*error.*"),
            FilterCondition(frequency=5, timeframe=60),
        ]
        summary = summarize_filter_logic(conditions)
        self.assertIn("Match:", summary)
        self.assertIn("Frequency:", summary)
        self.assertIn("|", summary)  # Separator between conditions


class TestRuleToDict(unittest.TestCase):
    """Test rule conversion to dictionary."""

    def test_rule_to_dict_conversion(self):
        """Test converting a RuleData object to dictionary."""
        rule = RuleData(
            rule_id=1001,
            level=3,
            description="Test rule",
            detection_cues=DetectionCues(
                decoded_as="nginx",
                if_sid=None,
                if_matched_groups=[],
                if_groups=[],
                description="Test rule"
            ),
            filter_conditions=[
                FilterCondition(match=".*error.*")
            ],
            mitre_techniques=["T1234"],
            cis_controls=["4.1"],
            nist_controls=["AC-2"],
            groups=["web"],
        )

        result = rule_to_dict(rule)

        self.assertEqual(result["rule_id"], 1001)
        self.assertEqual(result["level"], 3)
        self.assertEqual(result["description"], "Test rule")
        self.assertIn("filter_summary", result)
        self.assertIsInstance(result["detection_cues"], dict)
        self.assertIsInstance(result["filter_conditions"], list)


class TestRelationshipExtraction(unittest.TestCase):
    """Test relationship extraction functionality."""

    def test_extract_relationships(self):
        """Test extracting all relationship types from rules."""
        rules, _ = parse_wazuh_xml(SAMPLE_VALID_XML)
        
        relationships = extract_relationships(rules)
        
        # Should have relationships from if_sid, if_matched_group, and if_group
        self.assertGreater(len(relationships), 0)
        
        # Check if_sid relationship
        if_sid_rels = [r for r in relationships if r["relationship_type"] == "if_sid"]
        self.assertEqual(len(if_sid_rels), 1)
        self.assertEqual(if_sid_rels[0]["source_rule_id"], 1002)
        self.assertEqual(if_sid_rels[0]["target_rule_id"], 1001)
        
        # Check if_matched_group relationship
        if_matched_rels = [r for r in relationships if r["relationship_type"] == "if_matched_group"]
        self.assertEqual(len(if_matched_rels), 1)
        self.assertEqual(if_matched_rels[0]["source_rule_id"], 1003)
        self.assertEqual(if_matched_rels[0]["target_group"], "web")
        
        # Check if_group relationship
        if_group_rels = [r for r in relationships if r["relationship_type"] == "if_group"]
        self.assertEqual(len(if_group_rels), 1)
        self.assertEqual(if_group_rels[0]["source_rule_id"], 1004)
        self.assertEqual(if_group_rels[0]["target_group"], "sysmon_event3")

    def test_extract_if_matched_sid_frequency_timeframe(self):
        rules, warnings = parse_wazuh_xml(SAMPLE_WITH_IF_MATCHED_SID)

        self.assertEqual(warnings, [])
        rule = [r for r in rules if r.rule_id == 100539][0]

        self.assertEqual(rule.detection_cues.if_matched_sid, [100537])
        self.assertEqual(rule.frequency, 8)
        self.assertEqual(rule.timeframe, 60)

        relationships = extract_relationships(rules)
        matched_rels = [
            r
            for r in relationships
            if r["relationship_type"] == "if_matched_sid"
            and r["source_rule_id"] == 100539
        ]
        self.assertEqual(len(matched_rels), 1)
        self.assertEqual(matched_rels[0]["target_rule_id"], 100537)
        self.assertEqual(matched_rels[0]["frequency"], 8)
        self.assertEqual(matched_rels[0]["timeframe"], 60)


if __name__ == "__main__":
    unittest.main()
