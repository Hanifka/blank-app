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
        <description>Rule with frequency</description>
        <frequency>5</frequency>
        <timeframe>60</timeframe>
        <same_field>user</same_field>
    </rule>
    <rule id="1004" level="4">
        <description>Rule with match condition</description>
        <match>.*error.*</match>
    </rule>
    <rule id="1005" level="6">
        <description>Rule with no alert</description>
        <no_alert/>
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

SAMPLE_WITH_IF_MATCHED_GROUP = """<?xml version="1.0" encoding="UTF-8"?>
<ruleset>
    <rule id="5001" level="5">
        <description>Rule with single if_matched_group</description>
        <if_matched_group>authentication</if_matched_group>
    </rule>
</ruleset>
"""

SAMPLE_WITH_MULTIPLE_IF_MATCHED_GROUPS = """<?xml version="1.0" encoding="UTF-8"?>
<ruleset>
    <rule id="6001" level="7">
        <description>Rule with multiple if_matched_group elements</description>
        <if_matched_group>web, injection</if_matched_group>
        <if_matched_group>application_attack</if_matched_group>
        <if_matched_group>reconnaissance, credential_access</if_matched_group>
    </rule>
</ruleset>
"""

SAMPLE_WITH_IF_MATCHED_GROUP_WHITESPACE = """<?xml version="1.0" encoding="UTF-8"?>
<ruleset>
    <rule id="7001" level="6">
        <description>Rule with if_matched_group containing whitespace</description>
        <if_matched_group>  web  ,  authentication  ,  brute_force  </if_matched_group>
    </rule>
</ruleset>
"""


class TestWazuhParserBasic(unittest.TestCase):
    """Test basic rule parsing functionality."""

    def test_parse_valid_rules(self):
        """Test parsing a valid XML document with multiple rules."""
        rules, warnings = parse_wazuh_xml(SAMPLE_VALID_XML)

        self.assertEqual(len(rules), 5)
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

    def test_parse_rule_with_frequency(self):
        """Test parsing frequency-based conditions."""
        rules, warnings = parse_wazuh_xml(SAMPLE_VALID_XML)

        rule = [r for r in rules if r.rule_id == 1003][0]
        self.assertEqual(len(rule.filter_conditions), 1)

        cond = rule.filter_conditions[0]
        self.assertEqual(cond.frequency, 5)
        self.assertEqual(cond.timeframe, 60)
        self.assertEqual(cond.same_field, "user")

    def test_parse_rule_with_match(self):
        """Test parsing match conditions."""
        rules, warnings = parse_wazuh_xml(SAMPLE_VALID_XML)

        rule = [r for r in rules if r.rule_id == 1004][0]
        self.assertEqual(len(rule.filter_conditions), 1)
        self.assertEqual(rule.filter_conditions[0].match, ".*error.*")

    def test_parse_rule_with_no_alert(self):
        """Test parsing no_alert conditions."""
        rules, warnings = parse_wazuh_xml(SAMPLE_VALID_XML)

        rule = [r for r in rules if r.rule_id == 1005][0]
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
                description="Test rule"
            ),
            filter_conditions=[
                FilterCondition(match=".*error.*")
            ],
            mitre_techniques=["T1234"],
            cis_controls=["4.1"],
            nist_controls=["AC-2"],
            groups=["web"],
            if_matched_groups=["authentication", "web"],
        )

        result = rule_to_dict(rule)

        self.assertEqual(result["rule_id"], 1001)
        self.assertEqual(result["level"], 3)
        self.assertEqual(result["description"], "Test rule")
        self.assertIn("filter_summary", result)
        self.assertIn("if_matched_groups", result)
        self.assertEqual(result["if_matched_groups"], ["authentication", "web"])
        self.assertIsInstance(result["detection_cues"], dict)
        self.assertIsInstance(result["filter_conditions"], list)


class TestIfMatchedGroups(unittest.TestCase):
    """Test if_matched_group parsing."""

    def test_single_if_matched_group(self):
        """Test parsing a rule with single if_matched_group."""
        rules, warnings = parse_wazuh_xml(SAMPLE_WITH_IF_MATCHED_GROUP)

        self.assertEqual(len(rules), 1)
        self.assertEqual(len(warnings), 0)
        rule = rules[0]
        self.assertEqual(rule.rule_id, 5001)
        self.assertEqual(len(rule.if_matched_groups), 1)
        self.assertIn("authentication", rule.if_matched_groups)

    def test_multiple_if_matched_groups(self):
        """Test parsing a rule with multiple if_matched_group elements."""
        rules, warnings = parse_wazuh_xml(SAMPLE_WITH_MULTIPLE_IF_MATCHED_GROUPS)

        self.assertEqual(len(rules), 1)
        self.assertEqual(len(warnings), 0)
        rule = rules[0]
        self.assertEqual(rule.rule_id, 6001)
        self.assertEqual(len(rule.if_matched_groups), 5)
        self.assertIn("web", rule.if_matched_groups)
        self.assertIn("injection", rule.if_matched_groups)
        self.assertIn("application_attack", rule.if_matched_groups)
        self.assertIn("reconnaissance", rule.if_matched_groups)
        self.assertIn("credential_access", rule.if_matched_groups)

    def test_if_matched_group_whitespace_trimming(self):
        """Test that whitespace is properly trimmed from if_matched_group values."""
        rules, warnings = parse_wazuh_xml(SAMPLE_WITH_IF_MATCHED_GROUP_WHITESPACE)

        self.assertEqual(len(rules), 1)
        self.assertEqual(len(warnings), 0)
        rule = rules[0]
        self.assertEqual(rule.rule_id, 7001)
        self.assertEqual(len(rule.if_matched_groups), 3)
        self.assertIn("web", rule.if_matched_groups)
        self.assertIn("authentication", rule.if_matched_groups)
        self.assertIn("brute_force", rule.if_matched_groups)
        for group in rule.if_matched_groups:
            self.assertEqual(group, group.strip())

    def test_rule_without_if_matched_group(self):
        """Test that rules without if_matched_group have empty list."""
        rules, warnings = parse_wazuh_xml(SAMPLE_VALID_XML)

        self.assertEqual(len(rules), 5)
        for rule in rules:
            self.assertIsInstance(rule.if_matched_groups, list)
            self.assertEqual(len(rule.if_matched_groups), 0)


if __name__ == "__main__":
    unittest.main()
