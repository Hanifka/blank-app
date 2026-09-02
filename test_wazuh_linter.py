"""Tests for the Wazuh linter and cleaner. Run: python3 test_wazuh_linter.py"""

import unittest

from wazuh_linter import (
    clean_wazuh_xml,
    format_report_text,
    lint_with_recovery,
    lint_wazuh_xml,
)


def codes(report):
    return {issue.code for issue in report.issues}


def wrap(inner: str, name: str = "custom,") -> str:
    return f'<?xml version="1.0" encoding="UTF-8"?>\n<group name="{name}">\n{inner}\n</group>\n'


GOOD = wrap("""
  <rule id="100001" level="3">
    <decoded_as>sshd</decoded_as>
    <description>SSH activity</description>
    <group>syslog,sshd,</group>
  </rule>
  <rule id="100002" level="7">
    <if_sid>100001</if_sid>
    <match>authentication failure</match>
    <description>SSH authentication failure</description>
    <group>syslog,authentication_failed,</group>
  </rule>
""")


class TestCleanFile(unittest.TestCase):
    def test_clean_file_has_no_findings(self):
        report = lint_wazuh_xml(GOOD)
        self.assertTrue(report.parsed)
        self.assertTrue(report.manager_safe)
        self.assertEqual(report.issues, [], codes(report))
        self.assertEqual(report.rule_count, 2)
        self.assertEqual(report.health_score(), 100)

    def test_clean_is_idempotent(self):
        once, _ = clean_wazuh_xml(GOOD)
        twice, fixes = clean_wazuh_xml(once)
        self.assertEqual(twice, once)
        self.assertEqual(fixes, [])

    def test_clean_keeps_rules_readable(self):
        cleaned, _ = clean_wazuh_xml(GOOD)
        self.assertIn("</rule>\n\n  <rule", cleaned)
        self.assertTrue(lint_wazuh_xml(cleaned).manager_safe)


class TestBlockingErrors(unittest.TestCase):
    def test_duplicate_rule_id(self):
        xml = wrap("""
  <rule id="100001" level="3"><description>a</description><match>x</match></rule>
  <rule id="100001" level="4"><description>b</description><match>y</match></rule>
""")
        self.assertIn("WZ080", codes(lint_wazuh_xml(xml)))

    def test_level_out_of_range(self):
        xml = wrap('<rule id="100001" level="42"><description>a</description><match>x</match></rule>')
        self.assertIn("WZ053", codes(lint_wazuh_xml(xml)))

    def test_missing_description(self):
        xml = wrap('<rule id="100001" level="3"><match>x</match></rule>')
        self.assertIn("WZ061", codes(lint_wazuh_xml(xml)))

    def test_field_without_name(self):
        xml = wrap('<rule id="100001" level="3"><field>a:b</field><description>d</description></rule>')
        self.assertIn("WZ064", codes(lint_wazuh_xml(xml)))

    def test_frequency_without_timeframe(self):
        xml = wrap("""
  <rule id="100001" level="3"><description>a</description><match>x</match></rule>
  <rule id="100002" level="10">
    <if_matched_sid>100001</if_matched_sid>
    <frequency>8</frequency>
    <description>brute force</description>
  </rule>
""")
        self.assertIn("WZ069", codes(lint_wazuh_xml(xml)))

    def test_self_referencing_if_sid(self):
        xml = wrap('<rule id="100001" level="3"><if_sid>100001</if_sid><description>a</description></rule>')
        self.assertIn("WZ075", codes(lint_wazuh_xml(xml)))

    def test_circular_chain(self):
        xml = wrap("""
  <rule id="100001" level="3"><if_sid>100002</if_sid><description>a</description></rule>
  <rule id="100002" level="3"><if_sid>100001</if_sid><description>b</description></rule>
""")
        report = lint_wazuh_xml(xml)
        self.assertIn("WZ083", codes(report))
        self.assertEqual(len(report.stats["cycles"]), 1)

    def test_wrong_root_element(self):
        xml = '<rules><rule id="100001" level="3"><description>a</description><match>x</match></rule></rules>'
        self.assertIn("WZ030", codes(lint_wazuh_xml(xml)))

    def test_not_well_formed_reports_line(self):
        report = lint_wazuh_xml('<group name="a,"><rule id="1" level="1"></group>')
        self.assertFalse(report.parsed)
        self.assertFalse(report.manager_safe)
        self.assertIn("WZ020", codes(report))
        self.assertEqual(report.health_score(), 0)


class TestSilentFailures(unittest.TestCase):
    def test_pcre_syntax_without_pcre2_type(self):
        xml = wrap("""
  <rule id="100001" level="3">
    <regex>(?i)admin[0-9]{2}</regex>
    <description>a</description>
  </rule>
""")
        self.assertIn("WZ042", codes(lint_wazuh_xml(xml)))

    def test_pcre2_type_is_accepted(self):
        xml = wrap("""
  <rule id="100001" level="3">
    <regex type="pcre2">(?i)admin[0-9]{2}</regex>
    <description>a</description>
    <group>custom,</group>
  </rule>
""")
        self.assertNotIn("WZ042", codes(lint_wazuh_xml(xml)))

    def test_invalid_pcre2_is_an_error(self):
        xml = wrap("""
  <rule id="100001" level="3">
    <regex type="pcre2">admin[0-9</regex>
    <description>a</description>
  </rule>
""")
        self.assertIn("WZ040", codes(lint_wazuh_xml(xml)))

    def test_regex_metachars_inside_match(self):
        xml = wrap('<rule id="100001" level="3"><match>.*evil.*</match><description>a</description></rule>')
        self.assertIn("WZ041", codes(lint_wazuh_xml(xml)))

    def test_rule_with_no_condition(self):
        xml = wrap('<rule id="100001" level="5"><description>matches everything</description></rule>')
        self.assertIn("WZ077", codes(lint_wazuh_xml(xml)))

    def test_dangling_parent_reference(self):
        xml = wrap('<rule id="100002" level="3"><if_sid>100999</if_sid><description>a</description></rule>')
        report = lint_wazuh_xml(xml)
        self.assertIn("WZ081", codes(report))
        self.assertEqual(report.stats["dangling_parents"], [(100002, 100999)])

    def test_typo_tag_is_flagged(self):
        xml = wrap('<rule id="100001" level="3"><match>x</match><discription>oops</discription><description>a</description></rule>')
        self.assertIn("WZ059", codes(lint_wazuh_xml(xml)))

    def test_reserved_id_range(self):
        xml = wrap('<rule id="5715" level="3"><match>x</match><description>a</description></rule>')
        self.assertIn("WZ056", codes(lint_wazuh_xml(xml)))

    def test_overwrite_suppresses_reserved_id_warning(self):
        xml = wrap('<rule id="5715" level="3" overwrite="yes"><match>x</match><description>a</description></rule>')
        self.assertNotIn("WZ056", codes(lint_wazuh_xml(xml)))


class TestCleaner(unittest.TestCase):
    def test_escapes_bare_ampersand(self):
        xml = wrap('<rule id="100001" level="3"><match>x</match><description>Tom & Jerry</description></rule>')
        self.assertIn("WZ002", codes(lint_wazuh_xml(xml)))
        cleaned, fixes = clean_wazuh_xml(xml)
        self.assertIn("&amp;", cleaned)
        self.assertTrue(any("bare '&'" in f for f in fixes))
        self.assertTrue(lint_wazuh_xml(cleaned).parsed)

    def test_leaves_existing_entities_alone(self):
        xml = wrap('<rule id="100001" level="3"><match>x</match><description>a &amp; b &lt; c</description></rule>')
        cleaned, _ = clean_wazuh_xml(xml)
        self.assertNotIn("&amp;amp;", cleaned)

    def test_strips_bom_and_crlf(self):
        xml = "﻿" + GOOD.replace("\n", "\r\n")
        cleaned, fixes = clean_wazuh_xml(xml)
        self.assertFalse(cleaned.startswith("﻿"))
        self.assertNotIn("\r", cleaned)
        self.assertTrue(any("BOM" in f for f in fixes))

    def test_fixes_illegal_comment_dashes(self):
        xml = wrap('<!-- bad -- comment -->\n  <rule id="100001" level="3"><match>x</match><description>a</description></rule>')
        self.assertIn("WZ006", codes(lint_wazuh_xml(xml)))
        cleaned, _ = clean_wazuh_xml(xml)
        self.assertTrue(lint_wazuh_xml(cleaned).parsed)

    def test_adds_trailing_commas_to_groups(self):
        xml = wrap('<rule id="100001" level="3"><match>x</match><description>a</description><group>web,auth</group></rule>', name="root")
        cleaned, fixes = clean_wazuh_xml(xml)
        self.assertIn("<group>web,auth,</group>", cleaned)
        self.assertIn('name="root,"', cleaned)

    def test_text_only_mode_keeps_formatting(self):
        xml = wrap('<rule id="100001"    level="3"><match>x</match><description>a</description></rule>')
        cleaned, _ = clean_wazuh_xml(xml, reformat=False)
        self.assertIn('id="100001"    level="3"', cleaned)

    def test_does_not_reformat_broken_xml(self):
        broken = '<group name="a,"><rule id="1" level="1"></group>'
        cleaned, fixes = clean_wazuh_xml(broken)
        self.assertTrue(any("not well-formed" in f for f in fixes))


class TestRecovery(unittest.TestCase):
    def test_recovery_unblocks_deeper_checks(self):
        xml = wrap("""
  <rule id="100001" level="99"><description>Tom & Jerry</description></rule>
  <rule id="100001" level="3"><description>dupe</description></rule>
""")
        first = lint_wazuh_xml(xml)
        self.assertFalse(first.parsed)

        report, repaired, fixes = lint_with_recovery(xml)
        self.assertTrue(report.parsed)
        self.assertIsNotNone(repaired)
        self.assertIn("WZ002", codes(report))   # original syntax error kept
        self.assertIn("WZ053", codes(report))   # bad level, only visible after repair
        self.assertIn("WZ080", codes(report))   # duplicate id

    def test_recovery_is_a_noop_on_a_parseable_file(self):
        report, repaired, fixes = lint_with_recovery(GOOD)
        self.assertTrue(report.parsed)
        self.assertIsNone(repaired)
        self.assertEqual(fixes, [])


class TestReport(unittest.TestCase):
    def test_empty_input(self):
        report = lint_wazuh_xml("")
        self.assertIn("WZ000", codes(report))
        self.assertFalse(report.manager_safe)

    def test_every_issue_carries_a_recommendation(self):
        xml = wrap("""
  <rule id="5715" level="99" bogus="1">
    <regex>(?i)x[0-9]{2}</regex>
    <if_sid>999999</if_sid>
    <frequency>1</frequency>
    <discription>typo</discription>
  </rule>
""")
        report = lint_wazuh_xml(xml)
        self.assertGreater(len(report.issues), 5)
        for issue in report.issues:
            self.assertTrue(issue.recommendation.strip(), issue.code)
            self.assertTrue(issue.title.strip(), issue.code)
            self.assertIn(issue.severity, ("error", "warning", "info"))

    def test_text_report_renders(self):
        text = format_report_text(lint_wazuh_xml(GOOD))
        self.assertIn("WAZUH RULESET HEALTH REPORT", text)
        self.assertIn("No issues found", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
