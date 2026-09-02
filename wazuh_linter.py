"""
Wazuh XML rule linter, error detector and cleaner.

Two jobs:

1. ``lint_wazuh_xml`` - find everything that would make ``wazuh-manager`` refuse
   to start, silently drop a rule, or make a rule fire on the wrong events.
   Every finding carries a concrete recommendation.
2. ``clean_wazuh_xml`` - repair the mechanical problems (encoding, bare ``&``,
   bad comment dashes, indentation, group commas) and hand back clean XML plus
   a list of what changed.

Severity meaning:
    error    manager will reject the file, or the rule can never fire
    warning  loads fine but almost certainly does not do what you intended
    info     style / convention / worth a look
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

# --------------------------------------------------------------------------
# Wazuh schema knowledge
# --------------------------------------------------------------------------

MIN_LEVEL = 0
MAX_LEVEL = 16
MIN_RULE_ID = 1
MAX_RULE_ID = 999999

# Wazuh ships rules below 100000. Custom rules live in 100000-120000.
RESERVED_ID_CEILING = 100000
CUSTOM_ID_CEILING = 120000

VALID_RULE_ATTRS = {
    "id", "level", "maxsize", "frequency", "timeframe",
    "ignore", "overwrite", "noalert",
}

VALID_RULE_CHILDREN = {
    # matching
    "match", "regex", "decoded_as", "category", "field", "list", "srcip",
    "dstip", "srcport", "dstport", "srcuser", "dstuser", "user", "url", "id",
    "status", "hostname", "program_name", "protocol", "action", "extra_data",
    "system_name", "data", "srcgeoip", "dstgeoip", "location", "compiled_rule",
    # composition
    "if_sid", "if_group", "if_level", "if_matched_sid", "if_matched_group",
    "if_matched_level", "if_fts",
    # correlation
    "same_source_ip", "same_dest_ip", "same_src_port", "same_dst_port",
    "same_location", "same_user", "same_id", "same_field", "same_agent",
    "different_source_ip", "different_url", "different_field", "different_geoip",
    "not_same_field", "not_same_source_ip", "not_same_id", "not_same_agent",
    # metadata / behaviour
    "description", "info", "options", "group", "mitre", "check_diff",
    "frequency", "timeframe", "ignore", "time", "weekday", "var",
    "no_full_log", "no_log", "global_frequency", "reference", "no_alert",
}

# Old-style correlation tags Wazuh 4.x replaced with <same_field>.
DEPRECATED_TAGS = {
    "same_source_ip": "<same_field>srcip</same_field>",
    "same_dest_ip": "<same_field>dstip</same_field>",
    "same_src_port": "<same_field>srcport</same_field>",
    "same_dst_port": "<same_field>dstport</same_field>",
    "same_user": "<same_field>dstuser</same_field>",
    "same_id": "<same_field>id</same_field>",
    "same_location": "<same_field>location</same_field>",
}

VALID_OPTIONS = {
    "alert_by_email", "no_email_alert", "no_log", "no_full_log",
    "no_counter",
}

# Constructs OS_Regex (the default engine) does not implement. Hitting one of
# these without type="pcre2" means the rule quietly never matches.
PCRE_ONLY_PATTERNS = [
    (r"\(\?", "inline group flags or non-capturing groups, e.g. (?i) / (?:"),
    (r"\\b", r"word boundary \b"),
    (r"\{\d+(,\d*)?\}", "counted quantifiers, e.g. {2,5}"),
    (r"\[[^\]]+\]", "character classes, e.g. [a-z]"),
    (r"[*+]\?", "lazy quantifiers, e.g. .*?"),
    (r"\\[bBAZzGKQE]", "PCRE escape sequences"),
]

# Characters that are literal in <match> but that people write expecting regex.
MATCH_REGEXY = re.compile(r"[.*+\[\](){}\\]")

BARE_AMP = re.compile(r"&(?!(?:#\d+|#x[0-9a-fA-F]+|amp|lt|gt|quot|apos);)")


# --------------------------------------------------------------------------
# Result types
# --------------------------------------------------------------------------

@dataclass
class LintIssue:
    """One finding, with the fix the user should apply."""
    code: str
    severity: str                       # error | warning | info
    title: str
    detail: str
    recommendation: str
    rule_id: Optional[int] = None
    line: Optional[int] = None
    auto_fixable: bool = False

    def location(self) -> str:
        bits = []
        if self.rule_id is not None:
            bits.append(f"rule {self.rule_id}")
        if self.line is not None:
            bits.append(f"line {self.line}")
        return ", ".join(bits) if bits else "file"


@dataclass
class LintReport:
    """Everything the linter found, plus a quick verdict."""
    issues: List[LintIssue] = field(default_factory=list)
    parsed: bool = False
    rule_count: int = 0
    stats: Dict[str, Any] = field(default_factory=dict)

    @property
    def errors(self) -> List[LintIssue]:
        return [i for i in self.issues if i.severity == "error"]

    @property
    def warnings(self) -> List[LintIssue]:
        return [i for i in self.issues if i.severity == "warning"]

    @property
    def infos(self) -> List[LintIssue]:
        return [i for i in self.issues if i.severity == "info"]

    @property
    def manager_safe(self) -> bool:
        """True when nothing found would stop wazuh-manager from loading."""
        return not self.errors

    def health_score(self) -> int:
        """0-100. Errors hurt a lot, warnings some, info a little."""
        if not self.parsed:
            return 0
        penalty = 12 * len(self.errors) + 4 * len(self.warnings) + 1 * len(self.infos)
        return max(0, 100 - penalty)

    def by_severity(self) -> Dict[str, int]:
        return {
            "error": len(self.errors),
            "warning": len(self.warnings),
            "info": len(self.infos),
        }


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _build_line_map(xml_content: str) -> Dict[int, int]:
    """Map rule id -> 1-based line number of its <rule> tag (best effort)."""
    line_map: Dict[int, int] = {}
    for lineno, line in enumerate(xml_content.splitlines(), start=1):
        for m in re.finditer(r"<rule\b[^>]*\bid\s*=\s*[\"'](\d+)[\"']", line):
            rid = int(m.group(1))
            line_map.setdefault(rid, lineno)
    return line_map


def _text(elem: Optional[ET.Element]) -> str:
    if elem is None or elem.text is None:
        return ""
    return elem.text.strip()


def _int_list(raw: str) -> Tuple[List[int], List[str]]:
    """Split a comma separated sid list into ints plus the bits that failed."""
    good: List[int] = []
    bad: List[str] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            good.append(int(part))
        except ValueError:
            bad.append(part)
    return good, bad


# --------------------------------------------------------------------------
# Phase A - raw text checks (run before the XML parser sees the file)
# --------------------------------------------------------------------------

def _check_raw_text(xml_content: str, issues: List[LintIssue]) -> None:
    if xml_content.startswith("﻿"):
        issues.append(LintIssue(
            code="WZ001", severity="warning",
            title="File starts with a UTF-8 BOM",
            detail="A byte order mark before the XML declaration makes some "
                   "Wazuh builds report 'XML ERROR: Attribute name expected'.",
            recommendation="Save the file as UTF-8 without BOM. Run Clean XML "
                           "to strip it.",
            line=1, auto_fixable=True,
        ))

    lines = xml_content.splitlines()

    for lineno, line in enumerate(lines, start=1):
        # Ampersands that are not part of an entity break the parser.
        stripped_comment = re.sub(r"<!--.*?-->", "", line)
        if BARE_AMP.search(stripped_comment):
            issues.append(LintIssue(
                code="WZ002", severity="error",
                title="Unescaped '&' in XML text",
                detail=f"Line {lineno} contains a bare '&'. XML only allows it "
                       f"as the start of an entity such as &amp;.",
                recommendation="Replace '&' with '&amp;'. Clean XML does this "
                               "for you.",
                line=lineno, auto_fixable=True,
            ))
            break  # one report is enough, the fixer handles all of them

    if "\r\n" in xml_content:
        issues.append(LintIssue(
            code="WZ003", severity="info",
            title="Windows (CRLF) line endings",
            detail="The file uses CRLF. Wazuh reads it fine but diffs and some "
                   "editors on the manager host get noisy.",
            recommendation="Convert to LF. Clean XML does this.",
            auto_fixable=True,
        ))

    if "\t" in xml_content:
        issues.append(LintIssue(
            code="WZ004", severity="info",
            title="Tab characters used for indentation",
            detail="Mixed tabs and spaces make the ruleset hard to review.",
            recommendation="Use two spaces per level. Clean XML reindents.",
            auto_fixable=True,
        ))

    if any(line != line.rstrip() for line in lines):
        issues.append(LintIssue(
            code="WZ005", severity="info",
            title="Trailing whitespace",
            detail="One or more lines end in spaces or tabs.",
            recommendation="Strip it. Clean XML does this.",
            auto_fixable=True,
        ))

    # '--' is illegal inside an XML comment and is a classic copy-paste break.
    for m in re.finditer(r"<!--(.*?)(?:-->|$)", xml_content, re.DOTALL):
        body = m.group(1)
        if "--" in body:
            lineno = xml_content[:m.start()].count("\n") + 1
            issues.append(LintIssue(
                code="WZ006", severity="error",
                title="Double hyphen inside an XML comment",
                detail="XML forbids '--' inside <!-- -->. The parser stops "
                       "there and the manager reports an XML syntax error.",
                recommendation="Use a single hyphen or an em dash inside "
                               "comments. Clean XML collapses them.",
                line=lineno, auto_fixable=True,
            ))
            break

    open_comments = xml_content.count("<!--")
    close_comments = xml_content.count("-->")
    if open_comments != close_comments:
        issues.append(LintIssue(
            code="WZ007", severity="error",
            title="Unterminated XML comment",
            detail=f"Found {open_comments} '<!--' but {close_comments} '-->'. "
                   f"Everything after the unclosed comment is swallowed.",
            recommendation="Close every comment with '-->'.",
        ))

    if not re.match(r"^\s*<\?xml", xml_content.lstrip("﻿")):
        issues.append(LintIssue(
            code="WZ008", severity="info",
            title="No XML declaration",
            detail="The file does not start with <?xml version=\"1.0\" "
                   "encoding=\"UTF-8\"?>.",
            recommendation="Add the declaration so the encoding is explicit.",
            auto_fixable=True,
        ))


# --------------------------------------------------------------------------
# Phase B - well-formedness
# --------------------------------------------------------------------------

def _parse_error_advice(message: str) -> str:
    low = message.lower()
    if "junk after document element" in low:
        return ("The file has more than one top-level element. A Wazuh rule "
                "file must contain exactly one root <group>. Wrap every rule "
                "in a single <group name=\"custom,\"> ... </group>.")
    if "mismatched tag" in low:
        return ("A closing tag does not match its opening tag. Check the line "
                "reported above and the block just before it.")
    if "not well-formed" in low or "invalid token" in low:
        return ("Usually a bare '&', '<' or '>' inside text. Escape them as "
                "&amp; &lt; &gt;. Run Clean XML first.")
    if "no element found" in low:
        return ("The document ended early. A tag is left open, most often the "
                "final </group>.")
    if "unbound prefix" in low:
        return "A namespace prefix (something like ns:tag) is used but never declared."
    if "duplicate attribute" in low:
        return "The same attribute is written twice on one tag. Remove the extra."
    return ("Open the file at the reported line and column and fix the XML "
            "syntax there.")


def _parse(xml_content: str, issues: List[LintIssue]) -> Optional[ET.Element]:
    try:
        return ET.fromstring(xml_content)
    except ET.ParseError as exc:
        line, col = getattr(exc, "position", (None, None))
        context = ""
        if line:
            src = xml_content.splitlines()
            lo, hi = max(0, line - 3), min(len(src), line + 2)
            context = "\n".join(
                f"{'>' if n == line else ' '} {n:>5} | {src[n - 1]}"
                for n in range(lo + 1, hi + 1)
            )
        issues.append(LintIssue(
            code="WZ020", severity="error",
            title="XML is not well-formed",
            detail=f"{exc}\n\n{context}" if context else str(exc),
            recommendation=_parse_error_advice(str(exc)),
            line=line,
        ))
        return None


# --------------------------------------------------------------------------
# Phase C - file structure
# --------------------------------------------------------------------------

def _check_structure(root: ET.Element, issues: List[LintIssue]) -> None:
    if root.tag != "group":
        issues.append(LintIssue(
            code="WZ030", severity="error",
            title=f"Root element is <{root.tag}>, not <group>",
            detail="wazuh-manager expects every file in etc/rules/ to have a "
                   "single <group> root. A <rules> or <rule> root is rejected "
                   "at load time.",
            recommendation="Wrap the whole file in "
                           "<group name=\"custom,\"> ... </group>.",
            line=1, auto_fixable=True,
        ))
        return

    name = root.get("name")
    if not name:
        issues.append(LintIssue(
            code="WZ031", severity="warning",
            title="Root <group> has no name attribute",
            detail="Rules inherit the root group name. Without it they land in "
                   "no group and are harder to filter in the dashboard.",
            recommendation="Add name=\"custom,\" (or a descriptive group list) "
                           "to the root <group>.",
            line=1,
        ))
    elif not name.rstrip().endswith(","):
        issues.append(LintIssue(
            code="WZ032", severity="info",
            title="Root group name does not end with a comma",
            detail=f"name=\"{name}\" - Wazuh treats the attribute as a comma "
                   f"separated list and the trailing comma is the convention.",
            recommendation=f"Write name=\"{name},\".",
            line=1, auto_fixable=True,
        ))

    stray = [child.tag for child in root if child.tag not in ("rule",) and not isinstance(child.tag, str)]
    for child in root:
        if isinstance(child.tag, str) and child.tag != "rule":
            issues.append(LintIssue(
                code="WZ033", severity="warning",
                title=f"Unexpected <{child.tag}> directly under <group>",
                detail="Only <rule> elements belong inside a rules-file group.",
                recommendation=f"Move <{child.tag}> inside a rule, or delete it.",
            ))


# --------------------------------------------------------------------------
# Phase D - per rule
# --------------------------------------------------------------------------

def _check_regex_engine(rule_elem: ET.Element, rid: Optional[int],
                        line: Optional[int], issues: List[LintIssue]) -> None:
    """Catch patterns written for PCRE but handed to OS_Regex, and vice versa."""
    for tag in ("regex", "field", "match", "srcip", "user", "url", "program_name"):
        for elem in rule_elem.findall(tag):
            pattern = _text(elem)
            if not pattern:
                continue
            engine = (elem.get("type") or "").lower()

            if engine == "pcre2":
                try:
                    re.compile(pattern)
                except re.error as exc:
                    issues.append(LintIssue(
                        code="WZ040", severity="error",
                        title=f"Invalid PCRE2 pattern in <{tag}>",
                        detail=f"{exc}\nPattern: {pattern}",
                        recommendation="Fix the pattern syntax. Wazuh drops the "
                                       "whole rule when a pcre2 pattern fails "
                                       "to compile at load time.",
                        rule_id=rid, line=line,
                    ))
                continue

            if tag == "match":
                if MATCH_REGEXY.search(pattern):
                    issues.append(LintIssue(
                        code="WZ041", severity="warning",
                        title="Regex characters inside <match>",
                        detail=f"<match> is a literal substring test, so "
                               f"'{pattern}' is matched character for "
                               f"character - the metacharacters are not "
                               f"interpreted.",
                        recommendation="Switch to <regex type=\"pcre2\"> if you "
                                       "meant a pattern, or drop the "
                                       "metacharacters if you meant a literal.",
                        rule_id=rid, line=line,
                    ))
                continue

            # Default engine is OS_Regex, which implements far less than PCRE.
            for probe, human in PCRE_ONLY_PATTERNS:
                if re.search(probe, pattern):
                    issues.append(LintIssue(
                        code="WZ042", severity="warning",
                        title=f"PCRE-only syntax in <{tag}> without type=\"pcre2\"",
                        detail=f"The pattern uses {human}, which OS_Regex (the "
                               f"default engine) does not implement. The rule "
                               f"loads but never matches.\nPattern: {pattern}",
                        recommendation=f"Add type=\"pcre2\" to the <{tag}> tag, "
                                       f"or rewrite the pattern in OS_Regex "
                                       f"syntax.",
                        rule_id=rid, line=line, auto_fixable=False,
                    ))
                    break


def _check_rule(rule_elem: ET.Element, line_map: Dict[int, int],
                issues: List[LintIssue]) -> Optional[Dict[str, Any]]:
    """Validate one <rule>. Returns a small summary used by the graph phase."""
    rid_raw = rule_elem.get("id")
    level_raw = rule_elem.get("level")
    rid: Optional[int] = None
    line: Optional[int] = None

    if rid_raw is None:
        issues.append(LintIssue(
            code="WZ050", severity="error",
            title="<rule> without an id attribute",
            detail="Every Wazuh rule needs a unique numeric id.",
            recommendation="Add id=\"1000xx\" using a free id in the "
                           "100000-120000 custom range.",
        ))
    else:
        try:
            rid = int(rid_raw)
            line = line_map.get(rid)
        except ValueError:
            issues.append(LintIssue(
                code="WZ051", severity="error",
                title=f"Rule id \"{rid_raw}\" is not a number",
                detail="Wazuh parses the id as an integer.",
                recommendation="Use digits only, no quotes, spaces or letters.",
            ))

    if level_raw is None:
        issues.append(LintIssue(
            code="WZ052", severity="error",
            title="<rule> without a level attribute",
            detail="Wazuh refuses to load a rule that has no level.",
            recommendation="Add level=\"0\"-\"16\". Use 0 for rules that only "
                           "feed other rules.",
            rule_id=rid, line=line,
        ))
    else:
        try:
            level = int(level_raw)
            if not (MIN_LEVEL <= level <= MAX_LEVEL):
                issues.append(LintIssue(
                    code="WZ053", severity="error",
                    title=f"Rule level {level} is out of range",
                    detail=f"Valid Wazuh levels are {MIN_LEVEL}-{MAX_LEVEL}.",
                    recommendation=f"Clamp the level into {MIN_LEVEL}-{MAX_LEVEL}. "
                                   f"12+ already means 'highest importance'.",
                    rule_id=rid, line=line,
                ))
        except ValueError:
            issues.append(LintIssue(
                code="WZ054", severity="error",
                title=f"Rule level \"{level_raw}\" is not a number",
                detail="Wazuh parses the level as an integer.",
                recommendation="Use a plain integer between 0 and 16.",
                rule_id=rid, line=line,
            ))

    if rid is not None:
        if not (MIN_RULE_ID <= rid <= MAX_RULE_ID):
            issues.append(LintIssue(
                code="WZ055", severity="error",
                title=f"Rule id {rid} is outside the allowed range",
                detail=f"Wazuh rule ids must be {MIN_RULE_ID}-{MAX_RULE_ID}.",
                recommendation="Pick an id in the 100000-120000 custom range.",
                rule_id=rid, line=line,
            ))
        elif rid < RESERVED_ID_CEILING and rule_elem.get("overwrite") != "yes":
            issues.append(LintIssue(
                code="WZ056", severity="warning",
                title=f"Rule id {rid} sits in Wazuh's reserved range",
                detail="Ids below 100000 belong to the bundled ruleset. On the "
                       "next ruleset update your rule is either shadowed or it "
                       "collides with an upstream rule.",
                recommendation=f"Move the rule to 100000-{CUSTOM_ID_CEILING}, or "
                               f"add overwrite=\"yes\" if you really do intend "
                               f"to replace built-in rule {rid}.",
                rule_id=rid, line=line,
            ))
        elif rid > CUSTOM_ID_CEILING:
            issues.append(LintIssue(
                code="WZ057", severity="info",
                title=f"Rule id {rid} is above the usual custom range",
                detail=f"Custom rules conventionally live in "
                       f"100000-{CUSTOM_ID_CEILING}.",
                recommendation="Fine technically, but stay inside the custom "
                               "range so future ruleset updates never collide.",
                rule_id=rid, line=line,
            ))

    # Unknown attributes / children are almost always typos.
    for attr in rule_elem.keys():
        if attr not in VALID_RULE_ATTRS:
            issues.append(LintIssue(
                code="WZ058", severity="warning",
                title=f"Unknown rule attribute '{attr}'",
                detail=f"Wazuh ignores attributes it does not know, so "
                       f"'{attr}' silently does nothing.",
                recommendation=f"Valid attributes: "
                               f"{', '.join(sorted(VALID_RULE_ATTRS))}.",
                rule_id=rid, line=line,
            ))

    for child in rule_elem:
        if not isinstance(child.tag, str):
            continue
        if child.tag not in VALID_RULE_CHILDREN:
            issues.append(LintIssue(
                code="WZ059", severity="warning",
                title=f"Unknown tag <{child.tag}> inside rule",
                detail="Wazuh does not recognise this tag. Depending on the "
                       "version it is either ignored or rejected at load.",
                recommendation="Check the spelling against the Wazuh rules "
                               "syntax reference (common typos: <discription>, "
                               "<if_sids>, <mitre_id>).",
                rule_id=rid, line=line,
            ))
        elif child.tag in DEPRECATED_TAGS:
            issues.append(LintIssue(
                code="WZ060", severity="info",
                title=f"<{child.tag}> is deprecated",
                detail="Wazuh 4.x replaced the per-field correlation tags with "
                       "a single <same_field>.",
                recommendation=f"Use {DEPRECATED_TAGS[child.tag]} instead.",
                rule_id=rid, line=line,
            ))

    # Description
    desc_elem = rule_elem.find("description")
    if desc_elem is None:
        issues.append(LintIssue(
            code="WZ061", severity="error",
            title="Rule has no <description>",
            detail="wazuh-manager reports 'rule has no description' and stops "
                   "loading the file.",
            recommendation="Add a one line <description> saying what fired and "
                           "why it matters. It is the alert title in the "
                           "dashboard.",
            rule_id=rid, line=line,
        ))
    elif not _text(desc_elem):
        issues.append(LintIssue(
            code="WZ062", severity="error",
            title="Rule has an empty <description>",
            detail="An empty description is treated the same as a missing one.",
            recommendation="Write the alert title analysts will read.",
            rule_id=rid, line=line,
        ))
    elif len(_text(desc_elem)) > 255:
        issues.append(LintIssue(
            code="WZ063", severity="info",
            title="Description longer than 255 characters",
            detail="Long descriptions get truncated in alerts and in the "
                   "dashboard rule table.",
            recommendation="Keep the description short and move the detail "
                           "into <info>.",
            rule_id=rid, line=line,
        ))

    # <field> needs a name
    for fld in rule_elem.findall("field"):
        if not fld.get("name"):
            issues.append(LintIssue(
                code="WZ064", severity="error",
                title="<field> without a name attribute",
                detail="Wazuh cannot map the pattern to a decoded field.",
                recommendation="Write <field name=\"win.eventdata.image\">...</field>.",
                rule_id=rid, line=line,
            ))

    # <list> needs field + lookup
    for lst in rule_elem.findall("list"):
        if not lst.get("field") or not lst.get("lookup"):
            issues.append(LintIssue(
                code="WZ065", severity="error",
                title="<list> missing field or lookup attribute",
                detail="A CDB lookup needs both: which decoded field to test "
                       "and how to test it.",
                recommendation="Write <list field=\"srcip\" "
                               "lookup=\"address_match_key\">etc/lists/...</list>.",
                rule_id=rid, line=line,
            ))
        if not _text(lst):
            issues.append(LintIssue(
                code="WZ066", severity="error",
                title="<list> has no CDB path",
                detail="The element text must point at a compiled list, "
                       "relative to the Wazuh install root.",
                recommendation="Add the path, e.g. etc/lists/known-ips.",
                rule_id=rid, line=line,
            ))

    # <options>
    for opt in rule_elem.findall("options"):
        value = _text(opt)
        if value and value not in VALID_OPTIONS:
            issues.append(LintIssue(
                code="WZ067", severity="warning",
                title=f"Unknown rule option '{value}'",
                detail="Wazuh ignores unknown options.",
                recommendation=f"Valid options: {', '.join(sorted(VALID_OPTIONS))}.",
                rule_id=rid, line=line,
            ))

    # frequency / timeframe pairing
    freq_raw = rule_elem.findtext("frequency") or rule_elem.get("frequency")
    tf_raw = rule_elem.findtext("timeframe") or rule_elem.get("timeframe")
    freq = None
    if freq_raw:
        try:
            freq = int(freq_raw.strip())
        except ValueError:
            issues.append(LintIssue(
                code="WZ068", severity="error",
                title=f"<frequency> value \"{freq_raw}\" is not a number",
                detail="Wazuh needs an integer event count.",
                recommendation="Use a plain integer, e.g. <frequency>8</frequency>.",
                rule_id=rid, line=line,
            ))

    if freq is not None:
        if not tf_raw:
            issues.append(LintIssue(
                code="WZ069", severity="error",
                title="<frequency> without <timeframe>",
                detail="Wazuh rejects a frequency rule that has no time window.",
                recommendation="Add <timeframe>120</timeframe> (seconds) next to "
                               "the frequency.",
                rule_id=rid, line=line,
            ))
        if freq < 2:
            issues.append(LintIssue(
                code="WZ070", severity="warning",
                title=f"<frequency>{freq}</frequency> is below 2",
                detail="A frequency of 0 or 1 defeats the point of correlation "
                       "and fires on the first event.",
                recommendation="Use 2 or more, or drop the frequency block.",
                rule_id=rid, line=line,
            ))
        has_correlator = any(
            rule_elem.find(t) is not None
            for t in ("if_matched_sid", "if_matched_group", "if_matched_level")
        )
        if not has_correlator:
            issues.append(LintIssue(
                code="WZ071", severity="warning",
                title="<frequency> with no if_matched_* anchor",
                detail="Without if_matched_sid / if_matched_group Wazuh has no "
                       "event set to count, so the counter never advances.",
                recommendation="Add <if_matched_sid>PARENT_ID</if_matched_sid> "
                               "or <if_matched_group>authentication_failed"
                               "</if_matched_group>.",
                rule_id=rid, line=line,
            ))

    if tf_raw:
        try:
            int(str(tf_raw).strip())
        except ValueError:
            issues.append(LintIssue(
                code="WZ078", severity="error",
                title=f"<timeframe> value \"{tf_raw}\" is not a number",
                detail="Wazuh needs the window in whole seconds.",
                recommendation="Use a plain integer, e.g. <timeframe>120</timeframe>.",
                rule_id=rid, line=line,
            ))

    if freq is None and tf_raw and rule_elem.find("timeframe") is not None:
        issues.append(LintIssue(
            code="WZ072", severity="warning",
            title="<timeframe> without <frequency>",
            detail="A time window with nothing to count has no effect.",
            recommendation="Add a <frequency> or remove the timeframe.",
            rule_id=rid, line=line,
        ))

    # sid references must be numeric
    parents: List[int] = []
    matched: List[int] = []
    for tag, sink in (("if_sid", parents), ("if_matched_sid", matched)):
        for elem in rule_elem.findall(tag):
            raw = _text(elem)
            if not raw:
                issues.append(LintIssue(
                    code="WZ073", severity="error",
                    title=f"Empty <{tag}>",
                    detail="The tag is present but carries no rule id.",
                    recommendation=f"Put the parent rule id inside, or delete "
                                   f"the <{tag}> tag.",
                    rule_id=rid, line=line,
                ))
                continue
            good, bad = _int_list(raw)
            sink.extend(good)
            for token in bad:
                issues.append(LintIssue(
                    code="WZ074", severity="error",
                    title=f"<{tag}> contains a non-numeric id '{token}'",
                    detail=f"Value: {raw}",
                    recommendation="Use numeric rule ids, comma separated.",
                    rule_id=rid, line=line,
                ))

    if rid is not None and rid in parents:
        issues.append(LintIssue(
            code="WZ075", severity="error",
            title=f"Rule {rid} lists itself in <if_sid>",
            detail="A rule cannot be its own parent, so it can never fire.",
            recommendation="Point if_sid at the real parent rule id.",
            rule_id=rid, line=line,
        ))

    # groups convention
    grp = rule_elem.find("group")
    if grp is not None:
        gtext = _text(grp)
        if gtext and not gtext.endswith(","):
            issues.append(LintIssue(
                code="WZ076", severity="info",
                title="Rule <group> list does not end with a comma",
                detail=f"<group>{gtext}</group> - Wazuh convention is a "
                       f"trailing comma so group names concatenate cleanly.",
                recommendation=f"Write <group>{gtext},</group>.",
                rule_id=rid, line=line, auto_fixable=True,
            ))

    _check_regex_engine(rule_elem, rid, line, issues)

    # A rule with no condition and no parent matches every single event.
    condition_tags = (
        "match", "regex", "field", "list", "decoded_as", "program_name",
        "srcip", "dstip", "user", "url", "id", "status", "hostname",
        "category", "if_sid", "if_group", "if_level", "if_matched_sid",
        "if_matched_group", "if_matched_level", "if_fts", "action",
        "extra_data", "data", "compiled_rule", "protocol", "system_name",
        "srcport", "dstport", "location", "time", "weekday", "srcuser",
        "dstuser",
    )
    has_condition = any(rule_elem.find(t) is not None for t in condition_tags)
    if not has_condition and rule_elem.get("level") not in (None, "0"):
        issues.append(LintIssue(
            code="WZ077", severity="warning",
            title="Rule has no matching condition",
            detail="No match, regex, field, decoded_as, if_sid or any other "
                   "filter. Wazuh evaluates it against every decoded event, "
                   "which floods alerts and costs CPU on every log line.",
            recommendation="Anchor the rule with <if_sid> on a parent, or add "
                           "at least one field / match condition.",
            rule_id=rid, line=line,
        ))

    return {
        "rule_id": rid,
        "line": line,
        "parents": parents,
        "matched": matched,
        "if_groups": [_text(e) for e in rule_elem.findall("if_group") if _text(e)],
        "if_matched_groups": [
            _text(e) for e in rule_elem.findall("if_matched_group") if _text(e)
        ],
        "groups": [
            g.strip() for g in _text(grp).split(",") if g.strip()
        ] if grp is not None else [],
        "level": rule_elem.get("level"),
    }


# --------------------------------------------------------------------------
# Phase E - cross rule / graph
# --------------------------------------------------------------------------

def _check_graph(summaries: List[Dict[str, Any]], issues: List[LintIssue]) -> Dict[str, Any]:
    ids = [s["rule_id"] for s in summaries if s["rule_id"] is not None]
    id_set = set(ids)
    line_of = {s["rule_id"]: s["line"] for s in summaries}

    # Duplicate ids stop the manager dead.
    for rid, count in Counter(ids).items():
        if count > 1:
            issues.append(LintIssue(
                code="WZ080", severity="error",
                title=f"Rule id {rid} is defined {count} times",
                detail="wazuh-manager aborts with 'Duplicated rule ID' and the "
                       "whole ruleset fails to load.",
                recommendation=f"Give each copy its own id, or delete the "
                               f"duplicates. If you meant to replace an "
                               f"existing rule, keep one definition and add "
                               f"overwrite=\"yes\".",
                rule_id=rid, line=line_of.get(rid),
            ))

    # Groups defined anywhere in this file.
    known_groups: Set[str] = set()
    for s in summaries:
        known_groups.update(s["groups"])

    dangling: List[Tuple[int, int]] = []
    for s in summaries:
        rid = s["rule_id"]
        if rid is None:
            continue
        for parent in s["parents"] + s["matched"]:
            if parent not in id_set:
                dangling.append((rid, parent))
                severity = "info" if parent < RESERVED_ID_CEILING else "warning"
                origin = ("a rule from Wazuh's bundled ruleset"
                          if parent < RESERVED_ID_CEILING
                          else "a custom rule that is not in this file")
                issues.append(LintIssue(
                    code="WZ081", severity=severity,
                    title=f"Rule {rid} references parent {parent}, which is not "
                          f"in this file",
                    detail=f"Rule {parent} looks like {origin}. If it does not "
                           f"exist on the manager, rule {rid} can never fire "
                           f"and the manager logs 'Signature ID "
                           f"'{parent}' was not found'.",
                    recommendation=f"Confirm rule {parent} exists on the "
                                   f"manager (/var/ossec/bin/wazuh-logtest, or "
                                   f"grep the ruleset). If it does not, point "
                                   f"if_sid at a rule that does.",
                    rule_id=rid, line=s["line"],
                ))

        for gname in s["if_groups"] + s["if_matched_groups"]:
            if gname not in known_groups:
                issues.append(LintIssue(
                    code="WZ082", severity="info",
                    title=f"Rule {rid} references group '{gname}' which is not "
                          f"defined in this file",
                    detail="The group probably comes from the bundled ruleset. "
                           "Worth confirming, because a typo here silently "
                           "disables the rule.",
                    recommendation=f"Check the spelling of '{gname}' against "
                                   f"the groups your parent rules actually set.",
                    rule_id=rid, line=s["line"],
                ))

    # Cycles in the if_sid chain.
    parent_map = {
        s["rule_id"]: [p for p in s["parents"] if p in id_set]
        for s in summaries if s["rule_id"] is not None
    }
    cycles = [c for c in _find_cycles(parent_map) if len(c) > 1]
    for cycle in cycles:
        chain = " -> ".join(str(c) for c in cycle + [cycle[0]])
        issues.append(LintIssue(
            code="WZ083", severity="error",
            title="Circular if_sid dependency",
            detail=f"Chain: {chain}. Wazuh cannot resolve the rule tree and "
                   f"neither rule in the loop will ever fire.",
            recommendation="Break the loop. A rule tree has to be acyclic: "
                           "each rule points at exactly one ancestor chain.",
            rule_id=cycle[0], line=line_of.get(cycle[0]),
        ))

    # Rules nobody builds on and that build on nobody.
    has_children: Set[int] = set()
    for s in summaries:
        for p in s["parents"] + s["matched"]:
            has_children.add(p)
    orphans = [
        s["rule_id"] for s in summaries
        if s["rule_id"] is not None
        and not s["parents"] and not s["matched"]
        and not s["if_groups"] and not s["if_matched_groups"]
        and s["rule_id"] not in has_children
    ]

    return {
        "duplicate_ids": [rid for rid, c in Counter(ids).items() if c > 1],
        "dangling_parents": dangling,
        "cycles": cycles,
        "orphan_rules": orphans,
        "known_groups": sorted(known_groups),
    }


def _find_cycles(parent_map: Dict[int, List[int]]) -> List[List[int]]:
    """Return one representative node list per cycle found in the sid graph."""
    WHITE, GREY, BLACK = 0, 1, 2
    colour: Dict[int, int] = {n: WHITE for n in parent_map}
    stack: List[int] = []
    cycles: List[List[int]] = []
    seen_signatures: Set[frozenset] = set()

    def visit(node: int) -> None:
        colour[node] = GREY
        stack.append(node)
        for nxt in parent_map.get(node, []):
            if nxt not in colour:
                continue
            if colour[nxt] == GREY:
                cycle = stack[stack.index(nxt):]
                sig = frozenset(cycle)
                if sig not in seen_signatures:
                    seen_signatures.add(sig)
                    cycles.append(list(cycle))
            elif colour[nxt] == WHITE:
                visit(nxt)
        stack.pop()
        colour[node] = BLACK

    for node in list(parent_map):
        if colour[node] == WHITE:
            visit(node)
    return cycles


# --------------------------------------------------------------------------
# Public API - lint
# --------------------------------------------------------------------------

def lint_wazuh_xml(xml_content: str) -> LintReport:
    """Run every check against a Wazuh rules file and return a LintReport."""
    report = LintReport()
    if not xml_content or not xml_content.strip():
        report.issues.append(LintIssue(
            code="WZ000", severity="error",
            title="File is empty",
            detail="There is nothing to parse.",
            recommendation="Load a Wazuh rules XML file.",
        ))
        return report

    _check_raw_text(xml_content, report.issues)

    root = _parse(xml_content, report.issues)
    if root is None:
        return report

    report.parsed = True
    _check_structure(root, report.issues)

    line_map = _build_line_map(xml_content)
    summaries: List[Dict[str, Any]] = []
    for rule_elem in root.findall(".//rule"):
        summary = _check_rule(rule_elem, line_map, report.issues)
        if summary:
            summaries.append(summary)

    report.rule_count = len(summaries)
    if not summaries:
        report.issues.append(LintIssue(
            code="WZ090", severity="warning",
            title="No <rule> elements found",
            detail="The XML parsed but contains no rules.",
            recommendation="Check that rules sit inside the root <group>.",
        ))

    report.stats = _check_graph(summaries, report.issues)

    severity_rank = {"error": 0, "warning": 1, "info": 2}
    report.issues.sort(key=lambda i: (
        severity_rank.get(i.severity, 3),
        i.line if i.line is not None else 10**9,
        i.code,
    ))
    return report


# --------------------------------------------------------------------------
# Public API - clean
# --------------------------------------------------------------------------

def clean_wazuh_xml(xml_content: str, reformat: bool = True) -> Tuple[str, List[str]]:
    """
    Repair the mechanical problems in a Wazuh rules file.

    Args:
        xml_content: the original file text.
        reformat: also re-serialise and re-indent. Requires well-formed XML;
            falls back to text-only cleaning when the document does not parse.

    Returns:
        (cleaned_xml, list of human readable descriptions of what changed)
    """
    fixes: List[str] = []
    text = xml_content

    if text.startswith("﻿"):
        text = text.lstrip("﻿")
        fixes.append("Removed UTF-8 BOM")

    if "\r\n" in text or "\r" in text:
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        fixes.append("Converted CRLF line endings to LF")

    if "\t" in text:
        text = text.replace("\t", "  ")
        fixes.append("Replaced tabs with two spaces")

    # Escape bare ampersands, but never touch the inside of a comment.
    def _escape_outside_comments(src: str) -> Tuple[str, int]:
        out: List[str] = []
        count = 0
        pos = 0
        for m in re.finditer(r"<!--.*?-->", src, re.DOTALL):
            chunk = src[pos:m.start()]
            fixed, n = BARE_AMP.subn("&amp;", chunk)
            out.append(fixed)
            count += n
            out.append(m.group(0))
            pos = m.end()
        chunk = src[pos:]
        fixed, n = BARE_AMP.subn("&amp;", chunk)
        out.append(fixed)
        count += n
        return "".join(out), count

    text, amp_count = _escape_outside_comments(text)
    if amp_count:
        fixes.append(f"Escaped {amp_count} bare '&' as '&amp;'")

    # '--' is illegal inside XML comments.
    def _fix_comment_dashes(match: re.Match) -> str:
        body = match.group(1)
        return "<!--" + re.sub(r"-{2,}", "-", body) + "-->"

    text, dash_count = re.subn(r"<!--(.*?)-->", _fix_comment_dashes, text, flags=re.DOTALL)
    if dash_count and text != xml_content:
        # subn counts every comment, so only report when something really moved.
        if re.search(r"<!--[^>]*--[^>]*-->", xml_content, re.DOTALL):
            fixes.append("Collapsed illegal '--' sequences inside XML comments")

    stripped = "\n".join(line.rstrip() for line in text.split("\n"))
    if stripped != text:
        fixes.append("Stripped trailing whitespace")
        text = stripped

    if not reformat:
        return _ensure_declaration(text, fixes), fixes

    # Full reformat: parse (keeping comments), normalise, re-indent.
    try:
        parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))
        parser.feed(text)
        root = parser.close()
    except Exception:
        fixes.append("Skipped reindent: XML is not well-formed yet - fix the "
                     "errors listed above first")
        return _ensure_declaration(text, fixes), fixes

    if root.tag != "group":
        wrapper = ET.Element("group", {"name": "custom,"})
        if root.tag == "rule":
            wrapper.append(root)
        else:
            for child in list(root):
                wrapper.append(child)
        root = wrapper
        fixes.append("Wrapped the ruleset in a root <group name=\"custom,\">")

    name = root.get("name")
    if not name:
        root.set("name", "custom,")
        fixes.append("Added a name to the root <group>")
    elif not name.rstrip().endswith(","):
        root.set("name", name.rstrip() + ",")
        fixes.append("Added the trailing comma to the root group name")

    comma_fixes = 0
    for rule_elem in root.iter("rule"):
        grp = rule_elem.find("group")
        if grp is not None and grp.text:
            value = grp.text.strip()
            if value and not value.endswith(","):
                grp.text = value + ","
                comma_fixes += 1
    if comma_fixes:
        fixes.append(f"Added trailing commas to {comma_fixes} rule <group> lists")

    _strip_whitespace_text(root)
    reindented = False
    try:
        ET.indent(root, space="  ")  # Python 3.9+
        reindented = True
    except AttributeError:
        pass

    body = _space_out_rules(ET.tostring(root, encoding="unicode"))
    cleaned = '<?xml version="1.0" encoding="UTF-8"?>\n' + body.rstrip() + "\n"

    # Only claim a change the user can actually see in the output.
    if reindented and cleaned != text and cleaned != xml_content:
        fixes.append("Reindented with two spaces per level")
    if not re.match(r"^\s*<\?xml", xml_content.lstrip("﻿")):
        fixes.append("Added the XML declaration")

    return cleaned, fixes


def _space_out_rules(body: str) -> str:
    """Put one blank line between top-level rules so the file stays readable."""
    out: List[str] = []
    for line in body.split("\n"):
        starts_block = re.match(r"^  (?:<rule\b|<!--)", line)
        if starts_block and out and out[-1].strip():
            out.append("")
        out.append(line)
    return "\n".join(out)

def _strip_whitespace_text(elem: ET.Element) -> None:
    """Drop whitespace-only text so ET.indent produces a clean tree."""
    if elem.text is not None and not elem.text.strip():
        elem.text = None
    if elem.tail is not None and not elem.tail.strip():
        elem.tail = None
    for child in elem:
        _strip_whitespace_text(child)


def _ensure_declaration(text: str, fixes: List[str]) -> str:
    if not re.match(r"^\s*<\?xml", text):
        fixes.append("Added the XML declaration")
        return '<?xml version="1.0" encoding="UTF-8"?>\n' + text.lstrip()
    return text


# --------------------------------------------------------------------------
# Reporting helpers
# --------------------------------------------------------------------------

def format_report_text(report: LintReport) -> str:
    """Plain text version of the report, for download or copy/paste."""
    lines: List[str] = []
    lines.append("=" * 72)
    lines.append("WAZUH RULESET HEALTH REPORT")
    lines.append("=" * 72)
    counts = report.by_severity()
    lines.append(f"Rules analysed : {report.rule_count}")
    lines.append(f"Health score   : {report.health_score()}/100")
    lines.append(f"Manager safe   : {'yes' if report.manager_safe else 'NO'}")
    lines.append(
        f"Findings       : {counts['error']} error(s), "
        f"{counts['warning']} warning(s), {counts['info']} info"
    )
    lines.append("")

    if not report.issues:
        lines.append("No issues found. This ruleset is clean.")
        return "\n".join(lines)

    for severity, label in (("error", "ERRORS"), ("warning", "WARNINGS"),
                            ("info", "NOTES")):
        bucket = [i for i in report.issues if i.severity == severity]
        if not bucket:
            continue
        lines.append("-" * 72)
        lines.append(f"{label} ({len(bucket)})")
        lines.append("-" * 72)
        for issue in bucket:
            lines.append(f"[{issue.code}] {issue.title}  ({issue.location()})")
            for detail_line in issue.detail.splitlines():
                lines.append(f"    {detail_line}")
            lines.append(f"    FIX: {issue.recommendation}")
            lines.append("")
    return "\n".join(lines)


def issues_to_rows(report: LintReport) -> List[Dict[str, str]]:
    """
    Flatten the report for a dataframe view.

    Every value is a string on purpose. Mixing ints with a "-" placeholder in
    one column makes Arrow serialisation fail, and Streamlit then logs a
    conversion traceback on every rerender.
    """
    return [
        {
            "Severity": issue.severity,
            "Code": issue.code,
            "Rule": str(issue.rule_id) if issue.rule_id is not None else "-",
            "Line": str(issue.line) if issue.line is not None else "-",
            "Issue": issue.title,
            "Recommendation": issue.recommendation,
        }
        for issue in report.issues
    ]


# --------------------------------------------------------------------------
# Public API - lint with auto-recovery
# --------------------------------------------------------------------------

def lint_with_recovery(xml_content: str) -> Tuple[LintReport, Optional[str], List[str]]:
    """
    Lint a file, and when a syntax error blocks the parser, clean the file and
    lint again so the user still sees the semantic problems underneath.

    Returns:
        (report, repaired_xml_or_None, fixes_applied)

        ``repaired_xml`` is only set when cleaning actually unblocked the
        parser. The returned report then describes the repaired document, with
        the original syntax errors kept at the top of the issue list.
    """
    report = lint_wazuh_xml(xml_content)
    if report.parsed:
        return report, None, []

    repaired, fixes = clean_wazuh_xml(xml_content, reformat=True)
    if repaired == xml_content:
        return report, None, fixes

    second = lint_wazuh_xml(repaired)
    if not second.parsed:
        return report, None, fixes

    blocking = [i for i in report.issues if i.code in ("WZ002", "WZ006", "WZ007", "WZ020")]
    for issue in blocking:
        issue.detail += ("\n\nAuto-clean repaired this so the rest of the file "
                         "could be analysed. Download the cleaned XML below.")
    merged = LintReport(
        issues=blocking + second.issues,
        parsed=True,
        rule_count=second.rule_count,
        stats=second.stats,
    )
    return merged, repaired, fixes
