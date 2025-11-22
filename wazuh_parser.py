"""
Wazuh XML Rule Parser

This module provides utilities for ingesting, validating, and normalizing Wazuh XML rules.
It captures detection cues, filter conditions, and rule severity/level information.
"""

import xml.etree.ElementTree as ET
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass, asdict, field
import logging

logger = logging.getLogger(__name__)


@dataclass
class DetectionCues:
    """Captures detection-related information from a rule."""
    decoded_as: Optional[str] = None
    if_sid: Optional[int] = None
    if_matched_groups: List[str] = field(default_factory=list)
    if_groups: List[str] = field(default_factory=list)
    description: Optional[str] = None


@dataclass
class FilterCondition:
    """Represents a single filter condition in a rule."""
    match: Optional[str] = None
    field: Optional[str] = None
    frequency: Optional[int] = None
    timeframe: Optional[int] = None
    same_field: Optional[str] = None
    no_alert: Optional[bool] = None
    ignore: Optional[str] = None


@dataclass
class RuleData:
    """Normalized Python representation of a Wazuh rule."""
    rule_id: int
    level: int
    description: str = ""
    detection_cues: DetectionCues = field(default_factory=DetectionCues)
    filter_conditions: List[FilterCondition] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    cis_controls: List[str] = field(default_factory=list)
    nist_controls: List[str] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)


def parse_wazuh_xml(
    xml_content: str,
) -> Tuple[List[RuleData], List[str]]:
    """
    Parse Wazuh XML content and extract rule information.
    
    Args:
        xml_content: String containing the XML content to parse
        
    Returns:
        Tuple of (rules list, warnings list)
        - rules: List of normalized RuleData objects
        - warnings: List of warning messages encountered during parsing
    """
    rules = []
    warnings = []

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as e:
        warnings.append(f"XML parsing error: {str(e)}")
        return [], warnings
    except Exception as e:
        warnings.append(f"Unexpected error parsing XML: {str(e)}")
        return [], warnings

    # Find all rule elements (they can be at various levels)
    rule_elements = root.findall(".//rule")

    if not rule_elements:
        warnings.append("No <rule> elements found in XML document")
        return [], warnings

    for rule_elem in rule_elements:
        try:
            rule_data = _parse_rule_element(rule_elem)
            if rule_data:
                rules.append(rule_data)
        except Exception as e:
            rule_id = rule_elem.get("id", "unknown")
            warnings.append(f"Error parsing rule {rule_id}: {str(e)}")
            continue

    return rules, warnings


def _parse_rule_element(rule_elem: ET.Element) -> Optional[RuleData]:
    """
    Parse a single <rule> element and return a RuleData object.
    
    Args:
        rule_elem: An xml.etree.ElementTree.Element representing a <rule>
        
    Returns:
        RuleData object or None if required fields are missing
    """
    rule_id_str = rule_elem.get("id")
    level_str = rule_elem.get("level")

    # Validate required attributes
    if not rule_id_str or not level_str:
        raise ValueError(
            f"Rule missing required attributes. ID: {rule_id_str}, Level: {level_str}"
        )

    try:
        rule_id = int(rule_id_str)
        level = int(level_str)
    except ValueError as e:
        raise ValueError(f"Invalid rule ID or level format: {e}")

    # Extract description
    description_elem = rule_elem.find("description")
    description = description_elem.text if description_elem is not None else ""

    # Parse detection cues
    detection_cues = _parse_detection_cues(rule_elem)

    # Parse filter conditions
    filter_conditions = _parse_filter_conditions(rule_elem)

    # Parse reference information (MITRE, CIS, NIST)
    mitre_techniques = _extract_references(rule_elem, "attack", "technique")
    cis_controls = _extract_references(rule_elem, "cis", "control")
    nist_controls = _extract_references(rule_elem, "nist", "control")

    # Extract groups
    groups_elem = rule_elem.find("group")
    groups = []
    if groups_elem is not None and groups_elem.text:
        groups = [g.strip() for g in groups_elem.text.split(",")]

    return RuleData(
        rule_id=rule_id,
        level=level,
        description=description,
        detection_cues=detection_cues,
        filter_conditions=filter_conditions,
        mitre_techniques=mitre_techniques,
        cis_controls=cis_controls,
        nist_controls=nist_controls,
        groups=groups,
    )


def _parse_detection_cues(rule_elem: ET.Element) -> DetectionCues:
    """Extract detection-related cues from a rule element."""
    decoded_as = None
    if_sid = None
    if_matched_groups = []
    if_groups = []
    description = None

    # Look for decoded_as in decoder/program_name pattern
    decoder_elem = rule_elem.find("decoder")
    if decoder_elem is not None:
        program_name = decoder_elem.find("program_name")
        if program_name is not None and program_name.text:
            decoded_as = program_name.text

    # Look for if_sid (parent rule)
    if_sid_elem = rule_elem.find("if_sid")
    if if_sid_elem is not None and if_sid_elem.text:
        try:
            if_sid = int(if_sid_elem.text)
        except ValueError:
            pass

    # Look for if_matched_group (parent rule groups)
    for if_matched_group_elem in rule_elem.findall("if_matched_group"):
        if if_matched_group_elem is not None and if_matched_group_elem.text:
            group_name = if_matched_group_elem.text.strip()
            if_matched_groups.append(group_name)

    # Look for if_group (different from if_matched_group)
    for if_group_elem in rule_elem.findall("if_group"):
        if if_group_elem is not None and if_group_elem.text:
            group_name = if_group_elem.text.strip()
            if_groups.append(group_name)

    # Description for detection cues
    description_elem = rule_elem.find("description")
    if description_elem is not None and description_elem.text:
        description = description_elem.text

    # Debug logging for extracted relationships
    rule_id = rule_elem.get("id", "unknown")
    if if_sid:
        logger.info(f"Rule {rule_id} --if_sid--> {if_sid}")
    for group in if_matched_groups:
        logger.info(f"Rule {rule_id} --if_matched_group--> {group}")
    for group in if_groups:
        logger.info(f"Rule {rule_id} --if_group--> {group}")

    return DetectionCues(
        decoded_as=decoded_as,
        if_sid=if_sid,
        if_matched_groups=if_matched_groups,
        if_groups=if_groups,
        description=description,
    )


def _parse_filter_conditions(rule_elem: ET.Element) -> List[FilterCondition]:
    """Extract filter conditions from a rule element."""
    conditions = []

    # Parse match conditions
    match_elem = rule_elem.find("match")
    if match_elem is not None and match_elem.text:
        condition = FilterCondition(match=match_elem.text)
        conditions.append(condition)

    # Parse field conditions
    field_elem = rule_elem.find("field")
    if field_elem is not None and field_elem.text:
        condition = FilterCondition(field=field_elem.text)
        conditions.append(condition)

    # Parse frequency-based conditions
    frequency_elem = rule_elem.find("frequency")
    if frequency_elem is not None and frequency_elem.text:
        try:
            frequency = int(frequency_elem.text)
            timeframe_elem = rule_elem.find("timeframe")
            timeframe = None
            if timeframe_elem is not None and timeframe_elem.text:
                try:
                    timeframe = int(timeframe_elem.text)
                except ValueError:
                    pass

            same_field_elem = rule_elem.find("same_field")
            same_field = same_field_elem.text if same_field_elem is not None else None

            condition = FilterCondition(
                frequency=frequency,
                timeframe=timeframe,
                same_field=same_field,
            )
            conditions.append(condition)
        except ValueError:
            pass

    # Parse no_alert
    no_alert_elem = rule_elem.find("no_alert")
    if no_alert_elem is not None:
        condition = FilterCondition(no_alert=True)
        conditions.append(condition)

    # Parse ignore conditions
    ignore_elem = rule_elem.find("ignore")
    if ignore_elem is not None and ignore_elem.text:
        condition = FilterCondition(ignore=ignore_elem.text)
        conditions.append(condition)

    return conditions


def _extract_references(
    rule_elem: ET.Element, ref_type: str, sub_type: str
) -> List[str]:
    """
    Extract reference information (MITRE, CIS, NIST) from a rule.
    
    Args:
        rule_elem: The rule element to search
        ref_type: The type of reference (e.g., 'attack', 'cis', 'nist')
        sub_type: The subtype to extract (e.g., 'technique', 'control')
        
    Returns:
        List of extracted reference values
    """
    references = []
    for ref_elem in rule_elem.findall("reference"):
        ref_type_elem = ref_elem.find("type")
        if ref_type_elem is not None and ref_type_elem.text == ref_type:
            sub_elem = ref_elem.find(sub_type)
            if sub_elem is not None and sub_elem.text:
                references.append(sub_elem.text)
    return references


def summarize_filter_logic(conditions: List[FilterCondition]) -> str:
    """
    Generate a human-readable summary of filter conditions.
    
    Args:
        conditions: List of FilterCondition objects
        
    Returns:
        Human-readable summary string
    """
    if not conditions:
        return "No filter conditions"

    summaries = []
    for cond in conditions:
        if cond.match:
            summaries.append(f"Match: {cond.match}")
        if cond.field:
            summaries.append(f"Field: {cond.field}")
        if cond.frequency:
            timeframe_info = f" within {cond.timeframe}s" if cond.timeframe else ""
            field_info = f" on {cond.same_field}" if cond.same_field else ""
            summaries.append(
                f"Frequency: {cond.frequency} occurrences{timeframe_info}{field_info}"
            )
        if cond.no_alert:
            summaries.append("No alert: True")
        if cond.ignore:
            summaries.append(f"Ignore: {cond.ignore}")

    return " | ".join(summaries) if summaries else "No filter conditions"


def extract_relationships(rules: List[RuleData]) -> List[Dict[str, Any]]:
    """
    Extract all relationships from parsed rules for debugging and visualization.
    
    Args:
        rules: List of RuleData objects
        
    Returns:
        List of relationship dictionaries with source, target, and type
    """
    relationships = []
    
    for rule in rules:
        # if_sid relationships
        if rule.detection_cues.if_sid:
            relationships.append({
                "source_rule_id": rule.rule_id,
                "target_rule_id": rule.detection_cues.if_sid,
                "relationship_type": "if_sid",
                "description": f"Rule {rule.rule_id} references parent rule {rule.detection_cues.if_sid}"
            })
        
        # if_matched_group relationships
        for group in rule.detection_cues.if_matched_groups:
            relationships.append({
                "source_rule_id": rule.rule_id,
                "target_group": group,
                "relationship_type": "if_matched_group",
                "description": f"Rule {rule.rule_id} triggers on group {group}"
            })
        
        # if_group relationships
        for group in rule.detection_cues.if_groups:
            relationships.append({
                "source_rule_id": rule.rule_id,
                "target_group": group,
                "relationship_type": "if_group",
                "description": f"Rule {rule.rule_id} correlates with group {group}"
            })
    
    return relationships


def rule_to_dict(rule: RuleData) -> Dict[str, Any]:
    """
    Convert a RuleData object to a dictionary representation.
    
    Args:
        rule: RuleData object to convert
        
    Returns:
        Dictionary representation of the rule
    """
    return {
        "rule_id": rule.rule_id,
        "level": rule.level,
        "description": rule.description,
        "detection_cues": asdict(rule.detection_cues),
        "filter_conditions": [asdict(fc) for fc in rule.filter_conditions],
        "mitre_techniques": rule.mitre_techniques,
        "cis_controls": rule.cis_controls,
        "nist_controls": rule.nist_controls,
        "groups": rule.groups,
        "filter_summary": summarize_filter_logic(rule.filter_conditions),
    }


def generate_debug_log(rules: List[RuleData]) -> str:
    """
    Generate a comprehensive debug log showing all extracted values for each rule.
    
    Args:
        rules: List of RuleData objects to log
        
    Returns:
        Formatted string with debug information for all rules
    """
    if not rules:
        return "No rules to log."
    
    lines = []
    
    for rule in rules:
        lines.append("=" * 60)
        lines.append("RULE DEBUG LOG")
        lines.append("=" * 60)
        lines.append(f"Rule ID: {rule.rule_id}")
        lines.append(f"Level: {rule.level}")
        lines.append(f"Description: \"{rule.description}\"")
        
        lines.append(f"Groups Extracted: {rule.groups}")
        lines.append(f"if_sid Extracted: {[rule.detection_cues.if_sid] if rule.detection_cues.if_sid else []}")
        lines.append(f"if_matched_group Extracted: {rule.detection_cues.if_matched_groups}")
        lines.append(f"if_group Extracted: {rule.detection_cues.if_groups}")
        lines.append(f"MITRE Techniques Extracted: {rule.mitre_techniques}")
        lines.append(f"CIS Controls Extracted: {rule.cis_controls}")
        lines.append(f"NIST Controls Extracted: {rule.nist_controls}")
        
        if rule.filter_conditions:
            lines.append("Filter Conditions Extracted:")
            for i, condition in enumerate(rule.filter_conditions, 1):
                lines.append(f"  Condition {i}:")
                if condition.match:
                    lines.append(f"    Match: {condition.match}")
                if condition.field:
                    lines.append(f"    Field: {condition.field}")
                if condition.frequency is not None:
                    lines.append(f"    Frequency: {condition.frequency}")
                if condition.timeframe is not None:
                    lines.append(f"    Timeframe: {condition.timeframe} seconds")
                if condition.same_field:
                    lines.append(f"    Same Field: {condition.same_field}")
                if condition.no_alert is not None:
                    lines.append(f"    No Alert: {condition.no_alert}")
                if condition.ignore:
                    lines.append(f"    Ignore: {condition.ignore}")
        else:
            lines.append("Filter Conditions Extracted: (none)")
        
        if rule.detection_cues.decoded_as:
            lines.append(f"Decoded As: {rule.detection_cues.decoded_as}")
        
        lines.append("---\n")
    
    return "\n".join(lines)
