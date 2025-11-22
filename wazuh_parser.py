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

    # Description for detection cues
    description_elem = rule_elem.find("description")
    if description_elem is not None and description_elem.text:
        description = description_elem.text

    return DetectionCues(
        decoded_as=decoded_as,
        if_sid=if_sid,
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
