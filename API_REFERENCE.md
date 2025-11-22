# Wazuh Parser API Reference

Complete API documentation for the `wazuh_parser` module.

## Module Contents

### Main Functions

#### `parse_wazuh_xml(xml_content: str) -> Tuple[List[RuleData], List[str]]`

Parse Wazuh XML content and extract rule information.

**Parameters:**
- `xml_content` (str): String containing the XML content to parse

**Returns:**
- Tuple of (rules list, warnings list):
  - `rules` (List[RuleData]): List of normalized RuleData objects
  - `warnings` (List[str]): List of warning messages encountered during parsing

**Raises:**
- No exceptions are raised; errors are returned as warnings

**Example:**
```python
from wazuh_parser import parse_wazuh_xml

xml_content = '''<?xml version="1.0"?>
<ruleset>
    <rule id="1001" level="3">
        <description>Test rule</description>
    </rule>
</ruleset>'''

rules, warnings = parse_wazuh_xml(xml_content)
print(f"Parsed {len(rules)} rules")
for warning in warnings:
    print(f"Warning: {warning}")
```

---

#### `summarize_filter_logic(conditions: List[FilterCondition]) -> str`

Generate a human-readable summary of filter conditions.

**Parameters:**
- `conditions` (List[FilterCondition]): List of FilterCondition objects

**Returns:**
- `str`: Human-readable summary string with conditions joined by " | " separator

**Example:**
```python
from wazuh_parser import summarize_filter_logic, FilterCondition

conditions = [
    FilterCondition(match=".*error.*"),
    FilterCondition(frequency=5, timeframe=60)
]

summary = summarize_filter_logic(conditions)
# Output: "Match: .*error.* | Frequency: 5 occurrences within 60s"
```

---

#### `rule_to_dict(rule: RuleData) -> Dict[str, Any]`

Convert a RuleData object to a dictionary representation.

**Parameters:**
- `rule` (RuleData): RuleData object to convert

**Returns:**
- `Dict[str, Any]`: Dictionary representation of the rule including all nested objects

**Example:**
```python
from wazuh_parser import parse_wazuh_xml, rule_to_dict
import json

rules, _ = parse_wazuh_xml(xml_content)
rule_dicts = [rule_to_dict(r) for r in rules]
json_str = json.dumps(rule_dicts, indent=2)
```

---

### Data Classes

#### `RuleData`

Normalized Python representation of a Wazuh rule.

**Attributes:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `rule_id` | int | Unique rule identifier |
| `level` | int | Alert level (0-15) |
| `description` | str | Rule description |
| `detection_cues` | DetectionCues | Detection-related information |
| `filter_conditions` | List[FilterCondition] | Filter conditions applied to rule |
| `mitre_techniques` | List[str] | MITRE ATT&CK technique IDs |
| `cis_controls` | List[str] | CIS Controls references |
| `nist_controls` | List[str] | NIST Controls references |
| `groups` | List[str] | Rule categories/groups |

**Example:**
```python
from wazuh_parser import RuleData, DetectionCues

rule = RuleData(
    rule_id=1001,
    level=5,
    description="Example rule",
    detection_cues=DetectionCues(if_sid=1000),
    filter_conditions=[],
    mitre_techniques=["T1234"],
    cis_controls=["4.1"],
    nist_controls=["AC-2"],
    groups=["web", "http"]
)
```

---

#### `DetectionCues`

Captures detection-related information from a rule.

**Attributes:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `decoded_as` | Optional[str] | Decoder used (e.g., 'nginx', 'apache') |
| `if_sid` | Optional[int] | Parent rule ID for rule inheritance |
| `description` | Optional[str] | Detection description |

**Example:**
```python
from wazuh_parser import DetectionCues

cues = DetectionCues(
    decoded_as="nginx",
    if_sid=1000,
    description="Web attack detection"
)
```

---

#### `FilterCondition`

Represents a single filter condition in a rule.

**Attributes:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `match` | Optional[str] | Regex pattern to match against logs |
| `field` | Optional[str] | Specific field to check |
| `frequency` | Optional[int] | Number of events to trigger rule |
| `timeframe` | Optional[int] | Time window in seconds |
| `same_field` | Optional[str] | Field to group events by |
| `no_alert` | Optional[bool] | Whether to suppress alerts |
| `ignore` | Optional[str] | Pattern to ignore |

**Example:**
```python
from wazuh_parser import FilterCondition

# Frequency-based condition
freq_condition = FilterCondition(
    frequency=5,
    timeframe=300,
    same_field="src_ip"
)

# Match-based condition
match_condition = FilterCondition(
    match=".*error.*|.*failed.*"
)
```

---

### Internal Functions

These are documented for reference but typically not used directly:

#### `_parse_rule_element(rule_elem: ET.Element) -> Optional[RuleData]`

Parse a single `<rule>` XML element into a RuleData object.

**Parameters:**
- `rule_elem` (ET.Element): XML element representing a `<rule>`

**Returns:**
- `RuleData` or None if required attributes are missing

**Raises:**
- ValueError: If required attributes are invalid

---

#### `_parse_detection_cues(rule_elem: ET.Element) -> DetectionCues`

Extract detection-related cues from a rule element.

**Parameters:**
- `rule_elem` (ET.Element): The rule element to parse

**Returns:**
- `DetectionCues`: Detected cues information

---

#### `_parse_filter_conditions(rule_elem: ET.Element) -> List[FilterCondition]`

Extract filter conditions from a rule element.

**Parameters:**
- `rule_elem` (ET.Element): The rule element to parse

**Returns:**
- `List[FilterCondition]`: List of filter conditions found

---

#### `_extract_references(rule_elem: ET.Element, ref_type: str, sub_type: str) -> List[str]`

Extract reference information (MITRE, CIS, NIST) from a rule.

**Parameters:**
- `rule_elem` (ET.Element): The rule element to search
- `ref_type` (str): Type of reference ('attack', 'cis', 'nist')
- `sub_type` (str): Subtype to extract ('technique', 'control')

**Returns:**
- `List[str]`: List of reference values found

---

## Return Value Structure

### parse_wazuh_xml() Return Structure

```python
(
    [
        RuleData(
            rule_id=1001,
            level=5,
            description="Rule description",
            detection_cues=DetectionCues(
                decoded_as="nginx",
                if_sid=None,
                description="..."
            ),
            filter_conditions=[
                FilterCondition(match=".*error.*"),
                FilterCondition(frequency=5, timeframe=300, same_field="user")
            ],
            mitre_techniques=["T1234.001"],
            cis_controls=["4.1"],
            nist_controls=["AC-2"],
            groups=["web", "http"]
        ),
        ...
    ],
    [
        "Warning: Invalid rule format at line 42",
        "Warning: Missing description for rule 1002"
    ]
)
```

### rule_to_dict() Return Structure

```python
{
    "rule_id": 1001,
    "level": 5,
    "description": "Rule description",
    "detection_cues": {
        "decoded_as": "nginx",
        "if_sid": None,
        "description": "..."
    },
    "filter_conditions": [
        {
            "match": ".*error.*",
            "field": None,
            "frequency": None,
            "timeframe": None,
            "same_field": None,
            "no_alert": None,
            "ignore": None
        }
    ],
    "mitre_techniques": ["T1234.001"],
    "cis_controls": ["4.1"],
    "nist_controls": ["AC-2"],
    "groups": ["web", "http"],
    "filter_summary": "Match: .*error.* | ..."
}
```

---

## Error Handling

### Warnings and Error Messages

The parser returns warnings for various error conditions:

| Scenario | Warning Message | Rules Returned |
|----------|-----------------|-----------------|
| Malformed XML | "XML parsing error: {error}" | Empty list |
| No rules found | "No <rule> elements found in XML document" | Empty list |
| Missing rule attributes | "Error parsing rule {id}: {error}" | Partial results |
| Invalid data types | "Error parsing rule {id}: {error}" | Partial results |
| Unexpected exception | "Unexpected error parsing XML: {error}" | Empty list |

### Best Practices

```python
from wazuh_parser import parse_wazuh_xml

xml_content = read_file()
rules, warnings = parse_wazuh_xml(xml_content)

# Always check for warnings
if warnings:
    print("Parsing encountered issues:")
    for w in warnings:
        print(f"  - {w}")

# Handle empty results
if not rules:
    print("No valid rules found")
    return

# Process rules
for rule in rules:
    print(f"Rule {rule.rule_id}: {rule.description}")
```

---

## Type Hints

The module uses Python type hints for IDE support:

```python
from typing import Dict, List, Tuple, Any, Optional

def parse_wazuh_xml(
    xml_content: str,
) -> Tuple[List[RuleData], List[str]]: ...

def summarize_filter_logic(
    conditions: List[FilterCondition]
) -> str: ...

def rule_to_dict(
    rule: RuleData
) -> Dict[str, Any]: ...
```

---

## Performance Characteristics

- **Time Complexity**: O(n) where n is the number of rules
- **Space Complexity**: O(n) for storing parsed rules
- **XML Parsing**: Uses standard library's efficient ElementTree implementation
- **Typical Performance**: ~1000 rules/second on modern hardware

---

## Dependencies

- **Python**: 3.9+
- **Standard Library Only**: xml.etree.ElementTree, dataclasses, typing, logging

No external dependencies required!

---

## Changelog

### Version 1.0.0
- Initial release
- Core parsing functionality
- Detection cues extraction
- Filter condition parsing
- Reference extraction (MITRE, CIS, NIST)
- Group extraction
- Filter logic summarization
- Comprehensive error handling
- Unit test coverage
