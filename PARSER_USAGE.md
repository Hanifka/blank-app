# Wazuh XML Parser Usage Guide

The `wazuh_parser.py` module provides a complete solution for parsing, validating, and normalizing Wazuh XML rule files. This document explains how to use the parser in your Streamlit application.

## Overview

The parser module exposes the following key components:

- **`parse_wazuh_xml(xml_content: str)`**: Main entry point that returns both parsed rules and warnings
- **`RuleData`**: Data class representing a normalized Wazuh rule
- **`DetectionCues`**: Data class for detection-related information
- **`FilterCondition`**: Data class for individual filter conditions
- **`summarize_filter_logic()`**: Helper for human-readable condition summaries
- **`rule_to_dict()`**: Conversion function for JSON-compatible output

## Quick Start

```python
from wazuh_parser import parse_wazuh_xml

# Read XML content from uploaded file
xml_content = uploaded_file.read().decode('utf-8')

# Parse the XML
rules, warnings = parse_wazuh_xml(xml_content)

# Display warnings if any
for warning in warnings:
    st.warning(warning)

# Process parsed rules
for rule in rules:
    st.write(f"Rule {rule.rule_id}: {rule.description}")
    st.write(f"Level: {rule.level}")
```

## Data Structure

### RuleData

The primary output structure containing all rule information:

```python
@dataclass
class RuleData:
    rule_id: int                           # Unique rule identifier
    level: int                             # Alert level (0-15)
    description: str                       # Rule description
    detection_cues: DetectionCues          # Detection information
    filter_conditions: List[FilterCondition]  # Filter conditions
    mitre_techniques: List[str]            # MITRE ATT&CK techniques
    cis_controls: List[str]                # CIS Controls references
    nist_controls: List[str]               # NIST Controls references
    groups: List[str]                      # Rule groups/categories
```

### DetectionCues

Captures detection-related metadata:

```python
@dataclass
class DetectionCues:
    decoded_as: Optional[str]              # Decoder used (e.g., 'nginx')
    if_sid: Optional[int]                  # Parent rule ID
    description: Optional[str]             # Detection description
```

### FilterCondition

Represents a single filter condition:

```python
@dataclass
class FilterCondition:
    match: Optional[str]                   # Regex pattern to match
    field: Optional[str]                   # Field to check
    frequency: Optional[int]               # Event frequency threshold
    timeframe: Optional[int]               # Time window in seconds
    same_field: Optional[str]              # Group by field
    no_alert: Optional[bool]               # Suppress alerts
    ignore: Optional[str]                  # Field to ignore
```

## Usage Examples

### Example 1: Basic Rule Display

```python
import streamlit as st
from wazuh_parser import parse_wazuh_xml

st.title("Wazuh Rule Parser")

uploaded_file = st.file_uploader("Upload Wazuh XML", type="xml")

if uploaded_file:
    xml_content = uploaded_file.read().decode('utf-8')
    rules, warnings = parse_wazuh_xml(xml_content)
    
    st.write(f"Parsed {len(rules)} rules")
    
    for rule in rules:
        with st.expander(f"Rule {rule.rule_id}: {rule.description}"):
            st.write(f"**Level:** {rule.level}")
            st.write(f"**Groups:** {', '.join(rule.groups)}")
            st.write(f"**Conditions:** {len(rule.filter_conditions)}")
```

### Example 2: Using Filter Summaries

```python
from wazuh_parser import parse_wazuh_xml, summarize_filter_logic

xml_content = uploaded_file.read().decode('utf-8')
rules, warnings = parse_wazuh_xml(xml_content)

for rule in rules:
    if rule.filter_conditions:
        summary = summarize_filter_logic(rule.filter_conditions)
        st.write(f"Rule {rule.rule_id} Filter Logic: {summary}")
```

### Example 3: Converting to Dictionary/JSON

```python
from wazuh_parser import parse_wazuh_xml, rule_to_dict
import json

xml_content = uploaded_file.read().decode('utf-8')
rules, warnings = parse_wazuh_xml(xml_content)

# Convert all rules to dictionaries for JSON export
rule_dicts = [rule_to_dict(rule) for rule in rules]
json_output = json.dumps(rule_dicts, indent=2)

st.download_button(
    label="Download as JSON",
    data=json_output,
    file_name="parsed_rules.json",
    mime="application/json"
)
```

### Example 4: Error Handling and Validation

```python
import streamlit as st
from wazuh_parser import parse_wazuh_xml

uploaded_file = st.file_uploader("Upload Wazuh XML", type="xml")

if uploaded_file:
    try:
        xml_content = uploaded_file.read().decode('utf-8')
        rules, warnings = parse_wazuh_xml(xml_content)
        
        if warnings:
            for warning in warnings:
                st.warning(f"⚠️ {warning}")
        
        if rules:
            st.success(f"✅ Successfully parsed {len(rules)} rules")
        else:
            st.error("❌ No valid rules found in the XML file")
            
    except Exception as e:
        st.error(f"Error processing file: {str(e)}")
```

### Example 5: Filtering and Searching Rules

```python
from wazuh_parser import parse_wazuh_xml

xml_content = uploaded_file.read().decode('utf-8')
rules, warnings = parse_wazuh_xml(xml_content)

# Filter rules by level
min_level = st.slider("Minimum alert level", 0, 15, 3)
filtered_rules = [r for r in rules if r.level >= min_level]

# Filter rules by group
selected_group = st.selectbox(
    "Filter by group",
    options=sorted(set(g for r in rules for g in r.groups))
)
filtered_rules = [r for r in filtered_rules if selected_group in r.groups]

# Display filtered results
st.write(f"Found {len(filtered_rules)} matching rules")
for rule in filtered_rules:
    st.write(f"Rule {rule.rule_id}: {rule.description} (Level {rule.level})")
```

## Error Handling

The parser provides graceful error handling:

- **Malformed XML**: Returns empty rule list with descriptive error message
- **Missing attributes**: Skips invalid rules and continues processing
- **Invalid data types**: Attempts conversion, logs warning if unsuccessful
- **Partial failures**: Returns successfully parsed rules plus warning messages

Example:
```python
rules, warnings = parse_wazuh_xml(xml_content)

# Always check warnings, even if rules were parsed
for warning in warnings:
    print(f"Warning: {warning}")

# Handle empty results
if not rules:
    if warnings:
        print("Parsing failed:")
        for w in warnings:
            print(f"  - {w}")
    else:
        print("No rules found in document")
```

## Supported Rule Elements

The parser currently extracts:

- **Rule Attributes**: `id`, `level`
- **Detection Elements**: `description`, `decoder/program_name`, `if_sid`
- **Filter Elements**: `match`, `field`, `frequency`, `timeframe`, `same_field`, `no_alert`, `ignore`
- **Reference Elements**: `reference` elements with `type`, `technique`, `control`
- **Metadata Elements**: `group`

## Performance Notes

- XML parsing uses the standard library's `xml.etree.ElementTree` (efficient)
- Memory usage scales linearly with file size
- No external dependencies required beyond standard library
- Suitable for rules files up to several MB in size

## Testing

Run the included unit tests:

```bash
python -m unittest test_wazuh_parser -v
```

Tests cover:
- Valid XML parsing
- Error handling for malformed XML
- Detection cue extraction
- Filter condition parsing
- Reference extraction
- Filter summary generation
- Data conversion

## Extending the Parser

To add support for additional rule elements:

1. Update the `RuleData` dataclass to include new fields
2. Add parsing logic in `_parse_rule_element()` 
3. Extract the element using `rule_elem.find()` or `rule_elem.findall()`
4. Add corresponding unit tests

Example:
```python
# In _parse_rule_element()
cve_refs = _extract_references(rule_elem, "cve", "id")
```

## Integration with Streamlit

For a complete Streamlit integration example, see `streamlit_app.py` for usage patterns with:
- File upload handling
- Error display
- Rule visualization
- Data export
