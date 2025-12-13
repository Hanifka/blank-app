# Connection Type Toggles Feature

## Overview

The connection type toggles feature allows users to independently control the visibility of different types of rule relationships in the flowchart visualization. This provides fine-grained control over which connections are displayed, making it easier to focus on specific relationship types.

## Features

### Four Independent Toggles

1. **Parent Rules (if_sid)** - Blue edges
   - Shows direct parent-child relationships where a rule references another rule's ID
   - Example: Rule 101 with `<if_sid>100</if_sid>` creates edge: 100 → 101

2. **Matched Rules (if_matched_sid)** - Yellow edges
   - Shows rules that depend on a previous rule having matched
   - Example: Rule 102 with `<if_matched_sid>100,101</if_matched_sid>` creates edges: 100 → 102, 101 → 102

3. **Group Correlations (if_matched_group)** - Green edges
   - Shows rules that depend on a previous match within a specific group
   - Example: Rule 103 with `<if_matched_group>authentication_failure</if_matched_group>` creates edges from all rules in that group to 103

4. **Group Rules (if_group)** - Orange edges
   - Shows rules that check for membership in a specific group
   - Example: Rule 104 with `<if_group>web_attack</if_group>` creates edges from all rules in that group to 104

### Default Behavior

All four toggles are **enabled by default**, showing all available connections. Users can selectively disable toggles to focus on specific relationship types.

### Edge Hover Information

When hovering over an edge, users see:
- Source and target rule IDs
- Connection type (Parent Rule, Matched Rule, Group Correlation, or Group Rule)

Example: `Rule 100 → Rule 101<br>Type: Parent Rule`

## Implementation Details

### UI Changes (streamlit_app.py)

#### New Function: `render_connection_type_toggles()`
```python
def render_connection_type_toggles() -> dict:
    """Render connection type toggles and return the selected options."""
    st.subheader("Connection Types")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        show_if_sid = st.checkbox("🔗 Parent Rules (if_sid)", value=True)
    # ... similar for other toggles
    
    return {
        "show_if_sid": show_if_sid,
        "show_if_matched_sid": show_if_matched_sid,
        "show_if_matched_group": show_if_matched_group,
        "show_if_group": show_if_group,
    }
```

#### Updated: `render_flowchart_visualization()`
Now accepts `connection_toggles` dictionary instead of single `connection_type` string:
```python
def render_flowchart_visualization(rules, connection_toggles, display_options):
    fig = create_rule_network_visualization(
        rules, 
        show_if_sid=connection_toggles["show_if_sid"],
        show_if_matched_sid=connection_toggles["show_if_matched_sid"],
        show_if_matched_group=connection_toggles["show_if_matched_group"],
        show_if_group=connection_toggles["show_if_group"],
        show_desc_on_node=display_options["show_desc_on_node"],
        show_cond_on_node=display_options["show_cond_on_node"]
    )
```

### Visualization Changes (visualizations/flowchart.py)

#### Updated Function Signature
```python
def create_rule_network_visualization(
    rules: List[RuleData],
    show_if_sid: bool = True,
    show_if_matched_sid: bool = True,
    show_if_matched_group: bool = True,
    show_if_group: bool = True,
    min_level: int = 0,
    selected_groups: Optional[List[str]] = None,
    show_desc_on_node: bool = False,
    show_cond_on_node: bool = False,
) -> go.Figure:
```

#### Edge Building Logic
Changed from if/elif to independent if blocks:
```python
for rule in filtered_rules:
    cues = getattr(rule, "detection_cues", None)
    
    if show_if_sid:
        # Add if_sid edges...
        G.add_edge(parent_id, rule.rule_id, color="blue", type="if_sid")
    
    if show_if_matched_sid:
        # Add if_matched_sid edges...
        G.add_edge(parent_id, rule.rule_id, color="yellow", type="if_matched_sid")
    
    # ... similar for other connection types
```

This allows multiple edge types to be displayed simultaneously, as each check is independent.

#### Enhanced Edge Hover Text
```python
type_labels = {
    "if_sid": "Parent Rule",
    "if_matched_sid": "Matched Rule",
    "if_matched_group": "Group Correlation",
    "if_group": "Group Rule"
}
type_label = type_labels.get(edge_type, edge_type)
hover_text = f"Rule {source} → Rule {target}<br>Type: {type_label}"
```

#### Empty State Handling
When no edges exist (all toggles off or no connections found):
```python
def _format_connection_empty_message(enabled_types: List[str]) -> str:
    if not enabled_types:
        return "No connection types enabled. Please enable at least one connection type."
    
    if len(enabled_types) == 1:
        # Show specific message for single type
        return type_messages.get(enabled_types[0], "No rule connections found")
    
    return f"No rules with {', '.join(enabled_types)} connections found"
```

## Usage Examples

### Example 1: View Only Parent-Child Relationships
Enable: ✅ Parent Rules (if_sid)  
Disable: ❌ Matched Rules, ❌ Group Correlations, ❌ Group Rules

Result: Clean view of direct rule hierarchies with blue edges only.

### Example 2: Focus on Group-Based Logic
Enable: ✅ Group Correlations (if_matched_group), ✅ Group Rules (if_group)  
Disable: ❌ Parent Rules, ❌ Matched Rules

Result: Shows only group-based relationships with green and orange edges.

### Example 3: View All Connections (Default)
Enable: ✅ All toggles

Result: Comprehensive view showing all rule relationships with color-coded edges.

### Example 4: Combined with Node Display Options
Connection Toggles: ✅ Parent Rules, ✅ Matched Rules  
Node Display: ✅ Description on Node, ✅ Conditions on Node

Result: Filtered edges with detailed node information.

## Testing

Comprehensive test suite included:
- `test_connection_toggles.py` - Tests all toggle combinations
- `test_toggles_with_sample.py` - Tests with real sample data
- `test_toggle_edge_cases.py` - Tests edge cases and complex scenarios

All tests verify:
- Each toggle independently controls its connection type
- Multiple toggles work correctly together
- Empty state handling when no connections exist
- Integration with existing node display options
- Edge hover text displays correct connection type

## Backward Compatibility

**Breaking Change**: The `connection_type` parameter has been replaced with four boolean parameters (`show_if_sid`, `show_if_matched_sid`, `show_if_matched_group`, `show_if_group`).

Old API:
```python
create_rule_network_visualization(rules, connection_type="if_sid")
```

New API:
```python
create_rule_network_visualization(
    rules, 
    show_if_sid=True,
    show_if_matched_sid=False,
    show_if_matched_group=False,
    show_if_group=False
)
```

To maintain similar behavior to the old API with defaults:
```python
create_rule_network_visualization(rules)  # All connections shown by default
```

## Benefits

1. **Focused Analysis**: Users can isolate specific relationship types for clearer visualization
2. **Reduced Clutter**: Complex rule sets with many connection types can be simplified
3. **Flexible Exploration**: Easy to toggle between different views without changing filters
4. **Better Understanding**: Color-coded edges and hover information help identify relationship types
5. **Cumulative Display**: Multiple connection types can be shown simultaneously for comprehensive analysis

## Future Enhancements

Potential improvements:
- Save toggle preferences per session
- Preset toggle configurations for common analysis scenarios
- Connection type legend in the visualization
- Export filtered views with specific toggle states
- Statistics showing edge counts per connection type
