#!/usr/bin/env python3
"""
Debug script to check filter conditions and fix the toggle logic.
"""

from wazuh_parser import parse_wazuh_xml

def debug_filter_conditions():
    """Debug filter conditions for sample rules."""
    
    with open("sample_wazuh_rules.xml", "r", encoding="utf-8") as f:
        sample_xml = f.read()

    rules, warnings = parse_wazuh_xml(sample_xml)
    
    print("🔍 Debugging Filter Conditions")
    print("=" * 40)
    
    for rule in rules[:5]:
        print(f"\nRule {rule.rule_id}: {rule.description}")
        
        if rule.filter_conditions:
            print(f"  📋 Filter conditions: {len(rule.filter_conditions)}")
            for i, cond in enumerate(rule.filter_conditions):
                print(f"    Condition {i+1}:")
                print(f"      Type: {type(cond)}")
                print(f"      Attributes: {dir(cond)}")
                
                # Check each possible attribute
                if hasattr(cond, 'field') and cond.field:
                    print(f"      Field: {cond.field}")
                if hasattr(cond, 'match') and cond.match:
                    print(f"      Match: {cond.match}")
                if hasattr(cond, 'frequency') and cond.frequency:
                    print(f"      Frequency: {cond.frequency}")
                if hasattr(cond, 'decoded_as') and cond.decoded_as:
                    print(f"      Decoded as: {cond.decoded_as}")
                    
                # Check all attributes that aren't private
                for attr in dir(cond):
                    if not attr.startswith('_') and attr not in ['field', 'match', 'frequency', 'decoded_as']:
                        value = getattr(cond, attr)
                        if value is not None and value != '':
                            print(f"      {attr}: {value}")
        else:
            print("  ❌ No filter conditions")

if __name__ == "__main__":
    debug_filter_conditions()