#!/usr/bin/env python3

import os
import sys
import argparse
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def validate_yara_rule(rule_content):
    """Basic validation of YARA rule syntax"""
    # Check for required sections
    if 'rule ' not in rule_content:
        return False, "Missing 'rule' keyword"
    if 'strings:' not in rule_content and 'condition:' not in rule_content:
        return False, "Missing 'strings' or 'condition' sections"
    return True, "Rule appears valid"

def add_yara_rule(rule_name, rule_content, description, severity):
    """Add a new YARA rule to the malware_rules.yar file"""
    try:
        # Get the project root directory
        project_root = Path(__file__).parent.parent
        rules_file = project_root / 'static' / 'yara_rules' / 'malware_rules.yar'
        
        # Ensure the directory exists
        rules_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Validate rule content
        is_valid, message = validate_yara_rule(rule_content)
        if not is_valid:
            logger.error(f"Invalid YARA rule: {message}")
            return False
        
        # Format the rule with metadata
        formatted_rule = f"""rule {rule_name} {{
    meta:
        description = \"{description}\"
        severity = \"{severity}\"
{rule_content.strip()}
}}
"""
        
        # Append to the rules file
        with open(rules_file, 'a') as f:
            f.write("\n" + formatted_rule)
        
        logger.info(f"YARA rule '{rule_name}' added successfully to {rules_file}")
        return True
        
    except Exception as e:
        logger.error(f"Error adding YARA rule: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Add a new YARA rule to the malware analysis platform')
    parser.add_argument('--name', required=True, help='Name of the YARA rule')
    parser.add_argument('--file', help='Path to a file containing the YARA rule content')
    parser.add_argument('--description', default='Custom YARA rule', help='Description of the rule')
    parser.add_argument('--severity', default='medium', choices=['low', 'medium', 'high'], help='Severity level')
    
    args = parser.parse_args()
    
    # Get rule content from file or stdin
    if args.file:
        try:
            with open(args.file, 'r') as f:
                rule_content = f.read()
        except Exception as e:
            logger.error(f"Error reading rule file: {str(e)}")
            sys.exit(1)
    else:
        logger.info("Enter YARA rule content (Ctrl+D to finish):")
        rule_content = sys.stdin.read()
    
    # Add the rule
    success = add_yara_rule(args.name, rule_content, args.description, args.severity)
    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()