"""
Wazuh Rules Loader Module

This module provides functionality to load and validate Wazuh rules from JSON files.
Rules contain information about security events including ID, description, type, and level.
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

# Configure logging
logger = logging.getLogger(__name__)


class WazuhRule:
    """
    Represents a single Wazuh rule with validation.
    
    Attributes:
        id (int): Unique identifier for the rule
        description (str): Human-readable description of the rule
        type (str): Type/category of the rule (e.g., 'authentication', 'firewall', 'web')
        level (int): Severity level of the rule (typically 0-15)
    """
    
    def __init__(self, id: int, description: str, type: str, level: int):
        """
        Initialize a Wazuh rule with validation.
        
        Args:
            id (int): Rule ID
            description (str): Rule description
            type (str): Rule type
            level (int): Rule severity level
            
        Raises:
            ValueError: If any parameter is invalid
        """
        self.id = self._validate_id(id)
        self.description = self._validate_description(description)
        self.type = self._validate_type(type)
        self.level = self._validate_level(level)
    
    @staticmethod
    def _validate_id(rule_id: Any) -> int:
        """Validate rule ID."""
        if not isinstance(rule_id, int) or rule_id <= 0:
            raise ValueError(f"Rule ID must be a positive integer, got: {rule_id}")
        return rule_id
    
    @staticmethod
    def _validate_description(description: Any) -> str:
        """Validate rule description."""
        if not isinstance(description, str) or not description.strip():
            raise ValueError(f"Rule description must be a non-empty string, got: {description}")
        return description.strip()
    
    @staticmethod
    def _validate_type(rule_type: Any) -> str:
        """Validate rule type."""
        if not isinstance(rule_type, str) or not rule_type.strip():
            raise ValueError(f"Rule type must be a non-empty string, got: {rule_type}")
        return rule_type.strip().lower()
    
    @staticmethod
    def _validate_level(level: Any) -> int:
        """Validate rule level."""
        if not isinstance(level, int) or not (0 <= level <= 15):
            raise ValueError(f"Rule level must be an integer between 0 and 15, got: {level}")
        return level
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary."""
        return {
            'id': self.id,
            'description': self.description,
            'type': self.type,
            'level': self.level
        }
    
    def __repr__(self) -> str:
        return f"WazuhRule(id={self.id}, type='{self.type}', level={self.level})"


class RulesLoader:
    """
    Handles loading and management of Wazuh rules from JSON files.
    """
    
    def __init__(self, rules_file: Optional[str] = None):
        """
        Initialize the rules loader.
        
        Args:
            rules_file (str, optional): Path to rules JSON file. Defaults to 'rules.json'
        """
        self.rules_file = Path(rules_file or 'rules.json')
        self.rules: List[WazuhRule] = []
        self._rules_dict: Dict[int, WazuhRule] = {}
    
    def load_rules(self, reload: bool = False) -> List[WazuhRule]:
        """
        Load Wazuh rules from JSON file.
        
        Args:
            reload (bool): Whether to reload rules even if already loaded
            
        Returns:
            List[WazuhRule]: List of loaded rules
            
        Raises:
            FileNotFoundError: If rules file doesn't exist
            json.JSONDecodeError: If JSON is invalid
            ValueError: If rule data is invalid
        """
        if self.rules and not reload:
            logger.info(f"Rules already loaded ({len(self.rules)} rules)")
            return self.rules
        
        if not self.rules_file.exists():
            raise FileNotFoundError(f"Rules file not found: {self.rules_file}")
        
        try:
            logger.info(f"Loading rules from: {self.rules_file}")
            
            with open(self.rules_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if not isinstance(data, dict) or 'rules' not in data:
                raise ValueError("JSON must contain a 'rules' key with a list of rules")
            
            rules_data = data['rules']
            if not isinstance(rules_data, list):
                raise ValueError("'rules' must be a list")
            
            self.rules = []
            self._rules_dict = {}
            
            for i, rule_data in enumerate(rules_data):
                try:
                    rule = self._parse_rule(rule_data)
                    
                    # Check for duplicate IDs
                    if rule.id in self._rules_dict:
                        logger.warning(f"Duplicate rule ID {rule.id} found, skipping")
                        continue
                    
                    self.rules.append(rule)
                    self._rules_dict[rule.id] = rule
                    
                except ValueError as e:
                    logger.error(f"Error parsing rule at index {i}: {e}")
                    raise ValueError(f"Invalid rule at index {i}: {e}")
            
            logger.info(f"Successfully loaded {len(self.rules)} rules")
            return self.rules
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in rules file: {e}")
            raise
        except Exception as e:
            logger.error(f"Error loading rules: {e}")
            raise
    
    def _parse_rule(self, rule_data: Dict[str, Any]) -> WazuhRule:
        """
        Parse a single rule from JSON data.
        
        Args:
            rule_data (dict): Raw rule data from JSON
            
        Returns:
            WazuhRule: Parsed and validated rule
            
        Raises:
            ValueError: If rule data is invalid
        """
        required_fields = ['id', 'description', 'type', 'level']
        
        for field in required_fields:
            if field not in rule_data:
                raise ValueError(f"Missing required field: {field}")
        
        return WazuhRule(
            id=rule_data['id'],
            description=rule_data['description'],
            type=rule_data['type'],
            level=rule_data['level']
        )
    
    def get_rule_by_id(self, rule_id: int) -> Optional[WazuhRule]:
        """
        Get a rule by its ID.
        
        Args:
            rule_id (int): Rule ID to search for
            
        Returns:
            WazuhRule or None: Found rule or None if not found
        """
        return self._rules_dict.get(rule_id)
    
    def get_rules_by_type(self, rule_type: str) -> List[WazuhRule]:
        """
        Get all rules of a specific type.
        
        Args:
            rule_type (str): Type to filter by
            
        Returns:
            List[WazuhRule]: Rules matching the type
        """
        return [rule for rule in self.rules if rule.type == rule_type.lower()]
    
    def get_rules_by_level(self, min_level: int = 0, max_level: int = 15) -> List[WazuhRule]:
        """
        Get rules within a specific level range.
        
        Args:
            min_level (int): Minimum level (inclusive)
            max_level (int): Maximum level (inclusive)
            
        Returns:
            List[WazuhRule]: Rules within the level range
        """
        return [rule for rule in self.rules 
                if min_level <= rule.level <= max_level]
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics about loaded rules.
        
        Returns:
            Dict[str, Any]: Statistics including count, types, and level distribution
        """
        if not self.rules:
            return {'total': 0, 'types': {}, 'levels': {}}
        
        types = {}
        levels = {}
        
        for rule in self.rules:
            types[rule.type] = types.get(rule.type, 0) + 1
            levels[rule.level] = levels.get(rule.level, 0) + 1
        
        return {
            'total': len(self.rules),
            'types': types,
            'levels': levels,
            'average_level': sum(rule.level for rule in self.rules) / len(self.rules)
        }


def load_wazuh_rules(rules_file: str = 'rules.json') -> List[WazuhRule]:
    """
    Convenience function to load Wazuh rules.
    
    Args:
        rules_file (str): Path to rules JSON file
        
    Returns:
        List[WazuhRule]: Loaded rules
    """
    loader = RulesLoader(rules_file)
    return loader.load_rules()


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    try:
        loader = RulesLoader()
        rules = loader.load_rules()
        
        print(f"\nLoaded {len(rules)} rules")
        print("\nRule Statistics:")
        stats = loader.get_stats()
        for key, value in stats.items():
            print(f"  {key}: {value}")
        
        print("\nSample rules:")
        for rule in rules[:3]:
            print(f"  {rule}")
            
    except Exception as e:
        print(f"Error: {e}")
