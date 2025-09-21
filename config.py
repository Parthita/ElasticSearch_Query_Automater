"""
Configuration Management Module

This module provides comprehensive configuration management for the Wazuh NLP system.
It loads YAML configuration files, validates settings, handles environment variable
overrides, and provides a clean API for accessing configuration values.
"""

import os
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass
import yaml

logger = logging.getLogger(__name__)


class ConfigurationError(Exception):
    """Raised when there's an error in configuration loading or validation."""
    pass


class ConfigurationValidationError(ConfigurationError):
    """Raised when configuration validation fails."""
    pass


@dataclass
class SeverityMapping:
    """Represents a severity level mapping."""
    name: str
    min: int
    max: int
    description: str
    
    def contains_level(self, level: int) -> bool:
        """Check if a level falls within this severity range."""
        return self.min <= level <= self.max


@dataclass
class TimePeriod:
    """Represents a time period configuration."""
    name: str
    duration: str
    description: str
    start_offset: Optional[str] = None
    
    def to_seconds(self) -> int:
        """Convert duration to seconds."""
        return self._parse_duration(self.duration)
    
    @staticmethod
    def _parse_duration(duration: str) -> int:
        """Parse duration string (e.g., '1h', '7d') to seconds."""
        duration = duration.lower().strip()
        
        # Extract number and unit
        match = re.match(r'^(\d+)([smhdw])$', duration)
        if not match:
            raise ConfigurationValidationError(f"Invalid duration format: {duration}")
        
        value, unit = match.groups()
        value = int(value)
        
        multipliers = {
            's': 1,
            'm': 60,
            'h': 3600,
            'd': 86400,
            'w': 604800
        }
        
        if unit not in multipliers:
            raise ConfigurationValidationError(f"Invalid duration unit: {unit}")
        
        return value * multipliers[unit]


class ConfigManager:
    """
    Manages configuration loading, validation, and access for the Wazuh NLP system.
    
    This class provides a centralized way to:
    - Load configuration from YAML files
    - Apply environment variable overrides
    - Validate configuration values
    - Access configuration with type safety
    - Handle configuration errors gracefully
    """
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize the configuration manager.
        
        Args:
            config_file (str, optional): Path to configuration file. 
                                       If None, searches default locations.
        """
        self.config_file = config_file
        self.config: Dict[str, Any] = {}
        self.severity_mappings: Dict[str, SeverityMapping] = {}
        self.time_periods: Dict[str, TimePeriod] = {}
        self.loaded = False
        
        # Default configuration (fallback values)
        self._default_config = {
            'app': {
                'name': 'Wazuh NLP Query System',
                'version': '1.0.0',
                'debug': False,
                'log_level': 'INFO',
                'max_query_length': 500,
                'query_history_limit': 50
            },
            'severity': {
                'default_min': 0,
                'default_max': 15
            },
            'query_processing': {
                'min_keyword_length': 3,
                'max_results': 100,
                'default_results': 50,
                'min_query_length': 3,
                'max_query_length': 500
            },
            'files': {
                'default_rules': 'rules.json'
            }
        }
    
    def load_config(self, reload: bool = False) -> None:
        """
        Load configuration from file.
        
        Args:
            reload (bool): Whether to reload even if already loaded
            
        Raises:
            ConfigurationError: If configuration cannot be loaded
        """
        if self.loaded and not reload:
            logger.debug("Configuration already loaded")
            return
        
        config_path = self._find_config_file()
        
        try:
            logger.info(f"Loading configuration from: {config_path}")
            
            with open(config_path, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f) or {}
            
            # Apply defaults for missing sections
            self._apply_defaults()
            
            # Apply environment variable overrides
            self._apply_env_overrides()
            
            # Validate configuration
            self._validate_config()
            
            # Parse structured configuration
            self._parse_severity_mappings()
            self._parse_time_periods()
            
            self.loaded = True
            logger.info("Configuration loaded and validated successfully")
            
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML in configuration file: {e}")
        except FileNotFoundError:
            logger.warning(f"Configuration file not found: {config_path}. Using defaults.")
            self.config = self._default_config.copy()
            self.loaded = True
        except Exception as e:
            raise ConfigurationError(f"Error loading configuration: {e}")
    
    def _find_config_file(self) -> Path:
        """
        Find the configuration file to use.
        
        Returns:
            Path: Path to the configuration file
            
        Raises:
            ConfigurationError: If no configuration file is found
        """
        if self.config_file:
            path = Path(self.config_file)
            if path.exists():
                return path
            else:
                raise ConfigurationError(f"Specified config file not found: {self.config_file}")
        
        # Search default locations
        search_paths = [
            Path("config.yaml"),
            Path("~/.wazuh-nlp/config.yaml").expanduser(),
            Path("/etc/wazuh-nlp/config.yaml")
        ]
        
        for path in search_paths:
            if path.exists():
                return path
        
        # If no config file found, create a default one in current directory
        default_path = Path("config.yaml")
        logger.warning(f"No configuration file found. Using default: {default_path}")
        return default_path
    
    def _apply_defaults(self) -> None:
        """Apply default values for missing configuration sections."""
        def merge_dict(base: dict, defaults: dict) -> dict:
            """Recursively merge defaults into base configuration."""
            for key, value in defaults.items():
                if key not in base:
                    base[key] = value
                elif isinstance(value, dict) and isinstance(base[key], dict):
                    merge_dict(base[key], value)
            return base
        
        self.config = merge_dict(self.config, self._default_config)
    
    def _apply_env_overrides(self) -> None:
        """Apply environment variable overrides to configuration."""
        env_overrides = self.config.get('env_overrides', {})
        
        for config_path, env_var in env_overrides.items():
            env_value = os.environ.get(env_var)
            if env_value is not None:
                self._set_nested_value(self.config, config_path, env_value)
                logger.debug(f"Applied env override: {config_path} = {env_value} (from {env_var})")
    
    def _set_nested_value(self, config: dict, path: str, value: str) -> None:
        """Set a nested configuration value using dot notation."""
        keys = path.split('.')
        current = config
        
        # Navigate to the parent of the target key
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        # Set the final value with type conversion
        final_key = keys[-1]
        current[final_key] = self._convert_env_value(value)
    
    def _convert_env_value(self, value: str) -> Union[str, int, float, bool, List[str]]:
        """Convert environment variable string to appropriate type."""
        # Boolean conversion
        if value.lower() in ('true', 'yes', '1', 'on'):
            return True
        elif value.lower() in ('false', 'no', '0', 'off'):
            return False
        
        # Numeric conversion
        try:
            if '.' in value:
                return float(value)
            else:
                return int(value)
        except ValueError:
            pass
        
        # List conversion (comma-separated)
        if ',' in value:
            return [item.strip() for item in value.split(',')]
        
        # String value
        return value
    
    def _validate_config(self) -> None:
        """
        Validate the loaded configuration.
        
        Raises:
            ConfigurationValidationError: If validation fails
        """
        errors = []
        
        # Validate app settings
        app_config = self.config.get('app', {})
        if not isinstance(app_config.get('name'), str):
            errors.append("app.name must be a string")
        
        log_level = app_config.get('log_level', 'INFO')
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if log_level not in valid_levels:
            errors.append(f"app.log_level must be one of: {valid_levels}")
        
        # Validate severity mappings
        severity_config = self.config.get('severity', {})
        mappings = severity_config.get('mappings', {})
        
        for name, mapping in mappings.items():
            if not isinstance(mapping, dict):
                errors.append(f"severity.mappings.{name} must be a dict")
                continue
            
            min_level = mapping.get('min')
            max_level = mapping.get('max')
            
            if not isinstance(min_level, int) or not (0 <= min_level <= 15):
                errors.append(f"severity.mappings.{name}.min must be an integer 0-15")
            
            if not isinstance(max_level, int) or not (0 <= max_level <= 15):
                errors.append(f"severity.mappings.{name}.max must be an integer 0-15")
            
            if isinstance(min_level, int) and isinstance(max_level, int) and min_level > max_level:
                errors.append(f"severity.mappings.{name}.min cannot be greater than max")
        
        # Validate time periods
        time_periods = self.config.get('time_periods', {})
        for name, period in time_periods.items():
            if isinstance(period, dict) and 'duration' in period:
                try:
                    TimePeriod._parse_duration(period['duration'])
                except ConfigurationValidationError as e:
                    errors.append(f"time_periods.{name}.duration: {e}")
        
        # Validate query processing settings
        query_config = self.config.get('query_processing', {})
        min_length = query_config.get('min_query_length', 3)
        max_length = query_config.get('max_query_length', 500)
        
        if not isinstance(min_length, int) or min_length < 1:
            errors.append("query_processing.min_query_length must be a positive integer")
        
        if not isinstance(max_length, int) or max_length < min_length:
            errors.append("query_processing.max_query_length must be >= min_query_length")
        
        if errors:
            error_msg = "Configuration validation failed:\n" + "\n".join(f"  • {error}" for error in errors)
            raise ConfigurationValidationError(error_msg)
    
    def _parse_severity_mappings(self) -> None:
        """Parse severity mappings into structured objects."""
        severity_config = self.config.get('severity', {})
        mappings = severity_config.get('mappings', {})
        
        self.severity_mappings = {}
        for name, mapping in mappings.items():
            if isinstance(mapping, dict):
                self.severity_mappings[name] = SeverityMapping(
                    name=name,
                    min=mapping.get('min', 0),
                    max=mapping.get('max', 15),
                    description=mapping.get('description', '')
                )
    
    def _parse_time_periods(self) -> None:
        """Parse time periods into structured objects."""
        time_periods = self.config.get('time_periods', {})
        
        self.time_periods = {}
        for name, period in time_periods.items():
            if isinstance(period, dict):
                self.time_periods[name] = TimePeriod(
                    name=name,
                    duration=period.get('duration', '1h'),
                    description=period.get('description', ''),
                    start_offset=period.get('start_offset')
                )
    
    def get(self, path: str, default: Any = None) -> Any:
        """
        Get a configuration value using dot notation.
        
        Args:
            path (str): Dot-separated path to configuration value
            default: Default value if path not found
            
        Returns:
            Configuration value or default
        """
        if not self.loaded:
            self.load_config()
        
        keys = path.split('.')
        current = self.config
        
        try:
            for key in keys:
                current = current[key]
            return current
        except (KeyError, TypeError):
            return default
    
    def get_severity_mapping(self, name: str) -> Optional[SeverityMapping]:
        """
        Get a severity mapping by name.
        
        Args:
            name (str): Name of the severity mapping
            
        Returns:
            SeverityMapping or None if not found
        """
        if not self.loaded:
            self.load_config()
        
        return self.severity_mappings.get(name)
    
    def get_severity_for_level(self, level: int) -> Optional[SeverityMapping]:
        """
        Get the severity mapping that contains the given level.
        
        Args:
            level (int): Severity level
            
        Returns:
            SeverityMapping or None if no mapping contains the level
        """
        if not self.loaded:
            self.load_config()
        
        for mapping in self.severity_mappings.values():
            if mapping.contains_level(level):
                return mapping
        return None
    
    def get_time_period(self, name: str) -> Optional[TimePeriod]:
        """
        Get a time period by name.
        
        Args:
            name (str): Name of the time period
            
        Returns:
            TimePeriod or None if not found
        """
        if not self.loaded:
            self.load_config()
        
        return self.time_periods.get(name)
    
    def get_rule_type_keywords(self, rule_type: str) -> List[str]:
        """
        Get keywords for a rule type.
        
        Args:
            rule_type (str): Rule type name
            
        Returns:
            List of keywords for the rule type
        """
        rule_types = self.get('rule_types', {})
        type_config = rule_types.get(rule_type, {})
        return type_config.get('keywords', [])
    
    def get_rule_type_aliases(self, rule_type: str) -> List[str]:
        """
        Get aliases for a rule type.
        
        Args:
            rule_type (str): Rule type name
            
        Returns:
            List of aliases for the rule type
        """
        rule_types = self.get('rule_types', {})
        type_config = rule_types.get(rule_type, {})
        return type_config.get('aliases', [])
    
    def get_field_mapping(self, internal_field: str) -> Optional[str]:
        """
        Get Elasticsearch field mapping for an internal field.
        
        Args:
            internal_field (str): Internal field name
            
        Returns:
            Elasticsearch field name or None if no mapping exists
        """
        mappings = self.get('field_mappings', {})
        return mappings.get(internal_field)
    
    def get_search_fields(self, query_type: str) -> List[str]:
        """
        Get search fields for a query type.
        
        Args:
            query_type (str): Type of query (description, content, metadata)
            
        Returns:
            List of field names to search
        """
        search_fields = self.get('field_mappings.search_fields', {})
        return search_fields.get(query_type, [])
    
    def is_feature_enabled(self, feature: str) -> bool:
        """
        Check if a feature is enabled.
        
        Args:
            feature (str): Feature name
            
        Returns:
            bool: True if feature is enabled
        """
        return self.get(f'features.{feature}', False)
    
    def get_stop_words(self) -> List[str]:
        """
        Get list of stop words for query processing.
        
        Returns:
            List of stop words
        """
        return self.get('query_processing.stop_words', [])
    
    def get_severity_keywords(self) -> Dict[str, int]:
        """
        Get severity keywords mapping.
        
        Returns:
            Dict mapping severity keywords to minimum levels
        """
        return self.get('severity.keywords', {})
    
    def validate_query_length(self, query: str) -> tuple:
        """
        Validate query length against configuration limits.
        
        Args:
            query (str): Query string to validate
            
        Returns:
            tuple: (is_valid, error_message)
        """
        min_length = self.get('query_processing.min_query_length', 3)
        max_length = self.get('query_processing.max_query_length', 500)
        
        query_length = len(query.strip())
        
        if query_length < min_length:
            return False, f"Query too short (minimum {min_length} characters)"
        
        if query_length > max_length:
            return False, f"Query too long (maximum {max_length} characters)"
        
        return True, ""
    
    def get_config_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the current configuration.
        
        Returns:
            Dict with configuration summary
        """
        if not self.loaded:
            self.load_config()
        
        return {
            'app_name': self.get('app.name'),
            'version': self.get('app.version'),
            'debug_mode': self.get('app.debug'),
            'log_level': self.get('app.log_level'),
            'rules_file': self.get('files.default_rules'),
            'severity_mappings': len(self.severity_mappings),
            'time_periods': len(self.time_periods),
            'rule_types': len(self.get('rule_types', {})),
            'features_enabled': sum(1 for f in self.get('features', {}).values() if f),
            'elasticsearch_enabled': self.get('elasticsearch.enabled', False)
        }


# Global configuration instance
config = ConfigManager()


def get_config() -> ConfigManager:
    """
    Get the global configuration manager instance.
    
    Returns:
        ConfigManager: The global configuration instance
    """
    if not config.loaded:
        config.load_config()
    return config


def load_config(config_file: Optional[str] = None) -> ConfigManager:
    """
    Load configuration from file.
    
    Args:
        config_file (str, optional): Path to configuration file
        
    Returns:
        ConfigManager: Loaded configuration manager
    """
    global config
    if config_file:
        config = ConfigManager(config_file)
    config.load_config()
    return config


if __name__ == "__main__":
    # Configuration module demo/test
    import sys
    
    logging.basicConfig(level=logging.INFO)
    
    try:
        # Load and validate configuration
        cfg = load_config()
        
        print("Configuration loaded successfully!")
        print("\nConfiguration Summary:")
        summary = cfg.get_config_summary()
        for key, value in summary.items():
            print(f"  {key}: {value}")
        
        print("\nSeverity Mappings:")
        for name, mapping in cfg.severity_mappings.items():
            print(f"  {name}: {mapping.min}-{mapping.max} ({mapping.description})")
        
        print("\nTime Periods:")
        for name, period in cfg.time_periods.items():
            print(f"  {name}: {period.duration} ({period.description})")
        
        print("\nSample configuration access:")
        print(f"  App name: {cfg.get('app.name')}")
        print(f"  Debug mode: {cfg.get('app.debug')}")
        print(f"  Max query length: {cfg.get('app.max_query_length')}")
        
        # Test query validation
        test_queries = ["hi", "show me authentication failures", "a" * 600]
        print("\nQuery validation tests:")
        for query in test_queries:
            valid, error = cfg.validate_query_length(query)
            status = "✓" if valid else "✗"
            print(f"  {status} '{query[:50]}{'...' if len(query) > 50 else ''}': {error if error else 'Valid'}")
        
    except ConfigurationError as e:
        print(f"Configuration error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)
