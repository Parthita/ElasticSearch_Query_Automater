"""
Elasticsearch DSL Query Validator

This module provides comprehensive validation for Elasticsearch DSL queries used
with Wazuh data. It validates syntax, field mappings, date formats, and provides
optimization suggestions for better query performance.
"""

import re
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum

from config import get_config

logger = logging.getLogger(__name__)


class ValidationLevel(Enum):
    """Validation severity levels."""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    SUGGESTION = "suggestion"


@dataclass
class ValidationIssue:
    """Represents a validation issue with location and fix information."""
    level: ValidationLevel
    message: str
    path: str = ""
    field: str = ""
    suggestion: str = ""
    fix: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'level': self.level.value,
            'message': self.message,
            'path': self.path,
            'field': self.field,
            'suggestion': self.suggestion,
            'fix': self.fix
        }


@dataclass
class ValidationResult:
    """Contains validation results with issues and optimization suggestions."""
    is_valid: bool
    query: Dict[str, Any]
    issues: List[ValidationIssue] = field(default_factory=list)
    optimizations: List[str] = field(default_factory=list)
    field_mappings: Dict[str, str] = field(default_factory=dict)
    
    @property
    def errors(self) -> List[ValidationIssue]:
        """Get only error-level issues."""
        return [issue for issue in self.issues if issue.level == ValidationLevel.ERROR]
    
    @property
    def warnings(self) -> List[ValidationIssue]:
        """Get only warning-level issues."""
        return [issue for issue in self.issues if issue.level == ValidationLevel.WARNING]
    
    @property
    def suggestions(self) -> List[ValidationIssue]:
        """Get only suggestion-level issues."""
        return [issue for issue in self.issues if issue.level == ValidationLevel.SUGGESTION]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'is_valid': self.is_valid,
            'query': self.query,
            'issues': [issue.to_dict() for issue in self.issues],
            'optimizations': self.optimizations,
            'field_mappings': self.field_mappings,
            'summary': {
                'total_issues': len(self.issues),
                'errors': len(self.errors),
                'warnings': len(self.warnings),
                'suggestions': len(self.suggestions)
            }
        }


class ElasticsearchValidator:
    """
    Validates Elasticsearch DSL queries for Wazuh data.
    
    This validator checks:
    - Query syntax and structure
    - Field mappings against Wazuh schema
    - Date format validation
    - Query optimization opportunities
    - Common anti-patterns
    """
    
    def __init__(self, config_manager=None):
        """
        Initialize the Elasticsearch validator.
        
        Args:
            config_manager: Configuration manager instance
        """
        self.config = config_manager or get_config()
        self.logger = logging.getLogger(__name__)
        
        # Common Wazuh Elasticsearch field mappings
        self.wazuh_fields = {
            # Core fields
            '@timestamp': 'date',
            'timestamp': 'date',
            'rule.id': 'long',
            'rule.level': 'long',
            'rule.description': 'text',
            'rule.groups': 'keyword',
            'rule.mitre.id': 'keyword',
            'rule.mitre.tactic': 'keyword',
            'rule.mitre.technique': 'keyword',
            
            # Agent fields
            'agent.id': 'keyword',
            'agent.name': 'keyword',
            'agent.ip': 'ip',
            'agent.version': 'keyword',
            
            # Location fields
            'location': 'keyword',
            'input.type': 'keyword',
            'manager.name': 'keyword',
            
            # Decoder fields
            'decoder.name': 'keyword',
            'decoder.parent': 'keyword',
            'decoder.program_name': 'keyword',
            'decoder.srcuser': 'keyword',
            'decoder.dstuser': 'keyword',
            'decoder.srcip': 'ip',
            'decoder.dstip': 'ip',
            'decoder.srcport': 'long',
            'decoder.dstport': 'long',
            'decoder.protocol': 'keyword',
            'decoder.action': 'keyword',
            'decoder.id': 'keyword',
            'decoder.status': 'keyword',
            'decoder.extra_data': 'text',
            
            # Full log
            'full_log': 'text',
            'predecoder.program_name': 'keyword',
            'predecoder.timestamp': 'keyword',
            'predecoder.hostname': 'keyword',
            
            # GeoIP fields (if enabled)
            'srcgeoip.country_name': 'keyword',
            'srcgeoip.city_name': 'keyword',
            'srcgeoip.location': 'geo_point',
            'dstgeoip.country_name': 'keyword',
            'dstgeoip.city_name': 'keyword',
            'dstgeoip.location': 'geo_point',
            
            # Common custom fields
            'data.srcip': 'ip',
            'data.dstip': 'ip',
            'data.srcport': 'long',
            'data.dstport': 'long',
            'data.protocol': 'keyword',
            'data.id': 'keyword',
            'data.status': 'keyword',
            'data.url': 'keyword',
            'data.hostname': 'keyword',
            'data.program_name': 'keyword',
            'data.win.eventdata.image': 'keyword',
            'data.win.eventdata.commandLine': 'text',
            'data.win.eventdata.user': 'keyword',
            'data.win.system.eventID': 'keyword',
            'data.win.system.computer': 'keyword',
        }
        
        # Load additional field mappings from config
        config_mappings = self.config.get('field_mappings', {})
        for internal_field, es_field in config_mappings.items():
            if isinstance(es_field, str) and internal_field not in ['search_fields']:
                # Infer field type based on name patterns
                field_type = self._infer_field_type(es_field)
                self.wazuh_fields[es_field] = field_type
        
        # Valid query types
        self.valid_query_types = {
            'bool', 'match', 'match_all', 'match_phrase', 'match_phrase_prefix',
            'multi_match', 'term', 'terms', 'range', 'exists', 'prefix', 'wildcard',
            'regexp', 'fuzzy', 'ids', 'constant_score', 'dis_max', 'function_score',
            'boosting', 'nested', 'has_child', 'has_parent', 'geo_distance',
            'geo_bounding_box', 'geo_polygon', 'geo_shape', 'more_like_this',
            'script', 'simple_query_string', 'query_string'
        }
        
        # Date format patterns
        self.date_patterns = [
            r'^\d{4}-\d{2}-\d{2}$',  # YYYY-MM-DD
            r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$',  # YYYY-MM-DDTHH:MM:SS
            r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$',  # ISO format with Z
            r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$',  # ISO with timezone
            r'^now([+-]\d+[smhdwMy])?$',  # Elasticsearch date math: now, now+1d, now-5m
            r'^\d{13}$',  # Unix timestamp (milliseconds)
            r'^\d{10}$',  # Unix timestamp (seconds)
        ]
    
    def _infer_field_type(self, field_name: str) -> str:
        """Infer field type based on field name patterns."""
        field_lower = field_name.lower()
        
        if any(pattern in field_lower for pattern in ['timestamp', 'time', 'date']):
            return 'date'
        elif any(pattern in field_lower for pattern in ['ip', 'address']):
            return 'ip'
        elif any(pattern in field_lower for pattern in ['port', 'id', 'level', 'count', 'size']):
            if not any(pattern in field_lower for pattern in ['rule.id', 'event.id']):
                return 'long'
        elif any(pattern in field_lower for pattern in ['location', 'coordinate']):
            return 'geo_point'
        elif field_name.endswith('.keyword') or any(pattern in field_lower for pattern in ['status', 'action', 'protocol']):
            return 'keyword'
        
        return 'text'  # Default to text
    
    def validate_query(self, query: Union[str, Dict[str, Any]], dry_run: bool = False) -> ValidationResult:
        """
        Validate an Elasticsearch DSL query.
        
        Args:
            query: Query as JSON string or dictionary
            dry_run: If True, only validate without making actual connections
            
        Returns:
            ValidationResult: Comprehensive validation results
        """
        # Parse query if it's a string
        if isinstance(query, str):
            try:
                parsed_query = json.loads(query)
            except json.JSONDecodeError as e:
                return ValidationResult(
                    is_valid=False,
                    query={},
                    issues=[ValidationIssue(
                        level=ValidationLevel.ERROR,
                        message=f"Invalid JSON syntax: {str(e)}",
                        path="root"
                    )]
                )
        else:
            parsed_query = query.copy()
        
        result = ValidationResult(
            is_valid=True,
            query=parsed_query
        )
        
        try:
            # Validate query structure
            self._validate_structure(parsed_query, result, "")
            
            # Validate field mappings
            self._validate_field_mappings(parsed_query, result, "")
            
            # Validate date formats
            self._validate_date_formats(parsed_query, result, "")
            
            # Check for optimization opportunities
            self._analyze_optimizations(parsed_query, result)
            
            # Validate aggregations if present
            if 'aggs' in parsed_query or 'aggregations' in parsed_query:
                aggs = parsed_query.get('aggs', parsed_query.get('aggregations', {}))
                self._validate_aggregations(aggs, result, "aggs")
            
            # Set overall validity based on errors
            result.is_valid = len(result.errors) == 0
            
            self.logger.debug(f"Query validation completed: {len(result.issues)} issues found")
            
        except Exception as e:
            self.logger.error(f"Validation error: {e}")
            result.issues.append(ValidationIssue(
                level=ValidationLevel.ERROR,
                message=f"Internal validation error: {str(e)}",
                path="validation"
            ))
            result.is_valid = False
        
        return result
    
    def _validate_structure(self, query: Dict[str, Any], result: ValidationResult, path: str) -> None:
        """Validate basic query structure."""
        if not isinstance(query, dict):
            result.issues.append(ValidationIssue(
                level=ValidationLevel.ERROR,
                message="Query must be a JSON object",
                path=path
            ))
            return
        
        # Check for empty query
        if not query:
            result.issues.append(ValidationIssue(
                level=ValidationLevel.WARNING,
                message="Empty query object",
                path=path,
                suggestion="Add a query clause like 'match_all' or 'bool'"
            ))
            return
        
        # Validate top-level structure
        if 'query' not in query and not any(key in query for key in self.valid_query_types):
            result.issues.append(ValidationIssue(
                level=ValidationLevel.WARNING,
                message="No query clause found at top level",
                path=path,
                suggestion="Wrap your query in a 'query' object or use a valid query type"
            ))
        
        # Recursively validate query clauses
        for key, value in query.items():
            current_path = f"{path}.{key}" if path else key
            
            if key == 'query' and isinstance(value, dict):
                self._validate_query_clause(value, result, current_path)
            elif key in self.valid_query_types:
                self._validate_query_clause({key: value}, result, path)
            elif key in ['size', 'from']:
                self._validate_pagination(key, value, result, current_path)
            elif key == 'sort':
                self._validate_sort(value, result, current_path)
            elif key == '_source':
                self._validate_source_filtering(value, result, current_path)
    
    def _validate_query_clause(self, clause: Dict[str, Any], result: ValidationResult, path: str) -> None:
        """Validate individual query clauses."""
        for query_type, query_body in clause.items():
            current_path = f"{path}.{query_type}"
            
            if query_type not in self.valid_query_types:
                result.issues.append(ValidationIssue(
                    level=ValidationLevel.ERROR,
                    message=f"Unknown query type: {query_type}",
                    path=current_path,
                    suggestion=f"Valid query types: {', '.join(sorted(self.valid_query_types))}"
                ))
                continue
            
            # Validate specific query types
            if query_type == 'bool':
                self._validate_bool_query(query_body, result, current_path)
            elif query_type in ['match', 'match_phrase', 'match_phrase_prefix']:
                self._validate_match_query(query_body, result, current_path)
            elif query_type == 'term':
                self._validate_term_query(query_body, result, current_path)
            elif query_type == 'terms':
                self._validate_terms_query(query_body, result, current_path)
            elif query_type == 'range':
                self._validate_range_query(query_body, result, current_path)
            elif query_type == 'exists':
                self._validate_exists_query(query_body, result, current_path)
            elif query_type in ['wildcard', 'prefix', 'regexp']:
                self._validate_string_query(query_type, query_body, result, current_path)
    
    def _validate_bool_query(self, bool_query: Dict[str, Any], result: ValidationResult, path: str) -> None:
        """Validate bool query structure."""
        if not isinstance(bool_query, dict):
            result.issues.append(ValidationIssue(
                level=ValidationLevel.ERROR,
                message="Bool query must be an object",
                path=path
            ))
            return
        
        valid_bool_clauses = {'must', 'must_not', 'should', 'filter'}
        bool_clauses = set(bool_query.keys())
        
        # Check for valid clauses
        invalid_clauses = bool_clauses - valid_bool_clauses - {'boost', 'minimum_should_match'}
        if invalid_clauses:
            result.issues.append(ValidationIssue(
                level=ValidationLevel.ERROR,
                message=f"Invalid bool clauses: {', '.join(invalid_clauses)}",
                path=path,
                suggestion=f"Valid clauses: {', '.join(valid_bool_clauses)}"
            ))
        
        # Check if bool query has at least one clause
        if not any(clause in bool_query for clause in valid_bool_clauses):
            result.issues.append(ValidationIssue(
                level=ValidationLevel.ERROR,
                message="Bool query has no clauses",
                path=path,
                suggestion="Add at least one of: must, must_not, should, filter"
            ))
        
        # Validate each clause
        for clause_type in valid_bool_clauses:
            if clause_type in bool_query:
                clause_queries = bool_query[clause_type]
                current_path = f"{path}.{clause_type}"
                
                if isinstance(clause_queries, list):
                    for i, query in enumerate(clause_queries):
                        self._validate_query_clause(query, result, f"{current_path}[{i}]")
                elif isinstance(clause_queries, dict):
                    self._validate_query_clause(clause_queries, result, current_path)
                else:
                    result.issues.append(ValidationIssue(
                        level=ValidationLevel.ERROR,
                        message=f"Bool {clause_type} must be an object or array",
                        path=current_path
                    ))
    
    def _validate_match_query(self, match_query: Dict[str, Any], result: ValidationResult, path: str) -> None:
        """Validate match query structure."""
        if not isinstance(match_query, dict):
            result.issues.append(ValidationIssue(
                level=ValidationLevel.ERROR,
                message="Match query must be an object",
                path=path
            ))
            return
        
        if len(match_query) != 1:
            result.issues.append(ValidationIssue(
                level=ValidationLevel.ERROR,
                message="Match query must have exactly one field",
                path=path
            ))
            return
        
        field_name = list(match_query.keys())[0]
        field_query = match_query[field_name]
        
        # Validate field exists
        self._validate_field_name(field_name, result, f"{path}.{field_name}")
        
        # Validate query value
        if isinstance(field_query, dict):
            valid_params = {'query', 'analyzer', 'boost', 'operator', 'minimum_should_match', 'fuzziness'}
            invalid_params = set(field_query.keys()) - valid_params
            if invalid_params:
                result.issues.append(ValidationIssue(
                    level=ValidationLevel.WARNING,
                    message=f"Unknown match parameters: {', '.join(invalid_params)}",
                    path=f"{path}.{field_name}"
                ))
    
    def _validate_term_query(self, term_query: Dict[str, Any], result: ValidationResult, path: str) -> None:
        """Validate term query structure."""
        if not isinstance(term_query, dict) or len(term_query) != 1:
            result.issues.append(ValidationIssue(
                level=ValidationLevel.ERROR,
                message="Term query must have exactly one field",
                path=path
            ))
            return
        
        field_name = list(term_query.keys())[0]
        self._validate_field_name(field_name, result, f"{path}.{field_name}")
        
        # Check if using term on text field (common mistake)
        if field_name in self.wazuh_fields and self.wazuh_fields[field_name] == 'text':
            result.issues.append(ValidationIssue(
                level=ValidationLevel.WARNING,
                message=f"Using term query on text field '{field_name}'",
                path=f"{path}.{field_name}",
                suggestion=f"Use match query instead, or use '{field_name}.keyword' for exact matching",
                fix={"replace_with": "match", "field": field_name}
            ))
    
    def _validate_terms_query(self, terms_query: Dict[str, Any], result: ValidationResult, path: str) -> None:
        """Validate terms query structure."""
        if not isinstance(terms_query, dict) or len(terms_query) != 1:
            result.issues.append(ValidationIssue(
                level=ValidationLevel.ERROR,
                message="Terms query must have exactly one field",
                path=path
            ))
            return
        
        field_name = list(terms_query.keys())[0]
        values = terms_query[field_name]
        
        self._validate_field_name(field_name, result, f"{path}.{field_name}")
        
        if not isinstance(values, list):
            result.issues.append(ValidationIssue(
                level=ValidationLevel.ERROR,
                message="Terms query values must be an array",
                path=f"{path}.{field_name}"
            ))
        elif len(values) > 1000:
            result.issues.append(ValidationIssue(
                level=ValidationLevel.WARNING,
                message=f"Terms query has {len(values)} values (performance concern)",
                path=f"{path}.{field_name}",
                suggestion="Consider using terms lookup or splitting into multiple queries"
            ))
    
    def _validate_range_query(self, range_query: Dict[str, Any], result: ValidationResult, path: str) -> None:
        """Validate range query structure."""
        if not isinstance(range_query, dict) or len(range_query) != 1:
            result.issues.append(ValidationIssue(
                level=ValidationLevel.ERROR,
                message="Range query must have exactly one field",
                path=path
            ))
            return
        
        field_name = list(range_query.keys())[0]
        range_params = range_query[field_name]
        
        self._validate_field_name(field_name, result, f"{path}.{field_name}")
        
        if not isinstance(range_params, dict):
            result.issues.append(ValidationIssue(
                level=ValidationLevel.ERROR,
                message="Range parameters must be an object",
                path=f"{path}.{field_name}"
            ))
            return
        
        valid_params = {'gte', 'gt', 'lte', 'lt', 'boost', 'format', 'time_zone'}
        invalid_params = set(range_params.keys()) - valid_params
        if invalid_params:
            result.issues.append(ValidationIssue(
                level=ValidationLevel.WARNING,
                message=f"Unknown range parameters: {', '.join(invalid_params)}",
                path=f"{path}.{field_name}"
            ))
        
        # Validate range bounds
        range_operators = {'gte', 'gt', 'lte', 'lt'} & set(range_params.keys())
        if not range_operators:
            result.issues.append(ValidationIssue(
                level=ValidationLevel.ERROR,
                message="Range query must have at least one bound (gte, gt, lte, lt)",
                path=f"{path}.{field_name}"
            ))
        
        # Validate date formats in range query
        if field_name in self.wazuh_fields and self.wazuh_fields[field_name] == 'date':
            for param in range_operators:
                if param in range_params:
                    self._validate_date_value(range_params[param], result, f"{path}.{field_name}.{param}")
    
    def _validate_exists_query(self, exists_query: Dict[str, Any], result: ValidationResult, path: str) -> None:
        """Validate exists query structure."""
        if not isinstance(exists_query, dict) or 'field' not in exists_query:
            result.issues.append(ValidationIssue(
                level=ValidationLevel.ERROR,
                message="Exists query must have a 'field' parameter",
                path=path
            ))
            return
        
        field_name = exists_query['field']
        self._validate_field_name(field_name, result, f"{path}.field")
    
    def _validate_string_query(self, query_type: str, string_query: Dict[str, Any], result: ValidationResult, path: str) -> None:
        """Validate wildcard, prefix, and regexp queries."""
        if not isinstance(string_query, dict) or len(string_query) != 1:
            result.issues.append(ValidationIssue(
                level=ValidationLevel.ERROR,
                message=f"{query_type.title()} query must have exactly one field",
                path=path
            ))
            return
        
        field_name = list(string_query.keys())[0]
        self._validate_field_name(field_name, result, f"{path}.{field_name}")
        
        # Performance warnings for wildcard queries
        if query_type == 'wildcard':
            pattern = string_query[field_name]
            if isinstance(pattern, str) and pattern.startswith('*'):
                result.issues.append(ValidationIssue(
                    level=ValidationLevel.WARNING,
                    message="Wildcard query starting with '*' can be slow",
                    path=f"{path}.{field_name}",
                    suggestion="Consider using suffix matching or n-gram analysis"
                ))
    
    def _validate_field_mappings(self, query: Dict[str, Any], result: ValidationResult, path: str) -> None:
        """Validate field names against Wazuh mappings."""
        self._extract_and_validate_fields(query, result, path)
    
    def _extract_and_validate_fields(self, obj: Any, result: ValidationResult, path: str) -> None:
        """Recursively extract and validate field names."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                current_path = f"{path}.{key}" if path else key
                
                # Skip query structure keywords and parameters
                skip_keys = (
                    self.valid_query_types | 
                    {'query', 'bool', 'must', 'must_not', 'should', 'filter', 'aggs', 'aggregations'} |
                    {'size', 'from', 'sort', '_source', 'highlight', 'explain', 'timeout'} |
                    {'gte', 'gt', 'lte', 'lt', 'boost', 'format', 'time_zone', 'order', 'mode'} |
                    {'missing', 'unmapped_type', 'analyzer', 'operator', 'minimum_should_match', 'fuzziness'}
                )
                
                if key in skip_keys:
                    self._extract_and_validate_fields(value, result, current_path)
                    continue
                
                # Check if this is a field parameter (like 'field' in exists query)
                if key == 'field' and isinstance(value, str):
                    self._validate_field_name(value, result, current_path)
                    continue
                
                # Check if this looks like a field name (in leaf queries)
                # Only validate leaf values as field names, not intermediate objects
                if (isinstance(value, (str, int, float, bool)) or 
                    (isinstance(value, dict) and 
                     any(param in value for param in ['gte', 'gt', 'lte', 'lt', 'query', 'value']) and
                     key not in ['query', 'bool', 'must', 'must_not', 'should', 'filter'])):
                    # Only validate as field name if it's not a known parameter
                    if key not in skip_keys:
                        self._validate_field_name(key, result, current_path)
                
                if isinstance(value, (dict, list)):
                    self._extract_and_validate_fields(value, result, current_path)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                self._extract_and_validate_fields(item, result, f"{path}[{i}]")
    
    def _validate_field_name(self, field_name: str, result: ValidationResult, path: str) -> None:
        """Validate a single field name."""
        if not field_name:
            return
        
        # Check if field exists in known mappings
        if field_name not in self.wazuh_fields:
            # Check for common field name patterns
            suggestions = self._suggest_field_alternatives(field_name)
            
            result.issues.append(ValidationIssue(
                level=ValidationLevel.WARNING,
                message=f"Unknown field: {field_name}",
                path=path,
                field=field_name,
                suggestion=f"Did you mean: {', '.join(suggestions[:3])}" if suggestions else "Check field mapping"
            ))
        else:
            # Add to field mappings for reference
            result.field_mappings[field_name] = self.wazuh_fields[field_name]
    
    def _suggest_field_alternatives(self, field_name: str) -> List[str]:
        """Suggest alternative field names based on similarity."""
        suggestions = []
        field_lower = field_name.lower()
        
        # Look for partial matches
        for known_field in self.wazuh_fields.keys():
            if field_lower in known_field.lower() or known_field.lower() in field_lower:
                suggestions.append(known_field)
        
        # If no partial matches, look for similar words
        if not suggestions:
            words = field_lower.replace('.', ' ').replace('_', ' ').split()
            for known_field in self.wazuh_fields.keys():
                known_words = known_field.lower().replace('.', ' ').replace('_', ' ').split()
                if any(word in known_words for word in words):
                    suggestions.append(known_field)
        
        return sorted(set(suggestions))[:5]
    
    def _validate_date_formats(self, query: Dict[str, Any], result: ValidationResult, path: str) -> None:
        """Validate date formats in the query."""
        self._extract_and_validate_dates(query, result, path)
    
    def _extract_and_validate_dates(self, obj: Any, result: ValidationResult, path: str) -> None:
        """Recursively find and validate date values."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                current_path = f"{path}.{key}" if path else key
                
                # Check if this is a date field
                if key in self.wazuh_fields and self.wazuh_fields[key] == 'date':
                    if isinstance(value, (str, int)):
                        self._validate_date_value(value, result, current_path)
                elif isinstance(value, dict):
                    # Check for range queries on date fields
                    parent_field = path.split('.')[-1] if '.' in path else path
                    if parent_field in self.wazuh_fields and self.wazuh_fields[parent_field] == 'date':
                        for range_key, range_value in value.items():
                            if range_key in ['gte', 'gt', 'lte', 'lt'] and isinstance(range_value, (str, int)):
                                self._validate_date_value(range_value, result, f"{current_path}.{range_key}")
                
                if isinstance(value, (dict, list)):
                    self._extract_and_validate_dates(value, result, current_path)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                self._extract_and_validate_dates(item, result, f"{path}[{i}]")
    
    def _validate_date_value(self, date_value: Union[str, int], result: ValidationResult, path: str) -> None:
        """Validate a single date value."""
        if isinstance(date_value, int):
            # Unix timestamp validation
            if date_value < 0 or date_value > 2147483647000:  # Reasonable timestamp range
                result.issues.append(ValidationIssue(
                    level=ValidationLevel.WARNING,
                    message=f"Unusual timestamp value: {date_value}",
                    path=path
                ))
            return
        
        if not isinstance(date_value, str):
            return
        
        # Check against known patterns
        is_valid_format = any(re.match(pattern, date_value) for pattern in self.date_patterns)
        
        # Additional validation for dates that match format but have invalid values
        format_valid_but_invalid_date = False
        if is_valid_format and '-' in date_value and not date_value.startswith('now'):
            try:
                parts = date_value.split('T')[0].split('-')  # Get just date part
                if len(parts) == 3:
                    year, month, day = int(parts[0]), int(parts[1]), int(parts[2])
                    if not (1 <= month <= 12) or not (1 <= day <= 31):
                        format_valid_but_invalid_date = True
            except (ValueError, IndexError):
                format_valid_but_invalid_date = True
        
        if not is_valid_format or format_valid_but_invalid_date:
            result.issues.append(ValidationIssue(
                level=ValidationLevel.ERROR,
                message=f"Invalid date format: {date_value}",
                path=path,
                suggestion="Use ISO format (YYYY-MM-DDTHH:MM:SS.sssZ) or Elasticsearch date math (now-1d)"
            ))
        
        # Try to parse as ISO date for additional validation
        try:
            if 'T' in date_value and not date_value.startswith('now'):
                datetime.fromisoformat(date_value.replace('Z', '+00:00'))
            elif '-' in date_value and not date_value.startswith('now'):
                # Try to parse YYYY-MM-DD format
                parts = date_value.split('-')
                if len(parts) == 3:
                    year, month, day = int(parts[0]), int(parts[1]), int(parts[2])
                    if not (1 <= month <= 12):
                        raise ValueError("Invalid month")
                    if not (1 <= day <= 31):
                        raise ValueError("Invalid day")
        except ValueError as e:
            if not is_valid_format:  # Only add if format check also failed
                result.issues.append(ValidationIssue(
                    level=ValidationLevel.ERROR,
                    message=f"Date value is not parseable: {date_value} ({str(e)})",
                    path=path
                ))
    
    def _validate_aggregations(self, aggs: Dict[str, Any], result: ValidationResult, path: str) -> None:
        """Validate aggregations structure."""
        if not isinstance(aggs, dict):
            result.issues.append(ValidationIssue(
                level=ValidationLevel.ERROR,
                message="Aggregations must be an object",
                path=path
            ))
            return
        
        for agg_name, agg_config in aggs.items():
            current_path = f"{path}.{agg_name}"
            
            if not isinstance(agg_config, dict):
                result.issues.append(ValidationIssue(
                    level=ValidationLevel.ERROR,
                    message=f"Aggregation '{agg_name}' must be an object",
                    path=current_path
                ))
                continue
            
            # Validate aggregation types
            agg_types = set(agg_config.keys()) - {'aggs', 'aggregations'}
            if len(agg_types) != 1:
                result.issues.append(ValidationIssue(
                    level=ValidationLevel.ERROR,
                    message=f"Aggregation '{agg_name}' must have exactly one aggregation type",
                    path=current_path
                ))
                continue
            
            agg_type = list(agg_types)[0]
            agg_body = agg_config[agg_type]
            
            # Validate specific aggregation types
            if agg_type == 'terms':
                self._validate_terms_aggregation(agg_body, result, f"{current_path}.{agg_type}")
            elif agg_type == 'date_histogram':
                self._validate_date_histogram_aggregation(agg_body, result, f"{current_path}.{agg_type}")
            
            # Validate nested aggregations
            if 'aggs' in agg_config or 'aggregations' in agg_config:
                nested_aggs = agg_config.get('aggs', agg_config.get('aggregations', {}))
                self._validate_aggregations(nested_aggs, result, f"{current_path}.aggs")
    
    def _validate_terms_aggregation(self, terms_agg: Dict[str, Any], result: ValidationResult, path: str) -> None:
        """Validate terms aggregation."""
        if 'field' not in terms_agg:
            result.issues.append(ValidationIssue(
                level=ValidationLevel.ERROR,
                message="Terms aggregation must have a 'field' parameter",
                path=path
            ))
            return
        
        field_name = terms_agg['field']
        self._validate_field_name(field_name, result, f"{path}.field")
        
        # Check size parameter
        size = terms_agg.get('size', 10)
        if size > 10000:
            result.issues.append(ValidationIssue(
                level=ValidationLevel.WARNING,
                message=f"Large terms aggregation size: {size}",
                path=f"{path}.size",
                suggestion="Consider using composite aggregation for large cardinality fields"
            ))
    
    def _validate_date_histogram_aggregation(self, date_hist: Dict[str, Any], result: ValidationResult, path: str) -> None:
        """Validate date histogram aggregation."""
        # Check for required field parameter
        if 'field' not in date_hist:
            result.issues.append(ValidationIssue(
                level=ValidationLevel.ERROR,
                message="Date histogram aggregation missing required parameter: field",
                path=path
            ))
        
        # Check for required interval parameter (either calendar_interval or fixed_interval)
        if 'calendar_interval' not in date_hist and 'fixed_interval' not in date_hist:
            result.issues.append(ValidationIssue(
                level=ValidationLevel.ERROR,
                message="Date histogram aggregation missing required parameter: calendar_interval or fixed_interval",
                path=path
            ))
        
        if 'field' in date_hist:
            field_name = date_hist['field']
            self._validate_field_name(field_name, result, f"{path}.field")
            
            # Ensure field is date type
            if field_name in self.wazuh_fields and self.wazuh_fields[field_name] != 'date':
                result.issues.append(ValidationIssue(
                    level=ValidationLevel.WARNING,
                    message=f"Date histogram on non-date field: {field_name}",
                    path=f"{path}.field"
                ))
    
    def _validate_pagination(self, param: str, value: Any, result: ValidationResult, path: str) -> None:
        """Validate pagination parameters."""
        if not isinstance(value, int) or value < 0:
            result.issues.append(ValidationIssue(
                level=ValidationLevel.ERROR,
                message=f"{param} must be a non-negative integer",
                path=path
            ))
        elif param == 'size' and value > 10000:
            result.issues.append(ValidationIssue(
                level=ValidationLevel.WARNING,
                message=f"Large size parameter: {value}",
                path=path,
                suggestion="Use scroll API for large result sets"
            ))
    
    def _validate_sort(self, sort_config: Any, result: ValidationResult, path: str) -> None:
        """Validate sort configuration."""
        if isinstance(sort_config, str):
            self._validate_field_name(sort_config, result, path)
        elif isinstance(sort_config, list):
            for i, sort_item in enumerate(sort_config):
                self._validate_sort(sort_item, result, f"{path}[{i}]")
        elif isinstance(sort_config, dict):
            for field_name, sort_options in sort_config.items():
                self._validate_field_name(field_name, result, f"{path}.{field_name}")
                
                if isinstance(sort_options, dict):
                    valid_options = {'order', 'mode', 'missing', 'unmapped_type'}
                    invalid_options = set(sort_options.keys()) - valid_options
                    if invalid_options:
                        result.issues.append(ValidationIssue(
                            level=ValidationLevel.WARNING,
                            message=f"Unknown sort options: {', '.join(invalid_options)}",
                            path=f"{path}.{field_name}"
                        ))
    
    def _validate_source_filtering(self, source_config: Any, result: ValidationResult, path: str) -> None:
        """Validate _source filtering configuration."""
        if isinstance(source_config, bool):
            return  # Valid
        elif isinstance(source_config, str):
            self._validate_field_name(source_config, result, path)
        elif isinstance(source_config, list):
            for i, field in enumerate(source_config):
                if isinstance(field, str):
                    self._validate_field_name(field, result, f"{path}[{i}]")
        elif isinstance(source_config, dict):
            for key in ['includes', 'excludes']:
                if key in source_config:
                    includes = source_config[key]
                    if isinstance(includes, list):
                        for i, field in enumerate(includes):
                            if isinstance(field, str):
                                self._validate_field_name(field, result, f"{path}.{key}[{i}]")
    
    def _analyze_optimizations(self, query: Dict[str, Any], result: ValidationResult) -> None:
        """Analyze query for optimization opportunities."""
        optimizations = []
        
        # Check for match_all queries
        if self._contains_match_all(query):
            optimizations.append("Consider adding filters to reduce result set size")
        
        # Check for missing query context
        if self._has_only_filter_context(query):
            optimizations.append("Consider using query context instead of filter context for scoring")
        
        # Check for inefficient wildcard usage
        if self._has_leading_wildcards(query):
            optimizations.append("Avoid leading wildcards (*term) for better performance")
        
        # Check for large terms queries
        large_terms = self._find_large_terms_queries(query)
        if large_terms:
            optimizations.append(f"Large terms queries found at: {', '.join(large_terms)}")
        
        # Check for missing index patterns
        if not self._has_appropriate_filters(query):
            optimizations.append("Add timestamp filters to limit search scope")
        
        result.optimizations.extend(optimizations)
    
    def _contains_match_all(self, obj: Any) -> bool:
        """Check if query contains match_all."""
        if isinstance(obj, dict):
            if 'match_all' in obj:
                return True
            return any(self._contains_match_all(v) for v in obj.values())
        elif isinstance(obj, list):
            return any(self._contains_match_all(item) for item in obj)
        return False
    
    def _has_only_filter_context(self, query: Dict[str, Any]) -> bool:
        """Check if query uses only filter context."""
        if 'query' in query:
            query_part = query['query']
            if isinstance(query_part, dict) and 'bool' in query_part:
                bool_query = query_part['bool']
                return 'filter' in bool_query and not any(key in bool_query for key in ['must', 'should'])
        return False
    
    def _has_leading_wildcards(self, obj: Any) -> bool:
        """Check for leading wildcard patterns."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key == 'wildcard' and isinstance(value, dict):
                    for field_value in value.values():
                        if isinstance(field_value, str) and field_value.startswith('*'):
                            return True
                if isinstance(value, (dict, list)):
                    if self._has_leading_wildcards(value):
                        return True
        elif isinstance(obj, list):
            return any(self._has_leading_wildcards(item) for item in obj)
        return False
    
    def _find_large_terms_queries(self, obj: Any, path: str = "") -> List[str]:
        """Find terms queries with many values."""
        large_terms = []
        if isinstance(obj, dict):
            for key, value in obj.items():
                current_path = f"{path}.{key}" if path else key
                if key == 'terms' and isinstance(value, dict):
                    for field_name, terms_list in value.items():
                        if isinstance(terms_list, list) and len(terms_list) > 100:
                            large_terms.append(f"{current_path}.{field_name}")
                elif isinstance(value, (dict, list)):
                    large_terms.extend(self._find_large_terms_queries(value, current_path))
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                large_terms.extend(self._find_large_terms_queries(item, f"{path}[{i}]"))
        return large_terms
    
    def _has_appropriate_filters(self, query: Dict[str, Any]) -> bool:
        """Check if query has appropriate timestamp filters."""
        return self._has_timestamp_filter(query)
    
    def _has_timestamp_filter(self, obj: Any) -> bool:
        """Check for timestamp filters."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key in ['@timestamp', 'timestamp'] and isinstance(value, dict):
                    if any(range_key in value for range_key in ['gte', 'gt', 'lte', 'lt']):
                        return True
                elif key == 'range' and isinstance(value, dict):
                    if any(field in value for field in ['@timestamp', 'timestamp']):
                        return True
                elif isinstance(value, (dict, list)):
                    if self._has_timestamp_filter(value):
                        return True
        elif isinstance(obj, list):
            return any(self._has_timestamp_filter(item) for item in obj)
        return False


def validate_elasticsearch_query(query: Union[str, Dict[str, Any]], 
                                dry_run: bool = True, 
                                config_manager=None) -> ValidationResult:
    """
    Convenience function to validate an Elasticsearch DSL query.
    
    Args:
        query: Query as JSON string or dictionary
        dry_run: If True, only validate without making connections
        config_manager: Optional configuration manager
        
    Returns:
        ValidationResult: Comprehensive validation results
    """
    validator = ElasticsearchValidator(config_manager)
    return validator.validate_query(query, dry_run)


if __name__ == "__main__":
    # Demo and testing
    logging.basicConfig(level=logging.INFO)
    
    # Test queries
    test_queries = [
        # Valid query
        {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"rule.description": "authentication"}},
                        {"range": {"@timestamp": {"gte": "2023-01-01T00:00:00.000Z"}}}
                    ],
                    "filter": [
                        {"term": {"rule.level": 5}}
                    ]
                }
            },
            "size": 100
        },
        
        # Query with issues
        {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"full_log": "error"}},  # term on text field
                        {"range": {"timestamp": {"gte": "invalid-date"}}}  # invalid date
                    ]
                }
            },
            "size": 15000  # too large
        },
        
        # Invalid JSON string
        '{"query": {"match": {"rule.description": "test"}}',  # missing closing brace
        
        # Query with unknown fields
        {
            "query": {
                "match": {"unknown_field": "value"}
            }
        }
    ]
    
    print("Elasticsearch Query Validator Demo")
    print("=" * 50)
    
    for i, test_query in enumerate(test_queries, 1):
        print(f"\nTest Query {i}:")
        print("-" * 20)
        
        result = validate_elasticsearch_query(test_query)
        
        print(f"Valid: {result.is_valid}")
        print(f"Issues: {len(result.issues)}")
        
        for issue in result.issues:
            icon = "❌" if issue.level == ValidationLevel.ERROR else "⚠️" if issue.level == ValidationLevel.WARNING else "💡"
            print(f"  {icon} {issue.level.value.upper()}: {issue.message}")
            if issue.path:
                print(f"     Path: {issue.path}")
            if issue.suggestion:
                print(f"     Suggestion: {issue.suggestion}")
        
        if result.optimizations:
            print("  Optimizations:")
            for opt in result.optimizations:
                print(f"    • {opt}")
        
        print()
