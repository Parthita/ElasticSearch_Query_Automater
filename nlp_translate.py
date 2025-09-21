"""
NLP Translation Module

This module provides natural language processing functionality to translate
user queries into Elasticsearch DSL queries for Wazuh data. It uses keyword
matching, configuration-based mappings, and confidence scoring to generate
accurate queries with fallback handling for unrecognized input.
"""

import logging
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict
from dataclasses import dataclass

from config import get_config, ConfigManager
from elasticsearch_validator import validate_elasticsearch_query, ValidationResult

logger = logging.getLogger(__name__)


@dataclass
class TranslationResult:
    """Contains the result of NLP query translation."""
    success: bool
    query: Dict[str, Any]
    confidence: float
    validation_result: Optional[ValidationResult] = None
    fallback_used: bool = False
    detected_intent: Dict[str, Any] = None
    suggestions: List[str] = None
    
    def __post_init__(self):
        if self.detected_intent is None:
            self.detected_intent = {}
        if self.suggestions is None:
            self.suggestions = []


@dataclass
class QueryIntent:
    """Represents the detected intent from a natural language query."""
    rule_types: List[str]
    severity_levels: Tuple[int, int]  # min, max
    rule_ids: List[int]
    keywords: List[str]
    time_range: Optional[Dict[str, str]]
    description_terms: List[str]
    confidence_scores: Dict[str, float]
    
    def __post_init__(self):
        if not hasattr(self, 'confidence_scores') or self.confidence_scores is None:
            self.confidence_scores = {}


class NLPTranslator:
    """
    Translates natural language queries into Elasticsearch DSL queries for Wazuh data.
    
    Features:
    - Keyword-based matching for rule attributes
    - Configuration-driven severity mapping
    - Time expression processing
    - Confidence scoring
    - Query validation
    - Fallback handling
    """
    
    def __init__(self, config_manager: Optional[ConfigManager] = None):
        """Initialize the NLP translator."""
        self.logger = logging.getLogger(__name__)
        self.config = config_manager or get_config()
        
        # Rules metadata
        self.rules = []
        self.rules_by_id = {}
        self.rules_by_type = defaultdict(list)
        
        # Translation patterns and mappings
        self.severity_patterns = {}
        self.time_patterns = {}
        self.keyword_patterns = {}
        
        # Confidence thresholds
        self.min_confidence = 0.3
        self.good_confidence = 0.7
        
        self.initialized = False
        self._initialize_patterns()
    
    def _initialize_patterns(self) -> None:
        """Initialize translation patterns from configuration."""
        # Severity patterns from config
        severity_mappings = {}
        for name, mapping in self.config.get('severity.mappings', {}).items():
            if isinstance(mapping, dict):
                severity_mappings[name] = (mapping.get('min', 0), mapping.get('max', 15))
        
        severity_keywords = self.config.get_severity_keywords()
        
        self.severity_patterns = {
            'mappings': severity_mappings,
            'keywords': severity_keywords,
            'patterns': [
                (r'\b(critical|severe|urgent|dangerous)\b', 12, 15),
                (r'\b(high|serious|important)\b', 7, 10),
                (r'\b(medium|moderate|warning)\b', 4, 6),
                (r'\b(low|minor|info|informational)\b', 1, 3),
                (r'\blevel\s*([>=<]+)\s*(\d+)\b', 'level_constraint'),
                (r'\blevel\s+(\d+)\b', 'exact_level'),
            ]
        }
        
        # Time patterns
        self.time_patterns = {
            'recent': {'duration': '1h', 'relative': 'now-1h'},
            'today': {'duration': '24h', 'relative': 'now-24h'},
            'yesterday': {'duration': '24h', 'relative': 'now-48h', 'end': 'now-24h'},
            'last_hour': {'duration': '1h', 'relative': 'now-1h'},
            'last_day': {'duration': '24h', 'relative': 'now-24h'},
            'last_week': {'duration': '7d', 'relative': 'now-7d'},
            'last_month': {'duration': '30d', 'relative': 'now-30d'},
            'this_week': {'duration': '7d', 'relative': 'now-7d'},
            'this_month': {'duration': '30d', 'relative': 'now-30d'},
        }
        
        # Common query patterns
        self.keyword_patterns = {
            'rule_id': r'\b(?:rule|id)\s*[:#]?\s*(\d+)\b',
            'time_recent': r'\b(recent|recently|lately|now)\b',
            'time_today': r'\b(today|current)\b',
            'time_yesterday': r'\byesterday\b',
            'time_last': r'\blast\s+(hour|day|week|month|year)\b',
            'time_this': r'\bthis\s+(hour|day|week|month|year)\b',
            'time_range': r'\b(\d+)\s+(minutes?|hours?|days?|weeks?|months?)\s+ago\b',
            'show_all': r'\b(show|list|find|get|display)\s+(all|everything)\b',
            'count': r'\b(count|number|total)\s+of\b',
            'top': r'\b(top|first|last)\s*(\d+)?\b',
        }
    
    def initialize(self, rules: List[Any]) -> None:
        """
        Initialize the translator with rules metadata.
        
        Args:
            rules: List of WazuhRule objects
        """
        self.rules = rules
        self.rules_by_id = {rule.id: rule for rule in rules}
        
        # Group rules by type for better matching
        self.rules_by_type = defaultdict(list)
        for rule in rules:
            self.rules_by_type[rule.type].append(rule)
        
        self.initialized = True
        self.logger.info(f"NLP Translator initialized with {len(rules)} rules")
    
    def translate_query(self, query: str, validate_output: bool = True) -> TranslationResult:
        """
        Translate a natural language query into an Elasticsearch DSL query.
        
        Args:
            query: Natural language query
            validate_output: Whether to validate the generated query
            
        Returns:
            TranslationResult with the Elasticsearch query and metadata
        """
        if not self.initialized:
            return TranslationResult(
                success=False,
                query={},
                confidence=0.0,
                suggestions=["Translator not initialized with rules data"]
            )
        
        try:
            # Parse the natural language query
            intent = self._parse_query_intent(query)
            
            # Generate Elasticsearch DSL query
            es_query = self._generate_elasticsearch_query(intent)
            
            # Calculate overall confidence
            confidence = self._calculate_confidence(intent, query)
            
            # Validate the generated query if requested
            validation_result = None
            if validate_output and es_query:
                validation_result = validate_elasticsearch_query(es_query)
                if not validation_result.is_valid:
                    self.logger.warning(f"Generated invalid query: {len(validation_result.errors)} errors")
            
            # Handle low confidence with fallbacks
            if confidence < self.min_confidence:
                fallback_query = self._generate_fallback_query(query, intent)
                if fallback_query:
                    return TranslationResult(
                        success=True,
                        query=fallback_query,
                        confidence=self.min_confidence,
                        validation_result=validate_elasticsearch_query(fallback_query) if validate_output else None,
                        fallback_used=True,
                        detected_intent=intent.confidence_scores,
                        suggestions=self._generate_suggestions(intent, query)
                    )
            
            return TranslationResult(
                success=bool(es_query),
                query=es_query or {},
                confidence=confidence,
                validation_result=validation_result,
                fallback_used=False,
                detected_intent=intent.confidence_scores,
                suggestions=self._generate_suggestions(intent, query) if confidence < self.good_confidence else []
            )
            
        except Exception as e:
            self.logger.error(f"Translation error: {e}")
            return TranslationResult(
                success=False,
                query={},
                confidence=0.0,
                suggestions=[f"Translation failed: {str(e)}"]
            )
    
    def _parse_query_intent(self, query: str) -> QueryIntent:
        """
        Parse natural language query to extract intent.
        
        Args:
            query: Natural language query
            
        Returns:
            QueryIntent with extracted information
        """
        query_lower = query.lower().strip()
        confidence_scores = {}
        
        # Extract rule types
        rule_types, type_confidence = self._extract_rule_types(query_lower)
        confidence_scores['rule_type'] = type_confidence
        
        # Extract severity levels
        severity_min, severity_max, severity_confidence = self._extract_severity_levels(query_lower)
        confidence_scores['severity'] = severity_confidence
        
        # Extract rule IDs
        rule_ids, id_confidence = self._extract_rule_ids(query_lower)
        confidence_scores['rule_id'] = id_confidence
        
        # Extract time range
        time_range, time_confidence = self._extract_time_range(query_lower)
        confidence_scores['time_range'] = time_confidence
        
        # Extract keywords and description terms
        keywords, desc_terms, keyword_confidence = self._extract_keywords_and_descriptions(query_lower)
        confidence_scores['keywords'] = keyword_confidence
        
        return QueryIntent(
            rule_types=rule_types,
            severity_levels=(severity_min, severity_max),
            rule_ids=rule_ids,
            keywords=keywords,
            time_range=time_range,
            description_terms=desc_terms,
            confidence_scores=confidence_scores
        )
    
    def _extract_rule_types(self, query: str) -> Tuple[List[str], float]:
        """Extract rule types from query."""
        rule_types = []
        type_scores = defaultdict(float)
        
        # Get rule type keywords from config
        rule_types_config = self.config.get('rule_types', {})
        
        for rule_type, type_config in rule_types_config.items():
            if not isinstance(type_config, dict):
                continue
                
            keywords = type_config.get('keywords', [])
            aliases = type_config.get('aliases', [])
            
            # Score based on keyword matches
            for keyword in keywords + aliases:
                if keyword in query:
                    # Exact word boundary match gets higher score
                    if re.search(rf'\b{re.escape(keyword)}\b', query):
                        type_scores[rule_type] += 1.0
                    else:
                        type_scores[rule_type] += 0.5
        
        # Select types with significant scores
        threshold = self.config.get('nlp.type_detection_threshold', 0.5)
        for rule_type, score in type_scores.items():
            if score >= threshold:
                rule_types.append(rule_type)
        
        # Calculate confidence
        if type_scores:
            max_score = max(type_scores.values())
            confidence = min(max_score / 2.0, 1.0)  # Normalize to 0-1
        else:
            confidence = 0.0
        
        return rule_types, confidence
    
    def _extract_severity_levels(self, query: str) -> Tuple[int, int, float]:
        """Extract severity level constraints."""
        min_level, max_level = 0, 15
        confidence = 0.0
        
        # Check for named severity levels
        for severity_name, (sev_min, sev_max) in self.severity_patterns['mappings'].items():
            if severity_name in query:
                min_level = max(min_level, sev_min)
                max_level = min(max_level, sev_max)
                confidence += 0.8
        
        # Check for severity keywords
        for keyword, level in self.severity_patterns['keywords'].items():
            if re.search(rf'\b{re.escape(keyword)}\b', query):
                if 'high' in keyword or 'critical' in keyword:
                    min_level = max(min_level, level)
                elif 'low' in keyword:
                    max_level = min(max_level, level + 2)
                else:
                    min_level = max(min_level, level - 1)
                    max_level = min(max_level, level + 1)
                confidence += 0.7
        
        # Check for explicit level constraints
        level_matches = re.findall(r'\blevel\s*([>=<]+)\s*(\d+)\b', query)
        for operator, level_str in level_matches:
            level = int(level_str)
            if '>=' in operator or '>' in operator:
                min_level = max(min_level, level)
            elif '<=' in operator or '<' in operator:
                max_level = min(max_level, level)
            confidence += 0.9
        
        # Check for exact level
        exact_matches = re.findall(r'\blevel\s+(\d+)\b', query)
        if exact_matches:
            level = int(exact_matches[0])
            min_level = max_level = level
            confidence = 1.0
        
        return min_level, max_level, min(confidence, 1.0)
    
    def _extract_rule_ids(self, query: str) -> Tuple[List[int], float]:
        """Extract rule IDs from query."""
        rule_ids = []
        confidence = 0.0
        
        # Look for explicit rule ID patterns
        id_matches = re.findall(self.keyword_patterns['rule_id'], query)
        for id_str in id_matches:
            try:
                rule_id = int(id_str)
                if rule_id in self.rules_by_id:
                    rule_ids.append(rule_id)
                    confidence = 1.0
            except ValueError:
                continue
        
        return rule_ids, confidence
    
    def _extract_time_range(self, query: str) -> Tuple[Optional[Dict[str, str]], float]:
        """Extract time range from query."""
        time_range = None
        confidence = 0.0
        
        # Check for predefined time patterns
        for pattern_name, pattern_config in self.time_patterns.items():
            # Create regex patterns for each time expression
            if pattern_name == 'recent' and re.search(self.keyword_patterns['time_recent'], query):
                time_range = {'gte': pattern_config['relative']}
                confidence = 0.8
                break
            elif pattern_name == 'today' and re.search(self.keyword_patterns['time_today'], query):
                time_range = {'gte': pattern_config['relative']}
                confidence = 0.9
                break
            elif pattern_name.startswith('last_') and re.search(self.keyword_patterns['time_last'], query):
                time_range = {'gte': pattern_config['relative']}
                confidence = 0.8
                break
        
        # Check for "yesterday"
        if re.search(self.keyword_patterns['time_yesterday'], query):
            time_range = {
                'gte': self.time_patterns['yesterday']['relative'],
                'lte': self.time_patterns['yesterday']['end']
            }
            confidence = 0.9
        
        # Check for relative time expressions like "5 minutes ago"
        time_matches = re.findall(self.keyword_patterns['time_range'], query)
        if time_matches:
            amount, unit = time_matches[0]
            unit_map = {'minute': 'm', 'hour': 'h', 'day': 'd', 'week': 'w', 'month': 'M'}
            unit_char = unit_map.get(unit.rstrip('s'), 'd')
            time_range = {'gte': f'now-{amount}{unit_char}'}
            confidence = 0.8
        
        return time_range, confidence
    
    def _extract_keywords_and_descriptions(self, query: str) -> Tuple[List[str], List[str], float]:
        """Extract keywords and description terms."""
        # Get stop words from config
        stop_words = set(self.config.get_stop_words())
        
        # Extract all words
        words = re.findall(r'\b\w{3,}\b', query.lower())
        
        # Filter out stop words and common query terms
        query_terms = {'show', 'find', 'get', 'list', 'display', 'rule', 'rules', 'level', 'type'}
        keywords = []
        description_terms = []
        
        for word in words:
            if word not in stop_words and word not in query_terms and not word.isdigit():
                keywords.append(word)
                
                # Check if word appears in any rule descriptions
                for rule in self.rules:
                    if word in rule.description.lower():
                        if word not in description_terms:
                            description_terms.append(word)
                        break
        
        # Calculate confidence based on how many keywords match rule descriptions
        if keywords:
            matching_keywords = len([k for k in keywords if k in description_terms])
            confidence = matching_keywords / len(keywords)
        else:
            confidence = 0.0
        
        return keywords, description_terms, confidence
    
    def _generate_elasticsearch_query(self, intent: QueryIntent) -> Dict[str, Any]:
        """
        Generate Elasticsearch DSL query from parsed intent.
        
        Args:
            intent: Parsed query intent
            
        Returns:
            Elasticsearch DSL query
        """
        query = {
            "query": {
                "bool": {
                    "must": [],
                    "filter": []
                }
            },
            "size": self.config.get('query_processing.default_results', 50)
        }
        
        # Add rule type filters
        if intent.rule_types:
            if len(intent.rule_types) == 1:
                query["query"]["bool"]["filter"].append({
                    "term": {"rule.groups": intent.rule_types[0]}
                })
            else:
                query["query"]["bool"]["filter"].append({
                    "terms": {"rule.groups": intent.rule_types}
                })
        
        # Add severity level filters
        min_level, max_level = intent.severity_levels
        if min_level > 0 or max_level < 15:
            range_filter = {}
            if min_level > 0:
                range_filter["gte"] = min_level
            if max_level < 15:
                range_filter["lte"] = max_level
            
            query["query"]["bool"]["filter"].append({
                "range": {"rule.level": range_filter}
            })
        
        # Add rule ID filters
        if intent.rule_ids:
            if len(intent.rule_ids) == 1:
                query["query"]["bool"]["filter"].append({
                    "term": {"rule.id": intent.rule_ids[0]}
                })
            else:
                query["query"]["bool"]["filter"].append({
                    "terms": {"rule.id": intent.rule_ids}
                })
        
        # Add time range filter
        if intent.time_range:
            query["query"]["bool"]["filter"].append({
                "range": {"@timestamp": intent.time_range}
            })
        
        # Add description/content search
        if intent.description_terms:
            if len(intent.description_terms) == 1:
                query["query"]["bool"]["must"].append({
                    "match": {"rule.description": intent.description_terms[0]}
                })
            else:
                query["query"]["bool"]["must"].append({
                    "multi_match": {
                        "query": " ".join(intent.description_terms),
                        "fields": ["rule.description", "full_log"]
                    }
                })
        
        # If no specific constraints, add a match_all to ensure we get results
        if (not query["query"]["bool"]["must"] and 
            not query["query"]["bool"]["filter"]):
            query["query"] = {"match_all": {}}
        
        # Add sorting by timestamp (newest first)
        query["sort"] = [{"@timestamp": {"order": "desc"}}]
        
        return query
    
    def _calculate_confidence(self, intent: QueryIntent, original_query: str) -> float:
        """Calculate overall confidence score for the translation."""
        scores = list(intent.confidence_scores.values())
        
        if not scores:
            return 0.0
        
        # Weighted average with emphasis on higher scores
        weights = [score + 0.1 for score in scores]  # Add small base weight
        weighted_sum = sum(score * weight for score, weight in zip(scores, weights))
        weight_sum = sum(weights)
        
        confidence = weighted_sum / weight_sum if weight_sum > 0 else 0.0
        
        # Boost confidence if we have multiple types of matches
        if len([s for s in scores if s > 0.5]) >= 2:
            confidence += 0.1
        
        # Reduce confidence for very short queries
        if len(original_query.split()) < 3:
            confidence *= 0.8
        
        return min(confidence, 1.0)
    
    def _generate_fallback_query(self, query: str, intent: QueryIntent) -> Optional[Dict[str, Any]]:
        """Generate a fallback query for low-confidence translations."""
        # Simple keyword search across all fields
        keywords = intent.keywords or re.findall(r'\b\w{4,}\b', query.lower())
        
        if not keywords:
            # Ultimate fallback - recent events
            return {
                "query": {"match_all": {}},
                "filter": {
                    "range": {
                        "@timestamp": {"gte": "now-1h"}
                    }
                },
                "size": 20,
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
        
        # Search for keywords in rule descriptions and logs
        return {
            "query": {
                "multi_match": {
                    "query": " ".join(keywords[:3]),  # Limit to first 3 keywords
                    "fields": ["rule.description^2", "full_log"],
                    "type": "best_fields"
                }
            },
            "size": 30,
            "sort": [{"@timestamp": {"order": "desc"}}]
        }
    
    def _generate_suggestions(self, intent: QueryIntent, original_query: str) -> List[str]:
        """Generate suggestions for improving the query."""
        suggestions = []
        
        # Suggest adding time constraints if none specified
        if not intent.time_range:
            suggestions.append("Consider adding a time range like 'recent', 'today', or 'last week'")
        
        # Suggest being more specific about rule types
        if not intent.rule_types and intent.confidence_scores.get('rule_type', 0) < 0.5:
            available_types = list(self.config.get('rule_types', {}).keys())
            suggestions.append(f"Try specifying a rule type: {', '.join(available_types[:3])}")
        
        # Suggest severity levels
        if intent.severity_levels == (0, 15) and intent.confidence_scores.get('severity', 0) < 0.5:
            suggestions.append("Add severity level like 'high', 'critical', 'medium', or 'low'")
        
        # Suggest more specific terms
        if len(intent.description_terms) == 0 and intent.keywords:
            suggestions.append("Try using more specific terms related to security events")
        
        return suggestions
    
    def get_supported_patterns(self) -> Dict[str, List[str]]:
        """Get information about supported query patterns."""
        return {
            "rule_types": list(self.config.get('rule_types', {}).keys()),
            "severity_levels": list(self.config.get('severity.mappings', {}).keys()),
            "time_expressions": [
                "recent", "today", "yesterday", "last hour", "last day", 
                "last week", "last month", "5 minutes ago", "2 hours ago"
            ],
            "example_queries": [
                "Show me recent authentication failures",
                "Find high severity web attacks from today", 
                "List all firewall rules with level > 5",
                "Get malware alerts from the last week",
                "Show rule 5503 events from yesterday"
            ]
        }


def translate_natural_language_query(query: str, rules_metadata: List[Any] = None, 
                                   config_manager: Optional[ConfigManager] = None,
                                   validate_output: bool = True) -> TranslationResult:
    """
    Convenience function to translate a natural language query.
    
    Args:
        query: Natural language query
        rules_metadata: List of WazuhRule objects (optional)
        config_manager: Configuration manager (optional)
        validate_output: Whether to validate generated queries
        
    Returns:
        TranslationResult with Elasticsearch DSL query
    """
    translator = NLPTranslator(config_manager)
    
    if rules_metadata:
        translator.initialize(rules_metadata)
    
    return translator.translate_query(query, validate_output)


if __name__ == "__main__":
    # Demo and testing
    logging.basicConfig(level=logging.INFO)
    
    # Mock rules for testing
    class MockRule:
        def __init__(self, id, description, rule_type, level):
            self.id = id
            self.description = description
            self.type = rule_type
            self.level = level
    
    mock_rules = [
        MockRule(5503, "User login failed", "authentication", 5),
        MockRule(31101, "Web server access denied", "web", 5),
        MockRule(40101, "Multiple authentication failures", "authentication", 10),
        MockRule(18101, "Malware detection alert", "malware", 12),
    ]
    
    # Test queries
    test_queries = [
        "Show me recent authentication failures",
        "Find high severity web attacks from today",
        "Get all rules with level > 8", 
        "List malware alerts from last week",
        "Show me rule 5503 events",
        "What happened yesterday with critical alerts?"
    ]
    
    print("NLP Translation Demo")
    print("=" * 50)
    
    translator = NLPTranslator()
    translator.initialize(mock_rules)
    
    for query in test_queries:
        print(f"\nQuery: {query}")
        print("-" * 30)
        
        result = translator.translate_query(query)
        
        print(f"Success: {result.success}")
        print(f"Confidence: {result.confidence:.2f}")
        
        if result.success:
            print(f"Generated Query:")
            import json
            print(json.dumps(result.query, indent=2))
            
            if result.validation_result and not result.validation_result.is_valid:
                print(f"Validation Issues: {len(result.validation_result.issues)}")
        
        if result.suggestions:
            print(f"Suggestions: {', '.join(result.suggestions)}")
        
        print()
