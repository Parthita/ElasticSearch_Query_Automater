"""
NLP Translation Module

This module provides natural language processing functionality to translate
user queries into Elasticsearch DSL queries for Wazuh data. It uses keyword
matching, configuration-based mappings, and confidence scoring to generate
accurate queries with fallback handling for unrecognized input.
"""

import logging
import re
import difflib
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
    query: Dict[str, Any]  # The elasticsearch_query
    confidence: float
    validation_result: Optional[ValidationResult] = None
    fallback_used: bool = False
    detected_intent: Dict[str, Any] = None
    suggestions: List[str] = None
    fallback_query: Optional[Dict[str, Any]] = None  # For backward compatibility
    
    @property
    def elasticsearch_query(self) -> Dict[str, Any]:
        """Alias for query field to maintain API compatibility."""
        return self.query
    
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
    # Enhanced entities
    agents: List[str] = None
    hosts: List[str] = None
    ip_addresses: List[str] = None
    ports: List[int] = None
    file_paths: List[str] = None
    boolean_logic: Dict[str, List[str]] = None  # must, should, must_not words
    
    def __post_init__(self):
        if not hasattr(self, 'confidence_scores') or self.confidence_scores is None:
            self.confidence_scores = {}
        if self.agents is None:
            self.agents = []
        if self.hosts is None:
            self.hosts = []
        if self.ip_addresses is None:
            self.ip_addresses = []
        if self.ports is None:
            self.ports = []
        if self.file_paths is None:
            self.file_paths = []
        if self.boolean_logic is None:
            self.boolean_logic = {"must": [], "should": [], "must_not": []}


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
        
        # Synonym dictionaries
        self.severity_synonyms = {}
        self.time_synonyms = {}
        self.rule_type_synonyms = {}
        
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
        
        severity_keywords = self.config.get_severity_keywords() or {}
        
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
        
        # Severity synonyms (extendable via config)
        self.severity_synonyms = {
            'informational': 'low', 'info': 'low', 'minor': 'low', 'notice': 'low',
            'warn': 'medium', 'warning': 'medium', 'moderate': 'medium',
            'important': 'high', 'serious': 'high',
            'urgent': 'critical', 'severe': 'critical', 'dangerous': 'critical', 'emergency': 'critical'
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
        
        # Time synonyms
        self.time_synonyms = {
            'now': 'recent', 'currently': 'recent', 'lately': 'recent',
            'today': 'today', 'yday': 'yesterday', 'tonight': 'today'
        }
        
        # Common query patterns
        self.keyword_patterns = {
            'rule_id': r'\b(?:rule|id)\s*[:#]?\s*(\d+)\b',
            'time_recent': r'\b(recent|recently|lately|now|currently)\b',
            'time_today': r'\b(today|current)\b',
            'time_yesterday': r'\byesterday\b',
            'time_last': r'\b(last|past|previous)\s+(hour|day|week|month|year|\d+\s+(minutes?|hours?|days?|weeks?|months?))\b',
            'time_this': r'\bthis\s+(hour|day|week|month|year)\b',
            'time_range': r'\b(\d+)\s+(minutes?|mins?|hours?|hrs?|days?|weeks?|months?)\s+ago\b',
            'time_dynamic': r'\b(within\s+the?\s+last|in\s+the?\s+last|last|past|previous)\s+(\d+)\s+(minutes?|mins?|hours?|hrs?|days?|weeks?|months?)\b',
            'show_all': r'\b(show|list|find|get|display)\s+(all|everything)\b',
            'count': r'\b(count|number|total)\s+of\b',
            'top': r'\b(top|first|last)\s*(\d+)?\b',
            'agent_from': r'\b(from|on|at)\s+(host|server|agent)?\s*([a-zA-Z0-9._-]+)\b',
            'boolean_and': r'\bAND\b|\band\b|\+|&&',
            'boolean_or': r'\bOR\b|\bor\b|\|\|',
            'boolean_not': r'\bNOT\b|\bnot\b|\-|!'
        }
        
        # Rule type synonyms from config
        self.rule_type_synonyms = {}
        for rtype, tcfg in self.config.get('rule_types', {}).items():
            if isinstance(tcfg, dict):
                for syn in tcfg.get('aliases', []) + tcfg.get('keywords', []):
                    self.rule_type_synonyms[syn.lower()] = rtype
    
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
            
            # Generate suggestions
            suggestions = self._generate_suggestions(intent, query, confidence)
            
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
                        suggestions=suggestions,
                        fallback_query=fallback_query
                    )
            
            return TranslationResult(
                success=bool(es_query),
                query=es_query or {},
                confidence=confidence,
                validation_result=validation_result,
                fallback_used=False,
                detected_intent=intent.confidence_scores,
                suggestions=suggestions
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
        """Parse natural language query to extract intent and entities."""
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
        
        # Agent/Host
        agents, hosts, agent_conf = self._extract_agent_host(query_lower)
        confidence_scores['agent_host'] = agent_conf
        
        # Boolean logic
        boolean_logic, bool_conf = self._extract_boolean_logic(query_lower)
        confidence_scores['boolean'] = bool_conf
        
        # Field-specifics
        ips, ports, paths, fs_conf = self._extract_field_specifics(query_lower)
        confidence_scores['fields'] = fs_conf
        
        # Keywords/Descriptions
        keywords, desc_terms, keyword_confidence = self._extract_keywords_and_descriptions(query_lower)
        confidence_scores['keywords'] = keyword_confidence
        
        return QueryIntent(
            rule_types=rule_types,
            severity_levels=(severity_min, severity_max),
            rule_ids=rule_ids,
            keywords=keywords,
            time_range=time_range,
            description_terms=desc_terms,
            confidence_scores=confidence_scores,
            agents=agents,
            hosts=hosts,
            ip_addresses=ips,
            ports=ports,
            file_paths=paths,
            boolean_logic=boolean_logic
        )
    
    def _extract_rule_types(self, query: str) -> Tuple[List[str], float]:
        """Extract rule types from query with fuzzy and synonym matching."""
        rule_types = []
        type_scores = defaultdict(float)
        
        # Get rule type keywords from config
        rule_types_config = self.config.get('rule_types', {})
        candidates = list(rule_types_config.keys())
        
        # Tokenize query
        words = re.findall(r'\b[\w.-]{3,}\b', query)
        
        # Direct and synonym matches
        for word in words:
            # Direct canonical match
            if word in candidates:
                type_scores[word] += 1.0
                continue
            # Synonym maps to canonical
            if word in self.rule_type_synonyms:
                canonical = self.rule_type_synonyms[word]
                type_scores[canonical] += 0.8
                continue
            # Fuzzy match
            close = difflib.get_close_matches(word, candidates, n=1, cutoff=0.85)
            if close:
                type_scores[close[0]] += 0.6
        
        # Keywords and aliases from config
        for rule_type, type_config in rule_types_config.items():
            if not isinstance(type_config, dict):
                continue
            keywords = [k.lower() for k in type_config.get('keywords', [])]
            aliases = [a.lower() for a in type_config.get('aliases', [])]
            for token in words:
                if re.search(rf'\b{re.escape(token)}\b', " ".join(keywords + aliases)):
                    type_scores[rule_type] += 0.5
        
        # Select types with significant scores
        threshold = self.config.get('nlp.type_detection_threshold', 0.5)
        for rule_type, score in type_scores.items():
            if score >= threshold:
                rule_types.append(rule_type)
        
        # Calculate confidence
        if type_scores:
            max_score = max(type_scores.values())
            confidence = min(0.5 + min(max_score, 1.5) / 3.0, 1.0)  # Slight boost
        else:
            confidence = 0.0
        
        return rule_types, confidence
    
    def _extract_severity_levels(self, query: str) -> Tuple[int, int, float]:
        """Extract severity level constraints with synonyms and fuzzy matching."""
        min_level, max_level = 0, 15
        confidence = 0.0
        
        # Normalize synonyms
        q_norm = query
        for syn, canonical in self.severity_synonyms.items():
            q_norm = re.sub(rf'\b{re.escape(syn)}\b', canonical, q_norm)
        
        # Check for named severity levels
        for severity_name, (sev_min, sev_max) in self.severity_patterns['mappings'].items():
            if re.search(rf'\b{re.escape(severity_name)}\b', q_norm):
                min_level = max(min_level, sev_min)
                max_level = min(max_level, sev_max)
                confidence += 0.6
        
        # Check for severity keywords map
        for keyword, level in self.severity_patterns['keywords'].items():
            if re.search(rf'\b{re.escape(keyword)}\b', q_norm):
                if 'high' in keyword or 'critical' in keyword:
                    min_level = max(min_level, level)
                elif 'low' in keyword:
                    max_level = min(max_level, level + 2)
                else:
                    min_level = max(min_level, level - 1)
                    max_level = min(max_level, level + 1)
                confidence += 0.5
        
        # Fuzzy fallback for tokens near severity names
        words = re.findall(r'\b\w{3,}\b', q_norm)
        candidates = list(self.severity_patterns['mappings'].keys()) + list(self.severity_patterns['keywords'].keys())
        for w in words:
            close = difflib.get_close_matches(w, candidates, n=1, cutoff=0.87)
            if close:
                kw = close[0]
                if kw in self.severity_patterns['mappings']:
                    sev_min, sev_max = self.severity_patterns['mappings'][kw]
                    min_level = max(min_level, sev_min)
                    max_level = min(max_level, sev_max)
                elif kw in self.severity_patterns['keywords']:
                    level = self.severity_patterns['keywords'][kw]
                    min_level = max(min_level, max(0, level - 1))
                    max_level = min(max_level, min(15, level + 1))
                confidence += 0.3
        
        # Explicit level constraints
        level_matches = re.findall(r'\blevel\s*([>=<]+)\s*(\d+)\b', q_norm)
        for operator, level_str in level_matches:
            level = int(level_str)
            if '>=' in operator or '>' in operator:
                min_level = max(min_level, level)
            elif '<=' in operator or '<' in operator:
                max_level = min(max_level, level)
            confidence += 0.9
        
        # Exact level
        exact_matches = re.findall(r'\blevel\s+(\d+)\b', q_norm)
        if exact_matches:
            level = int(exact_matches[0])
            min_level = max_level = level
            confidence = max(confidence, 0.95)
        
        return min_level, max_level, min(confidence, 1.0)
    
    def _extract_rule_ids(self, query: str) -> Tuple[List[int], float]:
        """Extract rule IDs from query."""
        rule_ids: List[int] = []
        confidence = 0.0
        
        id_matches = re.findall(self.keyword_patterns['rule_id'], query)
        for id_str in id_matches:
            try:
                rule_id = int(id_str)
                if rule_id in self.rules_by_id:
                    rule_ids.append(rule_id)
                    confidence = 1.0
                else:
                    # Accept unknown rule ids but lower confidence
                    rule_ids.append(rule_id)
                    confidence = max(confidence, 0.6)
            except ValueError:
                continue
        
        return rule_ids, confidence
    
    def _extract_agent_host(self, query: str) -> Tuple[List[str], List[str], float]:
        """Extract agent/host names from query."""
        agents = []
        hosts = []
        confidence = 0.0
        
        # Look for "from/on/at hostname" patterns
        agent_matches = re.findall(self.keyword_patterns['agent_from'], query)
        for match in agent_matches:
            # match: ('from', 'server', 'server-01')
            hostname = match[2] if len(match) > 2 else ''
            if hostname:
                # Determine if it looks more like agent or host
                if 'agent' in match[1].lower():
                    agents.append(hostname)
                else:
                    hosts.append(hostname)
                confidence = 0.8
        
        return agents, hosts, confidence
    
    def _extract_boolean_logic(self, query: str) -> Tuple[Dict[str, List[str]], float]:
        """Extract boolean logic operators and associated terms."""
        logic = {"must": [], "should": [], "must_not": []}
        confidence = 0.0
        
        # Split by AND/OR/NOT and classify terms
        parts = re.split(r'\s+(AND|OR|NOT)\s+', query, flags=re.IGNORECASE)
        current_op = "must"  # default
        
        for i, part in enumerate(parts):
            part = part.strip()
            if part.upper() == "AND":
                current_op = "must"
                confidence += 0.3
            elif part.upper() == "OR":
                current_op = "should" 
                confidence += 0.3
            elif part.upper() == "NOT":
                current_op = "must_not"
                confidence += 0.3
            elif part and not part.upper() in ["AND", "OR", "NOT"]:
                # Extract meaningful keywords from this part
                words = re.findall(r'\b[\w.-]{3,}\b', part.lower())
                for word in words:
                    if word not in {'show', 'find', 'get', 'list', 'display', 'from', 'on', 'at'}:
                        logic[current_op].append(word)
        
        return logic, min(confidence, 1.0)
    
    def _extract_field_specifics(self, query: str) -> Tuple[List[str], List[int], List[str], float]:
        """Extract IP addresses, ports, and file paths from query."""
        ips = []
        ports = []
        paths = []
        confidence = 0.0
        
        # IP address patterns
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ip_matches = re.findall(ip_pattern, query)
        for ip in ip_matches:
            ips.append(ip)
            confidence += 0.4
        
        # Port patterns (port 22, dst port 443, etc.)
        port_pattern = r'\b(?:port|src\s*port|dst\s*port|source\s*port|dest\s*port)\s*(\d{1,5})\b'
        port_matches = re.findall(port_pattern, query, re.IGNORECASE)
        for port_str in port_matches:
            try:
                port = int(port_str)
                if 1 <= port <= 65535:
                    ports.append(port)
                    confidence += 0.3
            except ValueError:
                continue
        
        # File path patterns (Unix and Windows)
        path_patterns = [
            r'/[\w\-./]+',  # Unix paths
            r'[A-Z]:\\[\w\\.-]+',  # Windows paths
            r'\\\\[\w\\.-]+',  # UNC paths
        ]
        
        for pattern in path_patterns:
            path_matches = re.findall(pattern, query)
            for path in path_matches:
                if len(path) > 3:  # Minimum meaningful path length
                    paths.append(path)
                    confidence += 0.2
        
        return ips, ports, paths, min(confidence, 1.0)
    
    def _extract_time_range(self, query: str) -> Tuple[Optional[Dict[str, str]], float]:
        """Extract time range from query including dynamic expressions."""
        time_range = None
        confidence = 0.0
        q = query
        
        # Normalize time synonyms
        for syn, canonical in self.time_synonyms.items():
            q = re.sub(rf'\b{re.escape(syn)}\b', canonical, q)
        
        # Check for predefined time patterns
        for pattern_name, pattern_config in self.time_patterns.items():
            if pattern_name == 'recent' and re.search(self.keyword_patterns['time_recent'], q):
                time_range = {'gte': pattern_config['relative']}
                confidence = 0.8
                break
            elif pattern_name == 'today' and re.search(self.keyword_patterns['time_today'], q):
                time_range = {'gte': pattern_config['relative']}
                confidence = 0.9
                break
            elif pattern_name.startswith('last_') and re.search(self.keyword_patterns['time_this'], q):
                # "this week/month" etc.
                time_range = {'gte': pattern_config['relative']}
                confidence = 0.6
                break
        
        # Yesterday explicit
        if re.search(self.keyword_patterns['time_yesterday'], q):
            time_range = {
                'gte': self.time_patterns['yesterday']['relative'],
                'lte': self.time_patterns['yesterday']['end']
            }
            confidence = max(confidence, 0.9)
        
        # Relative "X units ago"
        time_matches = re.findall(self.keyword_patterns['time_range'], q)
        if time_matches:
            amount, unit = time_matches[0]
            unit_map = {'minute': 'm', 'minutes': 'm', 'mins': 'm', 'hour': 'h', 'hours': 'h', 'hrs': 'h', 'day': 'd', 'days': 'd', 'week': 'w', 'weeks': 'w', 'month': 'M', 'months': 'M'}
            unit_char = unit_map.get(unit.rstrip('s'), unit_map.get(unit, 'd'))
            time_range = {'gte': f'now-{amount}{unit_char}'}
            confidence = max(confidence, 0.8)
        
        # Dynamic "last N units"
        dyn = re.findall(self.keyword_patterns['time_dynamic'], q)
        if dyn:
            amount = dyn[0][1]
            unit = dyn[0][2]
            unit_map = {'minute': 'm', 'minutes': 'm', 'mins': 'm', 'hour': 'h', 'hours': 'h', 'hrs': 'h', 'day': 'd', 'days': 'd', 'week': 'w', 'weeks': 'w', 'month': 'M', 'months': 'M'}
            unit_key = unit.lower()
            unit_char = unit_map.get(unit_key, 'd')
            time_range = {'gte': f'now-{amount}{unit_char}'}
            confidence = max(confidence, 0.85)
        
        return time_range, min(confidence, 1.0)
    
    def _extract_keywords_and_descriptions(self, query: str) -> Tuple[List[str], List[str], float]:
        """Extract keywords and description terms with fuzzy tolerance."""
        stop_words = set(self.config.get_stop_words())
        words = re.findall(r'\b[\w.-]{3,}\b', query.lower())
        query_terms = {'show', 'find', 'get', 'list', 'display', 'rule', 'rules', 'level', 'type', 'from', 'on', 'at', 'with', 'and', 'or', 'not'}
        keywords = []
        description_terms = []
        
        # Build a set of words from all rule descriptions for fuzzy lookup
        rule_vocab = set()
        for rule in self.rules:
            rule_vocab.update(re.findall(r'\b[\w.-]{3,}\b', rule.description.lower()))
        
        for word in words:
            if word in stop_words or word in query_terms or word.isdigit():
                continue
            keywords.append(word)
            # Fuzzy match against rule description vocabulary
            if word in rule_vocab:
                description_terms.append(word)
            else:
                close = difflib.get_close_matches(word, list(rule_vocab), n=1, cutoff=0.9)
                if close and close[0] not in description_terms:
                    description_terms.append(close[0])
        
        confidence = 0.0
        if keywords:
            matching_keywords = len([k for k in keywords if k in description_terms])
            confidence = (matching_keywords / len(keywords)) * 0.8 + (1 if matching_keywords >= 2 else 0) * 0.2
        
        return keywords, description_terms, confidence
    
    def _generate_elasticsearch_query(self, intent: QueryIntent) -> Dict[str, Any]:
        """
        Generate Elasticsearch DSL query from parsed intent.
        """
        query = {
            "query": {
                "bool": {
                    "must": [],
                    "filter": [],
                    "must_not": [],
                    "should": []
                }
            },
            "size": self.config.get('query_processing.default_results', 50)
        }
        boolq = query["query"]["bool"]
        
        # Rule type filters
        if intent.rule_types:
            if len(intent.rule_types) == 1:
                boolq["filter"].append({"term": {"rule.groups": intent.rule_types[0]}})
            else:
                boolq["filter"].append({"terms": {"rule.groups": intent.rule_types}})
        
        # Severity
        min_level, max_level = intent.severity_levels
        if min_level > 0 or max_level < 15:
            range_filter = {}
            if min_level > 0:
                range_filter["gte"] = min_level
            if max_level < 15:
                range_filter["lte"] = max_level
            boolq["filter"].append({"range": {"rule.level": range_filter}})
        
        # Rule IDs
        if intent.rule_ids:
            if len(intent.rule_ids) == 1:
                boolq["filter"].append({"term": {"rule.id": intent.rule_ids[0]}})
            else:
                boolq["filter"].append({"terms": {"rule.id": intent.rule_ids}})
        
        # Time range
        if intent.time_range:
            boolq["filter"].append({"range": {"@timestamp": intent.time_range}})
        
        # Agent/Host filters
        for name in (intent.agents or []) + (intent.hosts or []):
            # Prefer agent.name; also allow manager.name and location keyword match
            boolq["filter"].append({"term": {"agent.name": name}})
        
        # Field-specific IP filters across common fields
        if intent.ip_addresses:
            ip_should = []
            for ip in intent.ip_addresses:
                for field in ["decoder.srcip", "decoder.dstip", "data.srcip", "data.dstip", "agent.ip"]:
                    ip_should.append({"term": {field: ip}})
            if ip_should:
                boolq["should"].extend(ip_should)
        
        # Port filters
        if intent.ports:
            port_should = []
            for port in intent.ports:
                for field in ["decoder.srcport", "decoder.dstport", "data.srcport", "data.dstport"]:
                    port_should.append({"term": {field: port}})
            if port_should:
                boolq["should"].extend(port_should)
        
        # File path queries as phrase match in full_log and commandLine
        for path in intent.file_paths:
            boolq["must"].append({"multi_match": {"query": path, "type": "phrase", "fields": ["full_log", "data.win.eventdata.commandLine"]}})
        
        # Description/content search
        if intent.description_terms:
            if len(intent.description_terms) == 1:
                boolq["must"].append({"match": {"rule.description": intent.description_terms[0]}})
            else:
                boolq["must"].append({
                    "multi_match": {
                        "query": " ".join(intent.description_terms),
                        "fields": ["rule.description", "full_log"]
                    }
                })
        
        # Boolean logic terms
        for term in intent.boolean_logic.get("must", []):
            boolq["must"].append({"simple_query_string": {"query": term, "fields": ["rule.description", "full_log"]}})
        for term in intent.boolean_logic.get("should", []):
            boolq["should"].append({"simple_query_string": {"query": term, "fields": ["rule.description", "full_log"]}})
        for term in intent.boolean_logic.get("must_not", []):
            boolq["must_not"].append({"simple_query_string": {"query": term, "fields": ["rule.description", "full_log"]}})
        
        # If nothing specified, use match_all
        if not any([boolq["must"], boolq["filter"], boolq["should"], boolq["must_not"]]):
            query["query"] = {"match_all": {}}
        else:
            # Prefer should minimum_should_match if we added shoulds
            if boolq["should"]:
                boolq["minimum_should_match"] = 1
        
        # Sort
        query["sort"] = [{"@timestamp": {"order": "desc"}}]
        return query
    
    def _calculate_confidence(self, intent: QueryIntent, original_query: str) -> float:
        """Calculate overall confidence score for the translation with multiple factors."""
        scores = list(intent.confidence_scores.values())
        base = sum(scores) / len(scores) if scores else 0.0
        
        # Entity presence boosts
        if intent.rule_types:
            base += 0.15
        if intent.time_range:
            base += 0.1
        if intent.severity_levels != (0, 15):
            base += 0.1
        if intent.rule_ids:
            base += 0.2
        if intent.ip_addresses:
            base += 0.15
        if intent.ports:
            base += 0.05
        if intent.agents or intent.hosts:
            base += 0.1
        if intent.description_terms:
            base += 0.05
        
        # Boolean logic presence small boost
        if any(intent.boolean_logic.values()):
            base += 0.05
        
        # Normalize and clamp
        confidence = max(0.0, min(base, 1.0))
        
        # Multiple strong signals boost
        strong = 0
        strong += 1 if intent.rule_types else 0
        strong += 1 if intent.time_range else 0
        strong += 1 if intent.rule_ids else 0
        if strong >= 2:
            confidence = min(1.0, confidence + 0.1)
        
        # Short query penalty
        if len(original_query.split()) < 3:
            confidence *= 0.85
        
        return min(confidence, 1.0)
    
    def _generate_fallback_query(self, query: str, intent: QueryIntent) -> Optional[Dict[str, Any]]:
        """Generate a fallback query for low-confidence translations."""
        # Prefer field-specific hints even in fallback
        if intent.ip_addresses:
            return {
                "query": {
                    "bool": {
                        "should": [
                            {"term": {"decoder.srcip": intent.ip_addresses[0]}},
                            {"term": {"decoder.dstip": intent.ip_addresses[0]}},
                            {"term": {"data.srcip": intent.ip_addresses[0]}},
                            {"term": {"data.dstip": intent.ip_addresses[0]}}
                        ],
                        "minimum_should_match": 1
                    }
                },
                "size": 30,
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
        
        # Simple keyword search across all fields
        keywords = intent.keywords or re.findall(r'\b\w{4,}\b', query.lower())
        
        if not keywords:
            return {
                "query": {"match_all": {}},
                "filter": {"range": {"@timestamp": {"gte": "now-1h"}}},
                "size": 20,
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
        
        return {
            "query": {
                "multi_match": {
                    "query": " ".join(keywords[:4]),
                    "fields": ["rule.description^2", "full_log"],
                    "type": "best_fields"
                }
            },
            "size": 30,
            "sort": [{"@timestamp": {"order": "desc"}}]
        }
    
    def _generate_suggestions(self, intent: QueryIntent, original_query: str, confidence: float = 0.0) -> List[str]:
        """Generate suggestions for improving the query."""
        suggestions = []
        
        # Base suggestions for common missing elements
        if not intent.time_range:
            suggestions.append("Consider adding a time range like 'recent', 'today', or 'last week'")
        
        if not intent.rule_types and intent.confidence_scores.get('rule_type', 0) < 0.5:
            available_types = list(self.config.get('rule_types', {}).keys())
            if available_types:
                suggestions.append(f"Try specifying a rule type like: {', '.join(available_types[:3])}")
        
        if intent.severity_levels == (0, 15) and intent.confidence_scores.get('severity', 0) < 0.5:
            suggestions.append("Add severity level such as 'high', 'critical', 'medium', or 'low'")
        
        if len(intent.description_terms) == 0 and intent.keywords:
            suggestions.append("Use more specific terms related to the event description")
        
        # Advanced suggestions for low confidence queries
        if confidence < self.good_confidence:
            if intent.ip_addresses and len(intent.ip_addresses) > 1:
                suggestions.append("Consider narrowing down to a single IP if possible")
            
            # Boolean guidance
            if not any(intent.boolean_logic.values()) and len(intent.keywords) >= 3:
                suggestions.append("Use boolean operators AND/OR/NOT to combine terms, e.g. 'login AND failure NOT success'")
            
            # Field-specific help for very low confidence
            if confidence < self.min_confidence:
                if not intent.ip_addresses:
                    suggestions.append("You can filter by IP using phrases like 'from 10.0.0.5' or 'src ip 10.0.0.5'")
                if not intent.ports:
                    suggestions.append("You can specify ports, e.g. 'port 22' or 'dst port 443'")
                if not intent.agents and not intent.hosts:
                    suggestions.append("You can specify agents/hosts like 'from server-01' or 'on host web-server'")
        
        return suggestions
    
    def get_supported_patterns(self) -> Dict[str, List[str]]:
        """Get information about supported query patterns."""
        return {
            "rule_types": list(self.config.get('rule_types', {}).keys()),
            "severity_levels": list(self.config.get('severity.mappings', {}).keys()),
            "time_expressions": [
                "recent", "today", "yesterday", "last hour", "last day", 
                "last week", "last month", "5 minutes ago", "2 hours ago",
                "last 24 hours", "past 7 days"
            ],
            "example_queries": [
                "Show me recent authentication failures",
                "Find high severity web attacks from today", 
                "List all firewall rules with level > 5",
                "Get malware alerts from the last week",
                "Show rule 5503 events from yesterday",
                "Events from server-01 in the last 2 hours"
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
