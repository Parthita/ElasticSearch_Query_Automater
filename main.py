#!/usr/bin/env python3
"""
Wazuh NLP Query Translation Flask API

Provides a REST API for translating natural language queries into Elasticsearch DSL
queries for Wazuh data, with validation and confidence scoring.
"""

import logging
import sys
import traceback
from pathlib import Path
from typing import Dict, Any, List
from dataclasses import asdict

from flask import Flask, request, jsonify

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from config import ConfigManager
from nlp_translate import NLPTranslator, TranslationResult
from load_rules import WazuhRule
from elasticsearch_validator import validate_elasticsearch_query, ValidationResult

# Initialize Flask app
app = Flask(__name__)

# Global variables for initialized components
config_manager = None
nlp_translator = None

def setup_logging(log_level: str = "INFO") -> None:
    """Setup logging configuration."""
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )


def initialize_system() -> None:
    """Initialize the system components."""
    global config_manager, nlp_translator
    
    logger = logging.getLogger(__name__)
    logger.info("Initializing Wazuh NLP Translation API...")
    
    try:
        # Load configuration
        config_manager = ConfigManager()
        config_manager.load_config()
        logger.info("Configuration loaded successfully")
        
        # Initialize NLP translator
        nlp_translator = NLPTranslator()
        logger.info("NLP Translator initialized successfully")
        
    except Exception as e:
        logger.error(f"System initialization failed: {e}")
        raise


def validate_request_data(data: Dict[str, Any]) -> tuple[bool, str]:
    """Validate the incoming request data."""
    
    # Check required fields
    if not isinstance(data, dict):
        return False, "Request body must be a JSON object"
    
    if 'query' not in data:
        return False, "Missing required field: 'query'"
    
    if 'rules' not in data:
        return False, "Missing required field: 'rules'"
    
    # Validate query
    if not isinstance(data['query'], str) or not data['query'].strip():
        return False, "Field 'query' must be a non-empty string"
    
    # Validate rules
    if not isinstance(data['rules'], list):
        return False, "Field 'rules' must be a list"
    
    if len(data['rules']) == 0:
        return False, "Field 'rules' cannot be empty"
    
    # Validate rule structure
    for i, rule in enumerate(data['rules']):
        if not isinstance(rule, dict):
            return False, f"Rule at index {i} must be an object"
        
        required_fields = ['id', 'description', 'type', 'level']
        for field in required_fields:
            if field not in rule:
                return False, f"Rule at index {i} missing required field: '{field}'"
        
        # Validate field types
        if not isinstance(rule['id'], (str, int)):
            return False, f"Rule at index {i}: 'id' must be string or integer"
        
        if not isinstance(rule['description'], str):
            return False, f"Rule at index {i}: 'description' must be string"
            
        if not isinstance(rule['type'], str):
            return False, f"Rule at index {i}: 'type' must be string"
            
        if not isinstance(rule['level'], int) or rule['level'] < 0 or rule['level'] > 15:
            return False, f"Rule at index {i}: 'level' must be integer between 0-15"
    
    return True, ""


def convert_rules_to_wazuh_objects(rules_data: List[Dict[str, Any]]) -> List[WazuhRule]:
    """Convert rule dictionaries to WazuhRule objects."""
    wazuh_rules = []
    
    for rule_data in rules_data:
        rule = WazuhRule(
            id=int(rule_data['id']) if isinstance(rule_data['id'], str) else rule_data['id'],
            description=rule_data['description'],
            type=rule_data['type'],
            level=rule_data['level']
        )
        wazuh_rules.append(rule)
    
    return wazuh_rules


@app.route('/translate', methods=['POST'])
def translate_query():
    """
    Translate natural language query to Elasticsearch DSL.
    
    Expected JSON body:
    {
        "query": "natural language query string",
        "rules": [
            {
                "id": "rule_id",
                "description": "Rule description",
                "type": "rule_type",
                "level": 10
            },
            ...
        ]
    }
    
    Returns:
    {
        "status": "success|error",
        "elasticsearch_query": {...},
        "confidence": 0.85,
        "validation": {...},
        "message": "optional message"
    }
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Parse JSON request
        if not request.is_json:
            return jsonify({
                'status': 'error',
                'message': 'Content-Type must be application/json'
            }), 400
        
        data = request.get_json()
        
        # Validate request data
        is_valid, error_message = validate_request_data(data)
        if not is_valid:
            logger.warning(f"Invalid request: {error_message}")
            return jsonify({
                'status': 'error',
                'message': error_message
            }), 400
        
        query_text = data['query']
        rules_data = data['rules']
        
        logger.info(f"Processing translation request for query: {query_text}")
        logger.debug(f"Received {len(rules_data)} rules")
        
        # Convert rules data to WazuhRule objects
        try:
            wazuh_rules = convert_rules_to_wazuh_objects(rules_data)
        except Exception as e:
            logger.error(f"Error converting rules: {e}")
            return jsonify({
                'status': 'error',
                'message': f'Error processing rules: {str(e)}'
            }), 400
        
        # Initialize translator with provided rules
        nlp_translator.initialize(wazuh_rules)
        
        # Translate query
        try:
            translation_result: TranslationResult = nlp_translator.translate_query(query_text)
        except Exception as e:
            logger.error(f"Translation error: {e}")
            return jsonify({
                'status': 'error',
                'message': f'Translation failed: {str(e)}'
            }), 500
        
        # Validate the generated Elasticsearch query
        try:
            validation_result: ValidationResult = validate_elasticsearch_query(
                translation_result.query, 
                dry_run=True
            )
            validation_dict = validation_result.to_dict()
        except Exception as e:
            logger.warning(f"Validation error: {e}")
            # If validation fails, still return the query but note the validation issue
            validation_dict = {
                'is_valid': False,
                'issues': [{'message': f'Validation error: {str(e)}', 'severity': 'error'}],
                'suggestions': []
            }
        
        # Prepare response
        response = {
            'status': 'success',
            'elasticsearch_query': translation_result.query,
            'confidence': translation_result.confidence,
            'validation': validation_dict,
        }
        
        # Add optional fields if present
        if hasattr(translation_result, 'fallback_used') and translation_result.fallback_used:
            response['fallback_used'] = True
        
        if translation_result.suggestions:
            response['suggestions'] = translation_result.suggestions
        
        logger.info(f"Successfully processed query with confidence {translation_result.confidence}")
        
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Unexpected error in /translate endpoint: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        
        return jsonify({
            'status': 'error',
            'message': 'Internal server error occurred'
        }), 500


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'service': 'Wazuh NLP Translation API',
        'version': '1.0.0'
    }), 200


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({
        'status': 'error',
        'message': 'Endpoint not found'
    }), 404


@app.errorhandler(405)
def method_not_allowed(error):
    """Handle 405 errors."""
    return jsonify({
        'status': 'error',
        'message': 'Method not allowed'
    }), 405


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger = logging.getLogger(__name__)
    logger.error(f"Internal server error: {error}")
    
    return jsonify({
        'status': 'error',
        'message': 'Internal server error'
    }), 500


def main():
    """Main entry point for Flask API."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Wazuh NLP Translation API')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to (default: 5000)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], 
                        default='INFO', help='Set logging level (default: INFO)')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_level)
    logger = logging.getLogger(__name__)
    
    try:
        # Initialize system
        initialize_system()
        
        # Start Flask app
        logger.info(f"Starting Wazuh NLP Translation API on {args.host}:{args.port}")
        logger.info(f"Debug mode: {args.debug}")
        
        app.run(
            host=args.host,
            port=args.port,
            debug=args.debug
        )
        
    except KeyboardInterrupt:
        logger.info("API server stopped by user")
    except Exception as e:
        logger.error(f"Failed to start API server: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
