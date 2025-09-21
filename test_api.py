#!/usr/bin/env python3
"""
Comprehensive test suite for the Wazuh NLP Flask API.

This test suite covers:
- Endpoint functionality
- Input validation
- Error handling
- Translation quality
- Various rule scenarios
"""

import json
import pytest
import subprocess
import time
import requests
from pathlib import Path

# Test configuration
API_BASE_URL = "http://127.0.0.1:5000"
SAMPLE_RULES_FILE = "sample_rules.json"


class TestAPI:
    """Test the Flask API endpoints and functionality."""
    
    @classmethod
    def setup_class(cls):
        """Start the Flask server for testing."""
        print("Starting Flask server for testing...")
        cls.server_process = subprocess.Popen(
            ["python", "main.py", "--host", "127.0.0.1", "--port", "5000", "--log-level", "ERROR"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        # Wait for server to start
        time.sleep(3)
        
        # Load sample rules
        with open(SAMPLE_RULES_FILE, 'r') as f:
            cls.sample_rules = json.load(f)['rules']
    
    @classmethod
    def teardown_class(cls):
        """Stop the Flask server after testing."""
        print("Stopping Flask server...")
        cls.server_process.terminate()
        cls.server_process.wait()

    def test_health_endpoint(self):
        """Test the health check endpoint."""
        response = requests.get(f"{API_BASE_URL}/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "Wazuh NLP Translation API"
        assert "version" in data

    def test_translate_endpoint_basic(self):
        """Test basic translation functionality."""
        payload = {
            "query": "Show me authentication failures",
            "rules": [
                {"id": 5503, "description": "User login failed", "type": "authentication", "level": 5}
            ]
        }
        
        response = requests.post(
            f"{API_BASE_URL}/translate",
            headers={"Content-Type": "application/json"},
            json=payload
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Check required fields
        assert data["status"] == "success"
        assert "elasticsearch_query" in data
        assert "confidence" in data
        assert isinstance(data["confidence"], (int, float))
        assert 0.0 <= data["confidence"] <= 1.0
        
        # Check Elasticsearch query structure
        es_query = data["elasticsearch_query"]
        assert "query" in es_query
        assert "size" in es_query
        assert "sort" in es_query

    def test_single_authentication_rule(self):
        """Test translation with a single authentication rule."""
        auth_rules = [rule for rule in self.sample_rules if rule["type"] == "authentication"][:1]
        
        payload = {
            "query": "Show me recent login failures",
            "rules": auth_rules
        }
        
        response = requests.post(
            f"{API_BASE_URL}/translate",
            headers={"Content-Type": "application/json"},
            json=payload
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["confidence"] > 0.5  # Should have good confidence for authentication queries

    def test_multiple_same_type_rules(self):
        """Test translation with multiple rules of the same type."""
        auth_rules = [rule for rule in self.sample_rules if rule["type"] == "authentication"]
        
        payload = {
            "query": "Find authentication events from today",
            "rules": auth_rules
        }
        
        response = requests.post(
            f"{API_BASE_URL}/translate",
            headers={"Content-Type": "application/json"},
            json=payload
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        
        # Should detect authentication type
        es_query = data["elasticsearch_query"]
        query_str = json.dumps(es_query).lower()
        assert "authentication" in query_str

    def test_mixed_rule_types(self):
        """Test translation with mixed rule types."""
        mixed_rules = [
            next(rule for rule in self.sample_rules if rule["type"] == "authentication"),
            next(rule for rule in self.sample_rules if rule["type"] == "system"),
            next(rule for rule in self.sample_rules if rule["type"] == "security")
        ]
        
        payload = {
            "query": "Show me security events",
            "rules": mixed_rules
        }
        
        response = requests.post(
            f"{API_BASE_URL}/translate",
            headers={"Content-Type": "application/json"},
            json=payload
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"

    def test_high_severity_filter(self):
        """Test translation with severity level filtering."""
        high_severity_rules = [rule for rule in self.sample_rules if rule["level"] >= 10]
        
        payload = {
            "query": "Show me critical alerts with high severity",
            "rules": high_severity_rules
        }
        
        response = requests.post(
            f"{API_BASE_URL}/translate",
            headers={"Content-Type": "application/json"},
            json=payload
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        
        # Should include severity filtering
        es_query = data["elasticsearch_query"]
        query_str = json.dumps(es_query)
        assert "level" in query_str or "range" in query_str

    def test_specific_rule_query(self):
        """Test translation for specific rule ID."""
        payload = {
            "query": "Show me rule 5503 events",
            "rules": self.sample_rules
        }
        
        response = requests.post(
            f"{API_BASE_URL}/translate",
            headers={"Content-Type": "application/json"},
            json=payload
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        
        # Should include rule ID filtering
        es_query = data["elasticsearch_query"]
        query_str = json.dumps(es_query)
        assert "5503" in query_str

    def test_time_based_query(self):
        """Test translation with time-based filtering."""
        payload = {
            "query": "Show me events from the last hour",
            "rules": self.sample_rules[:5]
        }
        
        response = requests.post(
            f"{API_BASE_URL}/translate",
            headers={"Content-Type": "application/json"},
            json=payload
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        
        # Should include time filtering
        es_query = data["elasticsearch_query"]
        query_str = json.dumps(es_query)
        assert "@timestamp" in query_str and ("now-" in query_str or "gte" in query_str)

    # Error handling tests
    
    def test_missing_query_field(self):
        """Test error handling for missing query field."""
        payload = {
            "rules": [{"id": 1, "description": "test", "type": "test", "level": 1}]
        }
        
        response = requests.post(
            f"{API_BASE_URL}/translate",
            headers={"Content-Type": "application/json"},
            json=payload
        )
        
        assert response.status_code == 400
        data = response.json()
        assert data["status"] == "error"
        assert "query" in data["message"].lower()

    def test_missing_rules_field(self):
        """Test error handling for missing rules field."""
        payload = {
            "query": "test query"
        }
        
        response = requests.post(
            f"{API_BASE_URL}/translate",
            headers={"Content-Type": "application/json"},
            json=payload
        )
        
        assert response.status_code == 400
        data = response.json()
        assert data["status"] == "error"
        assert "rules" in data["message"].lower()

    def test_empty_rules_array(self):
        """Test error handling for empty rules array."""
        payload = {
            "query": "test query",
            "rules": []
        }
        
        response = requests.post(
            f"{API_BASE_URL}/translate",
            headers={"Content-Type": "application/json"},
            json=payload
        )
        
        assert response.status_code == 400
        data = response.json()
        assert data["status"] == "error"
        assert "empty" in data["message"].lower()

    def test_invalid_rule_structure(self):
        """Test error handling for invalid rule structure."""
        payload = {
            "query": "test query",
            "rules": [{"id": 1, "description": "test"}]  # Missing type and level
        }
        
        response = requests.post(
            f"{API_BASE_URL}/translate",
            headers={"Content-Type": "application/json"},
            json=payload
        )
        
        assert response.status_code == 400
        data = response.json()
        assert data["status"] == "error"
        assert "missing" in data["message"].lower()

    def test_invalid_rule_level(self):
        """Test error handling for invalid rule level."""
        payload = {
            "query": "test query",
            "rules": [{"id": 1, "description": "test", "type": "test", "level": 99}]
        }
        
        response = requests.post(
            f"{API_BASE_URL}/translate",
            headers={"Content-Type": "application/json"},
            json=payload
        )
        
        assert response.status_code == 400
        data = response.json()
        assert data["status"] == "error"
        assert "level" in data["message"].lower()

    def test_wrong_content_type(self):
        """Test error handling for wrong content type."""
        response = requests.post(
            f"{API_BASE_URL}/translate",
            headers={"Content-Type": "text/plain"},
            data="not json"
        )
        
        assert response.status_code == 400
        data = response.json()
        assert data["status"] == "error"
        assert "json" in data["message"].lower()

    def test_wrong_http_method(self):
        """Test error handling for wrong HTTP method."""
        response = requests.get(f"{API_BASE_URL}/translate")
        
        assert response.status_code == 405
        data = response.json()
        assert data["status"] == "error"
        assert "method" in data["message"].lower()

    def test_nonexistent_endpoint(self):
        """Test error handling for non-existent endpoint."""
        response = requests.get(f"{API_BASE_URL}/nonexistent")
        
        assert response.status_code == 404
        data = response.json()
        assert data["status"] == "error"
        assert "not found" in data["message"].lower()

    # Translation quality tests

    def test_keyword_matching(self):
        """Test that queries with specific keywords are translated correctly."""
        test_cases = [
            ("authentication failures", "authentication"),
            ("system errors", "system"),
            ("security alerts", "security"),
            ("rootkit detection", "rootcheck"),
            ("configuration issues", "sca")
        ]
        
        for query_text, expected_type in test_cases:
            type_rules = [rule for rule in self.sample_rules if rule["type"] == expected_type]
            if not type_rules:
                continue
                
            payload = {
                "query": f"Show me {query_text}",
                "rules": type_rules + self.sample_rules[:3]  # Add some mixed rules
            }
            
            response = requests.post(
                f"{API_BASE_URL}/translate",
                headers={"Content-Type": "application/json"},
                json=payload
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert data["confidence"] > 0.3  # Should have reasonable confidence

    def test_all_rule_types(self):
        """Test translation with all available rule types."""
        all_types = list(set(rule["type"] for rule in self.sample_rules))
        
        for rule_type in all_types:
            type_rules = [rule for rule in self.sample_rules if rule["type"] == rule_type]
            
            payload = {
                "query": f"Show me {rule_type} events from today",
                "rules": type_rules
            }
            
            response = requests.post(
                f"{API_BASE_URL}/translate",
                headers={"Content-Type": "application/json"},
                json=payload
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert isinstance(data["elasticsearch_query"], dict)

    def test_confidence_scoring(self):
        """Test that confidence scores are reasonable."""
        test_cases = [
            ("Show me authentication failures", "authentication", True),  # Should be high confidence
            ("Find some random stuff", "authentication", False),  # Should be low confidence
            ("Get rule 5503 events", "authentication", True),  # Specific rule should be high
        ]
        
        for query_text, rule_type, expect_high in test_cases:
            type_rules = [rule for rule in self.sample_rules if rule["type"] == rule_type]
            
            payload = {
                "query": query_text,
                "rules": type_rules
            }
            
            response = requests.post(
                f"{API_BASE_URL}/translate",
                headers={"Content-Type": "application/json"},
                json=payload
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            
            if expect_high:
                assert data["confidence"] > 0.5, f"Expected high confidence for '{query_text}'"
            else:
                assert data["confidence"] <= 0.7, f"Expected lower confidence for '{query_text}'"


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v", "-s"])
