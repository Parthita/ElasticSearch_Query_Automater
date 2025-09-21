#!/usr/bin/env python3
"""
Interactive manual testing script for the Wazuh NLP Flask API.

This script provides an interactive interface to test the API with sample data,
allowing users to experiment with different queries and rule combinations.
"""

import json
import sys
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path
from typing import List, Dict, Any


class APITester:
    """Interactive API testing class."""
    
    def __init__(self, base_url: str = "http://127.0.0.1:5000"):
        self.base_url = base_url
        self.sample_rules = self.load_sample_rules()
        self.test_queries = self.load_test_queries()
    
    def load_sample_rules(self) -> List[Dict[str, Any]]:
        """Load sample rules from JSON file."""
        rules_file = Path("sample_rules.json")
        if not rules_file.exists():
            print(f"Warning: {rules_file} not found. Using minimal rule set.")
            return [
                {"id": 5503, "description": "User login failed", "type": "authentication", "level": 5},
                {"id": 1001, "description": "System boot completed", "type": "system", "level": 2},
                {"id": 2001, "description": "Privilege escalation attempt", "type": "security", "level": 13}
            ]
        
        try:
            with open(rules_file, 'r') as f:
                data = json.load(f)
                return data.get('rules', [])
        except Exception as e:
            print(f"Error loading sample rules: {e}")
            return []
    
    def load_test_queries(self) -> List[str]:
        """Load test queries from text file."""
        queries_file = Path("test_queries.txt")
        if not queries_file.exists():
            print(f"Warning: {queries_file} not found. Using default queries.")
            return [
                "Show me recent authentication failures",
                "Find system errors from today",
                "List critical security events",
                "Get all events with high severity"
            ]
        
        try:
            queries = []
            with open(queries_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        queries.append(line)
            return queries
        except Exception as e:
            print(f"Error loading test queries: {e}")
            return []
    
    def make_api_request(self, endpoint: str, method: str = "GET", data: Dict = None) -> Dict:
        """Make HTTP request to the API."""
        url = f"{self.base_url}{endpoint}"
        
        try:
            if method == "GET":
                with urllib.request.urlopen(url) as response:
                    return json.loads(response.read().decode())
            
            elif method == "POST":
                headers = {'Content-Type': 'application/json'}
                request_data = json.dumps(data).encode('utf-8')
                
                req = urllib.request.Request(url, data=request_data, headers=headers)
                with urllib.request.urlopen(req) as response:
                    return json.loads(response.read().decode())
        
        except urllib.error.HTTPError as e:
            try:
                error_data = json.loads(e.read().decode())
                return {
                    "status": "error",
                    "message": error_data.get("message", "HTTP Error"),
                    "status_code": e.code
                }
            except:
                return {
                    "status": "error", 
                    "message": f"HTTP {e.code}: {e.reason}",
                    "status_code": e.code
                }
        
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def test_health_endpoint(self):
        """Test the health check endpoint."""
        print("\n=== Testing Health Endpoint ===")
        response = self.make_api_request("/health")
        
        if response.get("status") == "healthy":
            print("✅ Health check passed!")
            print(f"Service: {response.get('service')}")
            print(f"Version: {response.get('version')}")
        else:
            print("❌ Health check failed!")
            print(f"Response: {response}")
        
        return response.get("status") == "healthy"
    
    def test_translate_endpoint(self, query: str, rules: List[Dict] = None):
        """Test the translate endpoint with a specific query."""
        if rules is None:
            rules = self.sample_rules
        
        payload = {
            "query": query,
            "rules": rules
        }
        
        response = self.make_api_request("/translate", method="POST", data=payload)
        return response
    
    def print_translation_result(self, query: str, response: Dict):
        """Print formatted translation results."""
        print(f"\n🔍 Query: {query}")
        print("-" * 50)
        
        if response.get("status") == "success":
            confidence = response.get("confidence", 0)
            print(f"✅ Status: Success")
            print(f"📊 Confidence: {confidence:.3f} ({confidence*100:.1f}%)")
            
            # Show Elasticsearch query (truncated)
            es_query = response.get("elasticsearch_query", {})
            query_str = json.dumps(es_query, indent=2)
            if len(query_str) > 500:
                query_str = query_str[:500] + "..."
            
            print(f"🔎 Elasticsearch Query:")
            print(query_str)
            
            # Show validation info if available
            validation = response.get("validation", {})
            if validation:
                issues = validation.get("issues", [])
                if issues:
                    print(f"⚠️  Validation Issues: {len(issues)}")
                else:
                    print("✅ Query validation: OK")
        
        else:
            print(f"❌ Status: Error")
            print(f"💥 Message: {response.get('message')}")
            if "status_code" in response:
                print(f"🔢 HTTP Status: {response['status_code']}")
    
    def interactive_query_test(self):
        """Interactive query testing mode."""
        print("\n=== Interactive Query Testing ===")
        print("Enter your queries (type 'quit' to exit, 'help' for commands)")
        
        while True:
            try:
                query = input("\n🔍 Query> ").strip()
                
                if query.lower() in ['quit', 'exit', 'q']:
                    break
                
                elif query.lower() == 'help':
                    self.show_help()
                    continue
                
                elif query.lower() == 'examples':
                    self.show_example_queries()
                    continue
                
                elif query.lower().startswith('rules '):
                    self.show_rules_by_type(query[6:].strip())
                    continue
                
                elif not query:
                    continue
                
                # Test the query
                response = self.test_translate_endpoint(query)
                self.print_translation_result(query, response)
                
            except KeyboardInterrupt:
                print("\n👋 Goodbye!")
                break
            except EOFError:
                break
    
    def show_help(self):
        """Show help information."""
        print("\n=== Help ===")
        print("Commands:")
        print("  help      - Show this help")
        print("  examples  - Show example queries")
        print("  rules <type> - Show rules of specific type")
        print("  quit/exit - Exit the program")
        print("\nExample queries:")
        print("  'Show me authentication failures'")
        print("  'Find critical security events'")
        print("  'List system errors from today'")
    
    def show_example_queries(self):
        """Show example queries organized by category."""
        print("\n=== Example Queries ===")
        
        categories = {
            "Authentication": [
                "Show me recent authentication failures",
                "Find all login failures from today",
                "List failed login attempts with high severity"
            ],
            "System": [
                "Find system errors from yesterday", 
                "Show me kernel errors",
                "List high CPU usage alerts"
            ],
            "Security": [
                "Find privilege escalation attempts",
                "Show critical security events",
                "List suspicious process executions"
            ],
            "Specific Rules": [
                "Show rule 5503 events",
                "Find events matching rule 4003",
                "Get rule 2001 occurrences"
            ]
        }
        
        for category, queries in categories.items():
            print(f"\n{category}:")
            for query in queries:
                print(f"  • {query}")
    
    def show_rules_by_type(self, rule_type: str):
        """Show rules of a specific type."""
        if not rule_type:
            # Show all types
            types = set(rule["type"] for rule in self.sample_rules)
            print(f"\nAvailable rule types: {', '.join(sorted(types))}")
            return
        
        matching_rules = [rule for rule in self.sample_rules if rule["type"] == rule_type.lower()]
        
        if not matching_rules:
            print(f"\nNo rules found for type: {rule_type}")
            return
        
        print(f"\n=== {rule_type.title()} Rules ===")
        for rule in matching_rules:
            print(f"  ID: {rule['id']:<6} Level: {rule['level']:<2} - {rule['description']}")
    
    def run_batch_tests(self):
        """Run batch tests with predefined scenarios."""
        print("\n=== Running Batch Tests ===")
        
        test_scenarios = [
            {
                "name": "Single Authentication Rule",
                "query": "Show me authentication failures",
                "rules": [rule for rule in self.sample_rules if rule["type"] == "authentication"][:1]
            },
            {
                "name": "Multiple Security Rules",
                "query": "Find critical security events",
                "rules": [rule for rule in self.sample_rules if rule["type"] == "security"]
            },
            {
                "name": "Mixed Rule Types",
                "query": "Show me high severity alerts",
                "rules": [rule for rule in self.sample_rules if rule["level"] >= 10]
            },
            {
                "name": "Specific Rule ID",
                "query": "Get rule 5503 events",
                "rules": self.sample_rules
            },
            {
                "name": "Time-based Query",
                "query": "Show events from the last hour",
                "rules": self.sample_rules[:5]
            }
        ]
        
        for i, scenario in enumerate(test_scenarios, 1):
            print(f"\n[{i}/{len(test_scenarios)}] {scenario['name']}")
            response = self.test_translate_endpoint(scenario['query'], scenario['rules'])
            
            if response.get("status") == "success":
                confidence = response.get("confidence", 0)
                print(f"✅ Success (Confidence: {confidence:.3f})")
            else:
                print(f"❌ Failed: {response.get('message')}")
    
    def run_error_tests(self):
        """Run error handling tests."""
        print("\n=== Testing Error Handling ===")
        
        error_tests = [
            {
                "name": "Missing Query Field",
                "data": {"rules": [{"id": 1, "description": "test", "type": "test", "level": 1}]}
            },
            {
                "name": "Empty Rules Array", 
                "data": {"query": "test", "rules": []}
            },
            {
                "name": "Invalid Rule Level",
                "data": {"query": "test", "rules": [{"id": 1, "description": "test", "type": "test", "level": 99}]}
            }
        ]
        
        for i, test in enumerate(error_tests, 1):
            print(f"\n[{i}/{len(error_tests)}] {test['name']}")
            response = self.make_api_request("/translate", method="POST", data=test['data'])
            
            if response.get("status") == "error":
                print(f"✅ Error handled correctly: {response.get('message')}")
            else:
                print(f"❌ Expected error, got: {response}")
    
    def main_menu(self):
        """Show main menu and handle user choices."""
        while True:
            print("\n" + "="*60)
            print("🔧 Wazuh NLP API Manual Tester")
            print("="*60)
            print("1. Test Health Endpoint")
            print("2. Interactive Query Testing")
            print("3. Run Batch Tests")
            print("4. Run Error Handling Tests")
            print("5. Show Sample Rules")
            print("6. Show Example Queries") 
            print("0. Exit")
            print("-"*60)
            
            try:
                choice = input("Select option (0-6): ").strip()
                
                if choice == '0':
                    print("👋 Goodbye!")
                    break
                
                elif choice == '1':
                    if not self.test_health_endpoint():
                        print("\n⚠️  API server may not be running!")
                        print("Start it with: python main.py")
                
                elif choice == '2':
                    if self.test_health_endpoint():
                        self.interactive_query_test()
                    else:
                        print("❌ Cannot run interactive tests - API not available")
                
                elif choice == '3':
                    if self.test_health_endpoint():
                        self.run_batch_tests()
                    else:
                        print("❌ Cannot run batch tests - API not available")
                
                elif choice == '4':
                    if self.test_health_endpoint():
                        self.run_error_tests()
                    else:
                        print("❌ Cannot run error tests - API not available")
                
                elif choice == '5':
                    self.show_all_rules()
                
                elif choice == '6':
                    self.show_example_queries()
                
                else:
                    print("❌ Invalid option. Please choose 0-6.")
                
                input("\nPress Enter to continue...")
                
            except KeyboardInterrupt:
                print("\n👋 Goodbye!")
                break
            except EOFError:
                break
    
    def show_all_rules(self):
        """Show all sample rules organized by type."""
        print("\n=== Sample Rules Dataset ===")
        
        types = {}
        for rule in self.sample_rules:
            rule_type = rule["type"]
            if rule_type not in types:
                types[rule_type] = []
            types[rule_type].append(rule)
        
        for rule_type, rules in sorted(types.items()):
            print(f"\n{rule_type.title()} Rules ({len(rules)}):")
            for rule in sorted(rules, key=lambda r: r["level"], reverse=True):
                print(f"  ID: {rule['id']:<6} Level: {rule['level']:<2} - {rule['description']}")


def main():
    """Main entry point."""
    print("🚀 Starting Wazuh NLP API Manual Tester...")
    
    # Check if sample files exist
    files_missing = []
    if not Path("sample_rules.json").exists():
        files_missing.append("sample_rules.json")
    if not Path("test_queries.txt").exists():
        files_missing.append("test_queries.txt")
    
    if files_missing:
        print(f"⚠️  Warning: Missing files: {', '.join(files_missing)}")
        print("Some features may be limited.")
    
    tester = APITester()
    
    if len(sys.argv) > 1:
        # Command line mode
        query = " ".join(sys.argv[1:])
        print(f"Testing query: {query}")
        
        if not tester.test_health_endpoint():
            print("❌ API server not available!")
            sys.exit(1)
        
        response = tester.test_translate_endpoint(query)
        tester.print_translation_result(query, response)
    
    else:
        # Interactive mode
        tester.main_menu()


if __name__ == "__main__":
    main()
