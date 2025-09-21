# Testing Guide for Wazuh NLP API

This guide covers the testing framework and sample data for the Wazuh NLP Flask API.

## Overview

The testing suite includes:
- **Automated tests**: Comprehensive pytest test suite (`test_api.py`)
- **Manual testing**: Interactive testing script (`manual_test.py`)  
- **Sample data**: Diverse rule sets and test queries
- **Error testing**: Coverage of edge cases and error conditions

## Test Files

### 1. Sample Data Files

#### `sample_rules.json`
Contains 20 diverse Wazuh rules across different types:
- **Authentication rules** (4): Login failures, password changes, etc.
- **System rules** (4): Boot events, service restarts, kernel errors, CPU usage
- **Security rules** (4): Privilege escalation, suspicious processes, file changes
- **SCA rules** (4): CIS benchmarks, configuration issues, policy violations
- **Rootcheck rules** (4): Suspicious binaries, rootkits, SUID files

#### `test_queries.txt`
Contains 35+ example English queries organized by category:
- Authentication queries
- System queries 
- Security queries
- Configuration assessment queries
- Rootcheck queries
- Mixed severity queries
- Time-based queries
- Specific rule queries

### 2. Test Scripts

#### `test_api.py` - Automated Test Suite
Comprehensive pytest test suite covering:
- ✅ Endpoint functionality (health, translate)
- ✅ Input validation and error handling
- ✅ Translation quality with various rule combinations
- ✅ HTTP status code validation
- ✅ Confidence scoring accuracy
- ✅ Elasticsearch query structure validation

#### `manual_test.py` - Interactive Testing
Interactive testing tool with features:
- ✅ Menu-driven interface
- ✅ Real-time query testing
- ✅ Batch test scenarios
- ✅ Error handling tests
- ✅ Sample data exploration
- ✅ Command-line support

## Running Tests

### Prerequisites
1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Start the Flask API server**:
   ```bash
   python main.py --host 127.0.0.1 --port 5000
   ```
   (Leave this running in a separate terminal)

### Automated Testing (pytest)

Run the complete test suite:
```bash
pytest test_api.py -v
```

Run specific test categories:
```bash
# Test only error handling
pytest test_api.py::TestAPI::test_missing_query_field -v

# Test only translation functionality  
pytest test_api.py::TestAPI::test_translate_endpoint_basic -v

# Test with detailed output
pytest test_api.py -v -s
```

### Manual/Interactive Testing

#### Interactive Mode
```bash
python manual_test.py
```

This opens an interactive menu:
```
🔧 Wazuh NLP API Manual Tester
============================================================
1. Test Health Endpoint
2. Interactive Query Testing  
3. Run Batch Tests
4. Run Error Handling Tests
5. Show Sample Rules
6. Show Example Queries
0. Exit
```

#### Command Line Mode
Test individual queries directly:
```bash
# Single query test
python manual_test.py "Show me authentication failures"

# Complex query test
python manual_test.py "Find critical security events from last week"
```

#### Interactive Query Session
Choose option 2 for interactive testing:
```bash
🔍 Query> Show me authentication failures
🔍 Query> Find system errors with level > 10  
🔍 Query> List rootkit detections from yesterday
🔍 Query> help          # Show available commands
🔍 Query> examples      # Show example queries
🔍 Query> rules system  # Show system rules
🔍 Query> quit          # Exit interactive mode
```

## Test Scenarios

### 1. Single Rule Type Testing
```json
{
  "query": "Show me authentication failures",
  "rules": [/* authentication rules only */]
}
```

### 2. Multiple Rule Types
```json
{
  "query": "Find security events", 
  "rules": [/* mixed authentication, system, security rules */]
}
```

### 3. Severity-Based Filtering
```json
{
  "query": "Show critical alerts",
  "rules": [/* rules with level >= 10 */]
}
```

### 4. Specific Rule ID Queries
```json
{
  "query": "Show rule 5503 events",
  "rules": [/* all available rules */]
}
```

### 5. Time-Based Queries
```json
{
  "query": "Find events from the last hour",
  "rules": [/* sample rules */]
}
```

## Expected Results

### Successful Translation
```json
{
  "status": "success",
  "elasticsearch_query": {
    "query": {
      "bool": {
        "filter": [...],
        "must": [...]
      }
    },
    "size": 50,
    "sort": [{"@timestamp": {"order": "desc"}}]
  },
  "confidence": 0.85,
  "validation": {
    "is_valid": true,
    "issues": [],
    "summary": {...}
  }
}
```

### Error Response
```json
{
  "status": "error", 
  "message": "Missing required field: 'query'"
}
```

## Confidence Scoring

The API provides confidence scores based on:
- **Rule type matching** (0.0 - 1.0)
- **Severity level detection** (0.0 - 1.0)  
- **Rule ID recognition** (0.0 - 1.0)
- **Time range parsing** (0.0 - 1.0)
- **Keyword matching** (0.0 - 1.0)

**Interpretation:**
- **0.8-1.0**: High confidence - query well understood
- **0.5-0.8**: Medium confidence - reasonable interpretation
- **0.3-0.5**: Low confidence - basic interpretation
- **0.0-0.3**: Very low confidence - fallback used

## Troubleshooting

### Common Issues

1. **Connection Refused Error**
   ```
   Solution: Start the Flask server first
   ```

2. **Import Errors in Tests**
   ```
   Solution: Install missing dependencies
   pip install requests pytest
   ```

3. **Test Failures**
   ```
   Solution: Check server is running on port 5000
   curl http://127.0.0.1:5000/health
   ```

### Performance Testing

Monitor API response times:
```bash
# Time a simple query
time python manual_test.py "Show authentication events"

# Test with large rule set (all sample rules)
python manual_test.py "Find any security issues"
```

### Debug Mode

Run tests with server in debug mode:
```bash
# Terminal 1: Start server with debug logging
python main.py --host 127.0.0.1 --port 5000 --debug --log-level DEBUG

# Terminal 2: Run tests
pytest test_api.py -v -s
```

## Test Coverage

The test suite covers:

✅ **API Endpoints**
- Health check endpoint
- Translation endpoint
- Error handlers (404, 405, 500)

✅ **Input Validation** 
- Missing fields
- Invalid data types
- Empty arrays
- Malformed JSON

✅ **Translation Quality**
- Rule type detection
- Severity level filtering  
- Time range parsing
- Specific rule ID matching
- Keyword matching accuracy

✅ **Error Handling**
- HTTP status codes
- Error message clarity
- Graceful failure modes

✅ **Rule Scenarios**
- Single rule type
- Multiple same types
- Mixed rule types
- High/low severity filtering
- All available rule types

This comprehensive testing framework ensures the API works correctly across various scenarios and handles errors gracefully.
