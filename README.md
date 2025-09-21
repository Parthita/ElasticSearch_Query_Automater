# Wazuh NLP Translation API

A Flask-based REST API that translates natural English language queries into Elasticsearch DSL queries for Wazuh security data. This system enables security analysts to query Wazuh logs using natural language instead of complex Elasticsearch syntax.

## Overview

The Wazuh NLP Translation API processes English queries like "Show me recent authentication failures" and converts them into proper Elasticsearch queries that can be executed against Wazuh indices. The system analyzes rule metadata, extracts intent from natural language, and generates optimized Elasticsearch DSL queries with confidence scoring.

## Features

- **Advanced Natural Language Processing**: Convert English queries to Elasticsearch DSL with fuzzy matching and typo tolerance
- **Rule-Based Translation**: Uses Wazuh rule metadata for context-aware translation
- **Intelligent Confidence Scoring**: Multi-factor confidence calculation with entity detection bonuses
- **Query Validation**: Validates generated Elasticsearch queries for correctness
- **Multiple Rule Types**: Supports authentication, system, security, SCA, and rootcheck rules
- **Enhanced Time Range Support**: Dynamic expressions like "last 3 hours", "within the past 2 days"
- **Severity Filtering**: Processes severity levels with synonym support (urgent→critical, warn→medium)
- **Field-Specific Queries**: IP addresses, ports, file paths, and agent/host filtering
- **Boolean Logic Support**: AND/OR/NOT operators for complex query combinations
- **Intelligent Suggestions**: Context-aware recommendations for improving low-confidence queries
- **Fuzzy Matching**: Handles typos and variations in rule types and keywords
- **Synonym Dictionaries**: Extensive synonym mapping for natural language flexibility
- **Error Handling**: Comprehensive input validation and error responses

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Setup

1. **Clone or download the project files**

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify configuration**:
   The system uses `config.yaml` for configuration. The default configuration should work for most use cases.

4. **Test the installation**:
   ```bash
   python main.py --help
   ```

## Running the API

### Start the Server

```bash
python main.py --host 127.0.0.1 --port 5000
```

The server will start and display:
```
Starting Wazuh NLP Translation API on 127.0.0.1:5000
 * Running on http://127.0.0.1:5000
```

### Command Line Options

```bash
python main.py [OPTIONS]

Options:
  --host HOST          Host to bind to (default: 127.0.0.1)
  --port PORT          Port to bind to (default: 5000) 
  --debug              Enable debug mode
  --log-level LEVEL    Set logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
```

### Health Check

Test if the API is running:
```bash
curl http://127.0.0.1:5000/health
```

Expected response:
```json
{
  "status": "healthy",
  "service": "Wazuh NLP Translation API", 
  "version": "1.0.0"
}
```

## API Reference

### POST /translate

Translates a natural language query into an Elasticsearch DSL query.

**Endpoint**: `POST /translate`

**Content-Type**: `application/json`

**Request Body**:
```json
{
  "query": "English language query string",
  "rules": [
    {
      "id": 5503,
      "description": "User login failed", 
      "type": "authentication",
      "level": 5
    }
  ]
}
```

**Response**:
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
  },
  "suggestions": [
    "Consider adding a time range like 'recent', 'today', or 'last week'",
    "You can filter by IP using phrases like 'from 10.0.0.5'"
  ]
}
```

## Rule Structure

### Required Rule Fields

Each rule in the `rules` array must contain these fields:

```json
{
  "id": 1001,
  "description": "System boot completed",
  "type": "system", 
  "level": 2
}
```

### Field Descriptions

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `id` | integer | Unique rule identifier | `5503` |
| `description` | string | Human-readable rule description | `"User login failed"` |
| `type` | string | Rule category/type | `"authentication"` |
| `level` | integer | Severity level (0-15) | `5` |

### Rule Types

Supported rule types:

- **authentication**: Login events, password changes, user authentication
- **system**: System events, service status, hardware issues  
- **security**: Security events, privilege escalation, suspicious activity
- **sca**: Security Configuration Assessment, policy compliance
- **rootcheck**: Rootkit detection, system integrity checks

### Severity Levels

- **0-3**: Informational/Low priority
- **4-6**: Medium priority, warnings
- **7-10**: High priority, significant events
- **11-15**: Critical priority, immediate attention required

## Usage Examples

### Basic Authentication Query

**Request**:
```bash
curl -X POST http://127.0.0.1:5000/translate \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Show me recent authentication failures",
    "rules": [
      {
        "id": 5503,
        "description": "User login failed",
        "type": "authentication", 
        "level": 5
      },
      {
        "id": 40101,
        "description": "Multiple authentication failures detected",
        "type": "authentication",
        "level": 10
      }
    ]
  }'
```

**Response**:
```json
{
  "status": "success",
  "elasticsearch_query": {
    "query": {
      "bool": {
        "filter": [
          {
            "term": {
              "rule.groups": "authentication"
            }
          },
          {
            "range": {
              "@timestamp": {
                "gte": "now-1h"
              }
            }
          }
        ],
        "must": []
      }
    },
    "size": 50,
    "sort": [
      {
        "@timestamp": {
          "order": "desc"
        }
      }
    ]
  },
  "confidence": 0.89,
  "validation": {
    "is_valid": true,
    "issues": [],
    "summary": {
      "total_issues": 0,
      "errors": 0,
      "warnings": 0
    }
  }
}
```

### High Severity Security Events

**Request**:
```bash
curl -X POST http://127.0.0.1:5000/translate \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Find critical security events from today",
    "rules": [
      {
        "id": 2001,
        "description": "Privilege escalation attempt",
        "type": "security",
        "level": 13
      },
      {
        "id": 4003,
        "description": "Known rootkit signatures detected", 
        "type": "rootcheck",
        "level": 15
      }
    ]
  }'
```

### Specific Rule Query

**Request**:
```bash
curl -X POST http://127.0.0.1:5000/translate \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Show rule 5503 events from the last 24 hours",
    "rules": [
      {
        "id": 5503,
        "description": "User login failed",
        "type": "authentication",
        "level": 5
      }
    ]
  }'
```

### Time-Based Query with Dynamic Expressions

**Request**:
```bash
curl -X POST http://127.0.0.1:5000/translate \
  -H "Content-Type: application/json" \
  -d '{
    "query": "List system errors from the last 3 hours",
    "rules": [
      {
        "id": 1003,
        "description": "Kernel error detected",
        "type": "system",
        "level": 12
      }
    ]
  }'
```

### Field-Specific Query with IP and Port

**Request**:
```bash
curl -X POST http://127.0.0.1:5000/translate \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Show SSH connections from 192.168.1.100 on port 22",
    "rules": [
      {
        "id": 5503,
        "description": "SSH connection attempt",
        "type": "authentication",
        "level": 6
      }
    ]
  }'
```

### Agent/Host Filtering Query

**Request**:
```bash
curl -X POST http://127.0.0.1:5000/translate \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Find authentication events from server web-01",
    "rules": [
      {
        "id": 5503,
        "description": "User login attempt",
        "type": "authentication",
        "level": 5
      }
    ]
  }'
```

### Boolean Logic Query

**Request**:
```bash
curl -X POST http://127.0.0.1:5000/translate \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Show login AND failure NOT success",
    "rules": [
      {
        "id": 5503,
        "description": "User login failed",
        "type": "authentication",
        "level": 5
      }
    ]
  }'
```

## How NLP Translation Works

### Translation Process

1. **Query Analysis**: The system parses the English query to extract intent
2. **Rule Type Detection**: Identifies relevant rule types based on keywords
3. **Severity Extraction**: Detects severity levels and ranges from the query
4. **Time Range Parsing**: Processes temporal expressions like "recent", "today"
5. **Rule ID Recognition**: Identifies specific rule IDs mentioned in queries
6. **Keyword Matching**: Matches query terms with rule descriptions
7. **Query Generation**: Constructs Elasticsearch DSL query based on extracted intent
8. **Confidence Calculation**: Computes confidence score based on match quality
9. **Query Validation**: Validates the generated Elasticsearch query
10. **Response Formation**: Returns structured response with query and metadata

### Supported Query Patterns

**Time Expressions**:
- "recent", "recently", "now" → last 1 hour
- "today", "current" → last 24 hours  
- "yesterday" → previous 24-hour period
- "last hour/day/week/month" → corresponding time range
- "5 minutes ago", "2 hours ago" → specific relative time
- "past 3 days", "last 2 weeks" → flexible dynamic ranges
- **Fuzzy matching**: "recnt", "todya" → handles typos and variations
- **Synonyms**: "now" → "recent", "current" → "today"

**Severity Expressions**:
- "critical", "severe", "urgent" → levels 12-15
- "high", "serious", "important" → levels 7-10
- "medium", "moderate", "warning" → levels 4-6
- "low", "minor", "info" → levels 1-3
- "level > 8", "level 10" → specific level constraints
- **Synonyms**: "urgent" → "critical", "serious" → "high", "minor" → "low"
- **Fuzzy matching**: "critcal", "sevrity" → handles spelling variations

**Rule Type Keywords**:
- Authentication: "login", "auth", "authentication", "password", "user"
- System: "system", "service", "boot", "kernel", "cpu"
- Security: "security", "privilege", "escalation", "suspicious"
- SCA: "configuration", "policy", "compliance", "benchmark"
- Rootcheck: "rootkit", "suspicious", "binary", "suid"
- **Fuzzy matching**: "autentication", "suspicius" → handles typos in rule types
- **Context awareness**: Rule type inference from query context

**Field-Specific Queries**:
- **IP Addresses**: "from 192.168.1.100", "source IP 10.0.0.5", "destination 172.16.1.1"
- **Ports**: "port 22", "on port 80", "destination port 443"
- **Agents/Hosts**: "from server web-01", "agent database-server", "host mail-01"
- **File Paths**: "file /etc/passwd", "path /var/log/auth.log", "directory /tmp"
- **User Names**: "user admin", "username john", "account root"
- **Process Names**: "process apache2", "service ssh", "daemon mysql"

**Boolean Logic Support**:
- **AND Operations**: "login AND failure", "ssh and error"
- **OR Operations**: "critical OR high", "authentication or authorization"
- **NOT Operations**: "login NOT success", "errors not warnings"
- **Complex Expressions**: "(login OR ssh) AND (failure OR error) NOT success"
- **Implicit Logic**: Natural language patterns automatically converted to boolean logic

### Confidence Scoring

The system provides confidence scores (0.0-1.0) based on:

- **Rule Type Matching**: How well query keywords match rule types
- **Severity Detection**: Accuracy of severity level extraction
- **Time Range Parsing**: Success of temporal expression parsing
- **Rule ID Recognition**: Exact rule ID matches
- **Keyword Coverage**: Proportion of query terms understood

**Confidence Interpretation**:
- **0.8-1.0**: High confidence - query well understood
- **0.5-0.8**: Medium confidence - reasonable interpretation  
- **0.3-0.5**: Low confidence - basic interpretation
- **0.0-0.3**: Very low confidence - fallback query used

## Error Handling

### Error Response Format

```json
{
  "status": "error",
  "message": "Description of the error"
}
```

### Common Error Codes

| HTTP Status | Error | Description |
|-------------|-------|-------------|
| 400 | Bad Request | Missing or invalid request data |
| 405 | Method Not Allowed | Wrong HTTP method used |
| 404 | Not Found | Invalid endpoint |
| 500 | Internal Server Error | Server-side processing error |

### Input Validation Errors

**Missing Required Fields**:
```json
{
  "status": "error",
  "message": "Missing required field: 'query'"
}
```

**Invalid Rule Structure**:
```json
{
  "status": "error", 
  "message": "Rule at index 0: 'level' must be integer between 0-15"
}
```

**Empty Rules Array**:
```json
{
  "status": "error",
  "message": "Field 'rules' cannot be empty"
}
```

## Testing

The project includes comprehensive testing tools:

### Automated Tests

Run the full test suite:
```bash
pytest test_api.py -v
```

### Manual Testing

Interactive testing tool:
```bash
python manual_test.py
```

Command line testing:
```bash
python manual_test.py "Show me authentication failures"
```

### Sample Data

- `sample_rules.json`: 20 diverse Wazuh rules for testing
- `test_queries.txt`: 35+ example English queries
- See `TESTING.md` for detailed testing documentation

## Configuration

The system uses `config.yaml` for configuration:

```yaml
app:
  name: "Wazuh NLP Query System"
  debug: false
  log_level: "INFO"
  max_query_length: 500

severity:
  mappings:
    low: { min: 1, max: 3 }
    medium: { min: 4, max: 6 }
    high: { min: 7, max: 10 }
    critical: { min: 11, max: 15 }

rule_types:
  authentication:
    keywords: ["login", "auth", "user", "password"]
    
query_processing:
  default_results: 50
  min_query_length: 3
  max_query_length: 500
```

## Project Structure

```
nlp_siem/
├── main.py                    # Flask API server
├── nlp_translate.py          # NLP translation engine
├── config.py                 # Configuration management
├── elasticsearch_validator.py # Query validation
├── load_rules.py             # Rule data structures
├── config.yaml               # System configuration
├── requirements.txt          # Python dependencies
├── sample_rules.json         # Sample rule data
├── test_queries.txt          # Example queries
├── test_api.py               # Automated tests
├── manual_test.py            # Interactive testing
├── TESTING.md                # Testing documentation
└── README.md                 # This file
```

## API Response Fields

### Successful Response

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | "success" for successful translations |
| `elasticsearch_query` | object | Generated Elasticsearch DSL query |
| `confidence` | number | Translation confidence (0.0-1.0) |
| `validation` | object | Query validation results and suggestions |

### Elasticsearch Query Structure

The generated queries follow this structure:
```json
{
  "query": {
    "bool": {
      "filter": [/* filtering conditions */],
      "must": [/* search conditions */]
    }
  },
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}]
}
```

**Common Filter Types**:
- `term`: Exact field matching (rule types, IDs)
- `range`: Numeric/date ranges (levels, timestamps)
- `terms`: Multiple value matching

**Common Must Clauses**:
- `match`: Text search in descriptions
- `multi_match`: Search across multiple fields

## Troubleshooting

### Server Won't Start

**Issue**: `Address already in use`
**Solution**: Change port with `--port 5001` or kill existing process

**Issue**: `Import errors`
**Solution**: Install dependencies with `pip install -r requirements.txt`

### Translation Issues

**Issue**: Low confidence scores
**Solution**: Use more specific keywords matching rule types and descriptions

**Issue**: No results returned
**Solution**: Check that rule types in query match provided rules

### Testing Problems

**Issue**: Tests fail with connection errors
**Solution**: Ensure Flask server is running before running tests

**Issue**: Timeout errors
**Solution**: Increase server startup wait time in tests

## Contributing

To extend the system:

1. **Add Rule Types**: Update `config.yaml` with new rule type keywords
2. **Improve NLP**: Enhance pattern matching in `nlp_translate.py`
3. **Add Validation**: Extend query validation in `elasticsearch_validator.py`
4. **Update Tests**: Add test cases for new functionality

## License

This project is provided as-is for educational and development purposes.
