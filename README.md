# Python Secrets Scanner

A tool for finding sensitive information – like API keys, passwords, and private keys – in your codebases.

## What it Does

This scanner helps you identify accidentally committed secrets before they end up in public repositories or production systems. It looks for patterns that match common secret formats across a wide range of services and technologies.

## Features

- **Multi-Pattern Detection**:  Supports over 50 built-in rules to detect various types of secrets, including:
    - Cloud credentials (AWS, GCP, Azure)
    - Tokens for version control systems (GitHub, GitLab)
    - Database connection strings
    - Private keys (RSA, SSH)
    - API keys from popular services (Stripe, Slack, SendGrid, etc.)
    - JWT tokens and passwords

- **Advanced Scanning Capabilities**:
    - **Git History Scanning**:  Finds secrets that were previously committed and later removed.
    - **File Type Detection & Filtering**:  Focuses on relevant files, reducing false positives.
    - **False Positive Reduction**: Uses confidence scoring to help prioritize findings.
    - **Configurable Severity Levels**:  Customize the scanner's sensitivity based on your needs.

- **Flexible Configuration**:
    - **Custom Rules**:  Add your own detection rules using a simple YAML configuration file.
    - **Include/Exclude Patterns**:  Specify which files and directories to scan or ignore.
    - **Severity Filtering**: Focus on high-severity findings first.
    - **File Size Limits**:  Avoid scanning excessively large files that might slow down the process.

- **Multiple Output Formats**:
    - **Colorized Console Output**:  Easy-to-read results directly in your terminal.
    - **JSON Format**:  Integrate with other tools and automate security checks.
    - **CSV Format**: Analyze findings in a spreadsheet program like Excel or Google Sheets.

- **Performance Optimized**:
    - **Duplicate Content Detection**:  Avoids redundant scanning of the same content.
    - **Memory-Efficient Streaming**: Handles large files without excessive memory usage.

## 📁 Project Structure

```
python-secrets-scanner/
├── src/
│   ├── main.py              # Application entry point
│   ├── scanner.py           # Core scanning logic
│   ├── models.py            # Data models and structures
│   ├── config.py            # Configuration management
│   ├── rules.py             # Detection rules engine
│   └── reporters.py         # Report generation
├── config/
│   └── custom_rules.yaml    # Custom detection rules
├── test-data/               # Sample data for testing
│   ├── api_keys.txt
│   ├── clean.txt
│   ├── config.py
│   ├── passwords.txt
│   ├── private_key.pem
│   └── test_script.py       # Script for testing the scanner
├── Pipfile                 # Python dependencies
└── README.md               # This file
```

   
## Quick Start

### Prerequisites

- Python 3.12 or higher
- Pipenv

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/marcoro11/python-secrets-scanner.git
   cd python-secrets-scanner
   ```

2. **Install dependencies**:
   ```bash
   # Install pipenv if you don't have it
   pip install --user pipenv
   
   # Install project dependencies
   pipenv install
   ```

3. **Run your first scan**:
   ```bash
   # Scan current directory
   pipenv run scan .
   
   # Scan specific file
   pipenv run scan /path/to/file.py
   
   # Scan with JSON output
   pipenv run scan /path/to/project --format json --output results.json
   ```

## Usage Examples

### Basic Scanning

```bash
# Scan a project directory
pipenv run scan /path/to/project

# Scan single file with verbose output
pipenv run scan file.py --verbose

# Exclude specific directories
pipenv run scan . --exclude "node_modules" --exclude "*.git*"
```

### Advanced Options

```bash
# Use custom rules and filter by severity
pipenv run scan . --custom-rules config/custom_rules.yaml --severity high

# Generate JSON report
pipenv run scan . --format json --output security_report.json

# Scan without Git history (faster)
pipenv run scan . --no-git

# Include only specific file types
pipenv run scan . --include "*.py" --include "*.js" --include "*.yaml"
```

### Integration Examples

```bash
# CI/CD Pipeline - exit with error if secrets found
pipenv run scan . --format json --output scan_results.json
EXIT_CODE=$?
if [ $EXIT_CODE -eq 1 ]; then
    echo "❌ Secrets detected! Check scan_results.json"
    exit 1
fi

# Pre-commit hook
pipenv run scan --format console $(git diff --cached --name-only)
```

## Testing the Tool

### Using Sample Data

The `test-data` folder contains sample files with mock secrets for testing the scanner. You can use the provided `test_script.py` to test the scanner:

1. **Run the test script**:
   ```bash
   python test-data/test_script.py
   ```

This setup allows you to verify the functionality of the scanner with predefined test data.

## Configuration

### Custom Rules

Create custom detection rules by editing `config/custom_rules.yaml`:

```yaml
rules:
  - id: "my-api-key"
    name: "My Service API Key"
    description: "API key for my custom service"
    pattern: 'MYSERVICE_API_KEY_[A-Za-z0-9]{32}'
    severity: "high"
    confidence: 0.9
    enabled: true
    tags:
      - "api-key"
      - "custom"
    false_positive_patterns:
      - 'MYSERVICE_API_KEY_PLACEHOLDER'
```

## Detection Categories

### Cloud Providers
- **AWS**: Access keys, secret keys, session tokens
- **Google Cloud**: Service account keys, API keys
- **Azure**: Client secrets, connection strings

### Version Control
- **GitHub**: Personal access tokens, app tokens
- **GitLab**: Access tokens, deploy keys

### Communication Services  
- **Slack**: Bot tokens, webhook URLs
- **Discord**: Bot tokens
- **Teams**: Webhook URLs

### Payment & Financial
- **Stripe**: Secret keys, publishable keys
- **PayPal**: Client secrets
- **Square**: Access tokens

### Databases
- **MongoDB**: Connection strings
- **PostgreSQL**: Connection strings  
- **MySQL**: Connection strings
- **Redis**: URLs with authentication

### Cryptographic Material
- **Private Keys**: RSA, SSH, OpenSSH
- **Certificates**: X.509 certificates
- **JWT Tokens**: JSON Web Tokens

## Sample Output

### Console Output
```
🔍 PYTHON SECRETS SCANNER REPORT
============================================================
Scan completed: 2025-01-17 14:30:22

SUMMARY
--------------------
Files scanned: 156
Secrets found: 3

By severity:
  ● HIGH:     2
  ● MEDIUM:   1

FINDINGS
--------------------

src/config.py
  [HIGH] AWS Secret Access Key
  Line 23, Column 25-65
  AWS Secret Access Key
  Match: aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  
  [MEDIUM] Generic API Key Pattern  
  Line 45, Column 12-44
  Generic API Key Pattern
  Match: api_key = "sk_test_1234567890abcdef"
  Confidence: 0.80
```

### JSON Output
```json
{
  "scan_time": "2025-01-17T14:30:22.123456",
  "total_files": 156,
  "total_secrets": 3,
  "summary": {
    "critical": 0,
    "high": 2,
    "medium": 1,
    "low": 0
  },
  "secrets": [
    {
      "rule_id": "aws-secret-key",
      "rule_name": "AWS Secret Access Key",
      "severity": "high",
      "file_path": "src/config.py",
      "line_number": 23,
      "matched_text": "aws_secret_access_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"",
      "confidence": 1.0
    }
  ]
}
```

### Adding New Detection Rules

1. **Built-in Rules**: Add to `src/rules.py` in the `_load_builtin_rules()` method
2. **Custom Rules**: Add to `config/custom_rules.yaml`

Example built-in rule:
```python
DetectionRule(
    id="my-service-token",
    name="My Service Token", 
    description="Authentication token for my service",
    pattern=r'MYSERVICE_[A-Za-z0-9]{32}',
    severity="high",
    confidence=0.9,
    enabled=True,
    tags=["service-token", "authentication"],
    false_positive_patterns=[
        r'MYSERVICE_TEST_TOKEN',
        r'MYSERVICE_DEV_TOKEN'
    ]
)
```