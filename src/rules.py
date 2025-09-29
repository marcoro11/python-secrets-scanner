import re
import logging

from typing import List, Dict, Pattern, Optional
from pathlib import Path
from config import ScannerConfig, load_custom_rules
from models import create_secret_match, create_detection_rule, Severity


logger = logging.getLogger(__name__)

def get_builtin_rules() -> List[Dict]:
    """Get built-in detection rules"""
    return [
        # AWS
        create_detection_rule(
            id="aws-access-key",
            name="AWS Access Key ID",
            description="AWS Access Key ID",
            pattern=r'AKIA[0-9A-Z]{16}',
            severity=Severity.HIGH
        ),
        create_detection_rule(
            id="aws-secret-key",
            name="AWS Secret Access Key",
            description="AWS Secret Access Key",
            pattern=r'aws_secret_access_key\s*=\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
            severity=Severity.CRITICAL
        ),
        create_detection_rule(
            id="aws-session-token",
            name="AWS Session Token",
            description="AWS Session Token",
            pattern=r'aws_session_token\s*=\s*["\']?([A-Za-z0-9/+=]{56,})["\']?',
            severity=Severity.HIGH
        ),
        # Google Cloud
        create_detection_rule(
            id="gcp-service-account",
            name="Google Cloud Service Account",
            description="Google Cloud Service Account Key",
            pattern=r'"type":\s*"service_account"',
            severity=Severity.CRITICAL
        ),
        create_detection_rule(
            id="gcp-api-key",
            name="Google API Key",
            description="Google API Key",
            pattern=r'AIza[0-9A-Za-z\\-_]{35}',
            severity=Severity.HIGH
        ),
        # Azure
        create_detection_rule(
            id="azure-client-secret",
            name="Azure Client Secret",
            description="Azure Client Secret",
            pattern=r'client_secret\s*=\s*["\']?([A-Za-z0-9\-._~]{34,})["\']?',
            severity=Severity.HIGH
        ),
        # GitHub
        create_detection_rule(
            id="github-token",
            name="GitHub Token",
            description="GitHub Personal Access Token",
            pattern=r'gh[pousr]_[A-Za-z0-9_]{36}',
            severity=Severity.HIGH
        ),
        create_detection_rule(
            id="github-classic-token",
            name="GitHub Classic Token",
            description="GitHub Classic Personal Access Token",
            pattern=r'[0-9a-f]{40}',
            severity=Severity.MEDIUM,
            confidence=0.7
        ),
        # Private Keys
        create_detection_rule(
            id="rsa-private-key",
            name="RSA Private Key",
            description="RSA Private Key",
            pattern=r'-----BEGIN RSA PRIVATE KEY-----',
            severity=Severity.CRITICAL
        ),
        create_detection_rule(
            id="private-key",
            name="Private Key",
            description="Generic Private Key",
            pattern=r'-----BEGIN PRIVATE KEY-----',
            severity=Severity.CRITICAL
        ),
        create_detection_rule(
            id="openssh-private-key",
            name="OpenSSH Private Key",
            description="OpenSSH Private Key",
            pattern=r'-----BEGIN OPENSSH PRIVATE KEY-----',
            severity=Severity.CRITICAL
        ),
        # Database
        create_detection_rule(
            id="db-connection-string",
            name="Database Connection String",
            description="Database Connection String with Password",
            pattern=r'(mongodb|mysql|postgres|postgresql)://[^:]+:[^@]+@[^/]+',
            severity=Severity.HIGH
        ),
        # Slack
        create_detection_rule(
            id="slack-token",
            name="Slack Token",
            description="Slack Token",
            pattern=r'xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}',
            severity=Severity.HIGH
        ),
        # Discord
        create_detection_rule(
            id="discord-token",
            name="Discord Token",
            description="Discord Bot Token",
            pattern=r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}',
            severity=Severity.HIGH
        ),
        # JWT
        create_detection_rule(
            id="jwt-token",
            name="JWT Token",
            description="JSON Web Token",
            pattern=r'eyJ[A-Za-z0-9_/+-]*\.eyJ[A-Za-z0-9_/+-]*\.[A-Za-z0-9._/+-]*',
            severity=Severity.MEDIUM
        ),
        # API Keys (Generic)
        create_detection_rule(
            id="api-key-generic",
            name="Generic API Key",
            description="Generic API Key Pattern",
            pattern=r'(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?key)["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?',
            severity=Severity.MEDIUM,
            confidence=0.8
        ),
        # Passwords
        create_detection_rule(
            id="password-assignment",
            name="Password Assignment",
            description="Password Assignment in Code",
            pattern=r'(?i)(password|passwd|pwd)["\']?\s*[:=]\s*["\']?([^\s"\']{8,})["\']?',
            severity=Severity.MEDIUM,
            confidence=0.6,
            false_positive_patterns=[
                r'(?i)(password|passwd|pwd)["\']?\s*[:=]\s*["\']?(input|prompt|ask|get|read)',
                r'(?i)(password|passwd|pwd)["\']?\s*[:=]\s*["\']?(\$\{|\{\{|%s|%d|null|none|empty|todo|fixme)',
                r'(?i)(password|passwd|pwd)["\']?\s*[:=]\s*["\']?(123|test|demo|example|sample)'
            ]
        ),
        # SSH Config
        create_detection_rule(
            id="ssh-config",
            name="SSH Configuration",
            description="SSH Configuration File",
            pattern=r'Host\s+[^\s]+\s+HostName\s+[^\s]+\s+User\s+[^\s]+\s+IdentityFile\s+[^\s]+',
            severity=Severity.LOW
        ),
        # Email Addresses (in certain contexts)
        create_detection_rule(
            id="email-in-config",
            name="Email in Configuration",
            description="Email Address in Configuration Files",
            pattern=r'(?i)(email|mail)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["\']?',
            severity=Severity.LOW,
            confidence=0.5
        ),
        # Cryptocurrency
        create_detection_rule(
            id="bitcoin-address",
            name="Bitcoin Address",
            description="Bitcoin Wallet Address",
            pattern=r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
            severity=Severity.MEDIUM,
            confidence=0.7
        ),
        # Credit Card (basic pattern)
        create_detection_rule(
            id="credit-card",
            name="Credit Card Number",
            description="Credit Card Number",
            pattern=r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
            severity=Severity.HIGH,
            confidence=0.8
        ),
        # Twilio
        create_detection_rule(
            id="twilio-api-key",
            name="Twilio API Key",
            description="Twilio API Key",
            pattern=r'SK[a-f0-9]{32}',
            severity=Severity.HIGH
        ),
        # Stripe
        create_detection_rule(
            id="stripe-secret-key",
            name="Stripe Secret Key",
            description="Stripe Secret Key",
            pattern=r'sk_live_[0-9a-zA-Z]{24}',
            severity=Severity.CRITICAL
        ),
        create_detection_rule(
            id="stripe-test-key",
            name="Stripe Test Key",
            description="Stripe Test Key",
            pattern=r'sk_test_[0-9a-zA-Z]{24}',
            severity=Severity.MEDIUM
        ),
        # SendGrid
        create_detection_rule(
            id="sendgrid-api-key",
            name="SendGrid API Key",
            description="SendGrid API Key",
            pattern=r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}',
            severity=Severity.HIGH
        ),
        # Mailgun
        create_detection_rule(
            id="mailgun-api-key",
            name="Mailgun API Key",
            description="Mailgun API Key",
            pattern=r'key-[0-9a-f]{32}',
            severity=Severity.HIGH
        ),
    ]

def load_rules(config: ScannerConfig) -> List[Dict]:
    """Load all detection rules (built-in and custom)"""
    rules = get_builtin_rules()
    logger.info(f"Loaded {len(rules)} built-in rules")

    # Load custom rules if specified
    if config.custom_rules_path:
        custom_rules = load_custom_rules_from_path(config.custom_rules_path)
        rules.extend(custom_rules)
        logger.info(f"Loaded {len(custom_rules)} custom rules from {config.custom_rules_path}")

    return rules

def load_custom_rules_from_path(rules_path: str) -> List[Dict]:
    """Load custom rules from file"""
    try:
        custom_rules_data = load_custom_rules(rules_path)
        custom_rules = []
        for rule_data in custom_rules_data:
            rule = create_detection_rule(
                id=rule_data['id'],
                name=rule_data['name'],
                description=rule_data['description'],
                pattern=rule_data['pattern'],
                severity=Severity(rule_data.get('severity', 'medium')),
                confidence=rule_data.get('confidence', 1.0),
                enabled=rule_data.get('enabled', True),
                tags=rule_data.get('tags', []),
                false_positive_patterns=rule_data.get('false_positive_patterns', [])
            )
            custom_rules.append(rule)
        return custom_rules
    except Exception as e:
        logger.error(f'Error loading custom rules: {e}')
        return []

def compile_rules(rules: List[Dict]) -> Dict[str, Pattern]:
    """Compile regex patterns for better performance"""
    compiled_patterns = {}
    for rule in rules:
        if rule['enabled']:
            try:
                compiled_patterns[rule['id']] = re.compile(rule['pattern'], re.MULTILINE | re.IGNORECASE)
                # Compile false positive patterns
                if rule['false_positive_patterns']:
                    fp_patterns = []
                    for fp_pattern in rule['false_positive_patterns']:
                        try:
                            fp_patterns.append(re.compile(fp_pattern, re.MULTILINE | re.IGNORECASE))
                        except re.error:
                            logger.warning(f"Invalid false positive pattern in rule {rule['id']}: {fp_pattern}")
                    rule['false_positive_patterns'] = fp_patterns
            except re.error as e:
                logger.error(f"Invalid regex pattern in rule {rule['id']}: {e}")
                rule['enabled'] = False
    logger.info(f"Compiled {len(compiled_patterns)} regex patterns")
    return compiled_patterns

def scan_content(content: str, file_path: str, rules: List[Dict],
                 compiled_patterns: Dict[str, Pattern], config: ScannerConfig) -> List[Dict]:
    """Scan content for secrets using all enabled rules"""
    matches = []
    lines = content.split('\n')
    for rule in rules:
        if not rule['enabled'] or rule['id'] not in compiled_patterns:
            continue
        # Skip if rule severity is below minimum
        if severity_to_int(rule['severity']) < severity_to_int(config.min_severity):
            continue
        pattern = compiled_patterns[rule['id']]
        for match in pattern.finditer(content):
            # Check for false positives
            if is_false_positive(match.group(0), rule):
                continue
            # Find line number and column
            line_num, col_start, col_end = get_position(content, match.start(), match.end())
            # Get context
            context_before, context_after = get_context(lines, line_num - 1)
            secret_match = create_secret_match(
                rule_id=rule['id'],
                rule_name=rule['name'],
                description=rule['description'],
                severity=rule['severity'],
                file_path=file_path,
                line_number=line_num,
                column_start=col_start,
                column_end=col_end,
                matched_text=match.group(0),
                context_before=context_before,
                context_after=context_after,
                confidence=rule['confidence']
            )
            matches.append(secret_match)
    return matches

def is_false_positive(matched_text: str, rule: Dict) -> bool:
    """Check if a match is a false positive"""
    if not rule.get('false_positive_patterns'):
        return False
    for fp_pattern in rule['false_positive_patterns']:
        if hasattr(fp_pattern, 'search') and fp_pattern.search(matched_text):
            return True
    return False

def get_position(content: str, start: int, end: int) -> tuple:
    lines_before = content[:start].count('\n')
    line_num = lines_before + 1
    line_start = content.rfind('\n', 0, start)
    if line_start == -1:
        line_start = 0
    else:
        line_start += 1
    col_start = start - line_start + 1
    col_end = end - line_start + 1
    return line_num, col_start, col_end

def get_context(lines: List[str], line_index: int, context_size: int = 2) -> tuple:
    start_idx = max(0, line_index - context_size)
    end_idx = min(len(lines), line_index + context_size + 1)
    context_before = '\n'.join(lines[start_idx:line_index]) if line_index > 0 else ''
    context_after = '\n'.join(lines[line_index + 1:end_idx]) if line_index + 1 < len(lines) else ''
    return context_before, context_after

def severity_to_int(severity: Severity) -> int:
    severity_map = {
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4
    }
    return severity_map.get(severity, 1)
