from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class Severity(Enum):
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'

def create_secret_match(rule_id: str, rule_name: str, description: str, severity: Severity,
                        file_path: str, line_number: int, column_start: int, column_end: int,
                        matched_text: str, context_before: str = '', context_after: str = '',
                        confidence: float = 1.0) -> Dict[str, Any]:
    return {
        'rule_id': rule_id,
        'rule_name': rule_name,
        'description': description,
        'severity': severity,
        'file_path': file_path,
        'line_number': line_number,
        'column_start': column_start,
        'column_end': column_end,
        'matched_text': matched_text,
        'context_before': context_before,
        'context_after': context_after,
        'confidence': confidence
    }

def secret_match_to_dict(secret_match: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'rule_id': secret_match['rule_id'],
        'rule_name': secret_match['rule_name'],
        'description': secret_match['description'],
        'severity': secret_match['severity'].value,
        'file_path': secret_match['file_path'],
        'line_number': secret_match['line_number'],
        'column_start': secret_match['column_start'],
        'column_end': secret_match['column_end'],
        'matched_text': secret_match['matched_text'][:100] + '...' if len(secret_match['matched_text']) > 100 else secret_match['matched_text'],
        'context_before': secret_match['context_before'],
        'context_after': secret_match['context_after'],
        'confidence': secret_match['confidence']
    }

def create_file_result(path: str, secrets: Optional[List[Dict[str, Any]]] = None,
                      size: int = 0, encoding: str = 'utf-8') -> Dict[str, Any]:
    return {
        'path': path,
        'secrets': secrets or [],
        'size': size,
        'encoding': encoding
    }

def file_result_to_dict(file_result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'path': file_result['path'],
        'secrets': [secret_match_to_dict(secret) for secret in file_result['secrets']],
        'size': file_result['size'],
        'encoding': file_result['encoding'],
        'secret_count': len(file_result['secrets'])
    }

def create_scan_result(files: Optional[List[Dict[str, Any]]] = None,
                      secrets: Optional[List[Dict[str, Any]]] = None,
                      total_files: int = 0, total_secrets: int = 0,
                      scan_time: Optional[datetime] = None,
                      errors: Optional[List[str]] = None) -> Dict[str, Any]:
    if scan_time is None:
        scan_time = datetime.now()
    return {
        'files': files or [],
        'secrets': secrets or [],
        'total_files': total_files,
        'total_secrets': total_secrets,
        'scan_time': scan_time,
        'errors': errors or []
    }

def scan_result_to_dict(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'scan_time': scan_result['scan_time'].isoformat() if scan_result['scan_time'] else None,
        'total_files': scan_result['total_files'],
        'total_secrets': scan_result['total_secrets'],
        'files': [file_result_to_dict(file_result) for file_result in scan_result['files']],
        'secrets': [secret_match_to_dict(secret) for secret in scan_result['secrets']],
        'errors': scan_result['errors'],
        'summary': {
            'critical': len([s for s in scan_result['secrets'] if s['severity'] == Severity.CRITICAL]),
            'high': len([s for s in scan_result['secrets'] if s['severity'] == Severity.HIGH]),
            'medium': len([s for s in scan_result['secrets'] if s['severity'] == Severity.MEDIUM]),
            'low': len([s for s in scan_result['secrets'] if s['severity'] == Severity.LOW])
        }
    }

def create_detection_rule(id: str, name: str, description: str, pattern: str, severity: Severity,
                         confidence: float = 1.0, enabled: bool = True,
                         tags: Optional[List[str]] = None,
                         false_positive_patterns: Optional[List[str]] = None) -> Dict[str, Any]:
    return {
        'id': id,
        'name': name,
        'description': description,
        'pattern': pattern,
        'severity': severity,
        'confidence': confidence,
        'enabled': enabled,
        'tags': tags or [],
        'false_positive_patterns': false_positive_patterns or []
    }

def detection_rule_to_dict(detection_rule: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'id': detection_rule['id'],
        'name': detection_rule['name'],
        'description': detection_rule['description'],
        'pattern': detection_rule['pattern'],
        'severity': detection_rule['severity'].value,
        'confidence': detection_rule['confidence'],
        'enabled': detection_rule['enabled'],
        'tags': detection_rule['tags'],
        'false_positive_patterns': detection_rule['false_positive_patterns']
    }
