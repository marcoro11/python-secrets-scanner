import yaml

from pathlib import Path
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
from models import Severity


@dataclass
class ScannerConfig:
    custom_rules_path: Optional[str] = None
    exclude_patterns: List[str] = field(default_factory=list)
    include_patterns: List[str] = field(default_factory=list)
    min_severity: Optional[str] = None
    scan_git_history: bool = True
    max_file_size_mb: int = 10
    
    def __post_init__(self):
        default_excludes = [
            '*.git*',
            '*.svn*',
            '*node_modules*',
            '*venv*',
            '*.env*',
            '*__pycache__*',
            '*.pyc',
            '*.pyo',
            '*.class',
            '*.jar',
            '*.war',
            '*.zip',
            '*.tar.gz',
            '*.tar.bz2',
            '*.rar',
            '*.7z',
            '*.pdf',
            '*.doc*',
            '*.xls*',
            '*.ppt*',
            '*.jpg',
            '*.jpeg',
            '*.png',
            '*.gif',
            '*.bmp',
            '*.ico',
            '*.svg',
            '*.mp3',
            '*.mp4',
            '*.avi',
            '*.mov',
            '*.wmv',
            '*.exe',
            '*.dll',
            '*.so',
            '*.dylib',
            '*.min.js',
            '*.min.css',
            '*bower_components*',
            '*vendor*',
            '*third_party*',
            '*.lock',
            'package-lock.json',
            'yarn.lock',
            'poetry.lock',
            'Pipfile.lock'
        ]
        self.exclude_patterns.extend([p for p in default_excludes if p not in self.exclude_patterns])
        if self.min_severity:
            try:
                self.min_severity = Severity(self.min_severity.lower())
            except ValueError:
                self.min_severity = Severity.LOW
        else:
            self.min_severity = Severity.LOW

def load_custom_rules(rules_path: str) -> List[Dict[str, Any]]:
    try:
        with open(rules_path, 'r') as f:
            data = yaml.safe_load(f)
            return data.get('rules', [])
    except Exception as e:
        raise ValueError(f'Error loading custom rules from {rules_path}: {e}')
