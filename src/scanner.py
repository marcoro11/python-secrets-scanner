import re
import hashlib
import mimetypes
import logging
import fnmatch
import subprocess
import tempfile

from pathlib import Path
from typing import List, Dict, Set, Optional, Iterator, Pattern
from models import create_scan_result, create_file_result
from config import ScannerConfig
from rules import load_rules, compile_rules, scan_content


logger = logging.getLogger(__name__)

def get_scannable_extensions() -> Set[str]:
    return {
        '.py', '.js', '.ts', '.java', '.go', '.rb', '.php', '.cs', '.cpp', '.c',
        '.h', '.hpp', '.swift', '.kt', '.scala', '.rs', '.pl', '.sh', '.bash',
        '.zsh', '.fish', '.ps1', '.bat', '.cmd', '.yaml', '.yml', '.json',
        '.xml', '.ini', '.conf', '.config', '.env', '.properties', '.toml',
        '.sql', '.html', '.htm', '.css', '.scss', '.sass', '.less', '.vue',
        '.jsx', '.tsx', '.md', '.rst', '.txt', '.log', '.cfg', '.pem', '.key',
        '.pub', '.cert', '.crt', '.p12', '.pfx', '.jks', '.keystore'
    }

def scan_path(path: Path, config: ScannerConfig, rules: List, compiled_patterns: Dict[str, Pattern]) -> Dict:
    """Scan a file or directory for secrets"""
    logger.info(f"Scanning: {path}")
    result = create_scan_result()
    scanned_hashes: Set[str] = set()

    if path.is_file():
        file_result = scan_file(path, config, rules, compiled_patterns, scanned_hashes)
        if file_result:
            result['files'].append(file_result)
            result['secrets'].extend(file_result['secrets'])
    else:
        files_results, secrets = scan_directory(path, config, rules, compiled_patterns, scanned_hashes)
        result['files'].extend(files_results)
        result['secrets'].extend(secrets)

    # Scan Git history if enabled
    if config.scan_git_history and is_git_repo(path):
        logger.info("Scanning Git history...")
        git_secrets = scan_git_history(path, rules, compiled_patterns, config)
        result['secrets'].extend(git_secrets)

    result['total_files'] = len(result['files'])
    result['total_secrets'] = len(result['secrets'])
    logger.info(f"Scan complete. Files: {result['total_files']}, Secrets: {result['total_secrets']}")
    return result

def scan_directory(directory: Path, config: ScannerConfig, rules: List,
                  compiled_patterns: Dict[str, Pattern], scanned_hashes: Set[str]) -> tuple:
    """Recursively scan directory"""
    files = []
    all_secrets = []
    for file_path in get_scannable_files(directory, config):
        try:
            file_result = scan_file(file_path, config, rules, compiled_patterns, scanned_hashes)
            if file_result:
                files.append(file_result)
                all_secrets.extend(file_result['secrets'])
        except Exception as e:
            logger.warning(f"Error scanning {file_path}: {e}")
    return files, all_secrets

def scan_file(file_path: Path, config: ScannerConfig, rules: List,
              compiled_patterns: Dict[str, Pattern], scanned_hashes: Set[str]) -> Optional[Dict]:
    """Scan a single file for secrets"""
    if not should_scan_file(file_path, config):
        return None
    try:
        # Check file size
        file_size = file_path.stat().st_size
        max_size = config.max_file_size_mb * 1024 * 1024
        if file_size > max_size:
            logger.debug(f"Skipping large file: {file_path} ({file_size} bytes)")
            return None
        # Read file content
        content = read_file_content(file_path)
        if content is None:
            return None
        # Check if we've already scanned this content
        content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
        if content_hash in scanned_hashes:
            logger.debug(f"Skipping duplicate content: {file_path}")
            return None
        scanned_hashes.add(content_hash)
        # Scan for secrets
        secrets = scan_content(content, str(file_path), rules, compiled_patterns, config)
        if secrets:
            logger.debug(f"Found {len(secrets)} secrets in {file_path}")
            return create_file_result(
                path=str(file_path),
                secrets=secrets,
                size=file_size
            )
    except Exception as e:
        logger.warning(f"Error reading file {file_path}: {e}")
    return None

def read_file_content(file_path: Path) -> Optional[str]:
    try:
        content = file_path.read_text(encoding='utf-8', errors='ignore')
        return content
    except UnicodeDecodeError:
        for encoding in ['latin1', 'cp1252', 'iso-8859-1']:
            try:
                content = file_path.read_text(encoding=encoding, errors='ignore')
                return content
            except:
                continue
        else:
            logger.debug(f'Could not decode file: {file_path}')
            return None

def get_scannable_files(directory: Path, config: ScannerConfig) -> Iterator[Path]:
    for item in directory.rglob('*'):
        if item.is_file() and should_scan_file(item, config):
            yield item

def should_scan_file(file_path: Path, config: ScannerConfig) -> bool:
    for pattern in config.exclude_patterns:
        if fnmatch.fnmatch(str(file_path), pattern) or fnmatch.fnmatch(file_path.name, pattern):
            return False
    if config.include_patterns:
        included = False
        for pattern in config.include_patterns:
            if fnmatch.fnmatch(str(file_path), pattern) or fnmatch.fnmatch(file_path.name, pattern):
                included = True
                break
        if not included:
            return False
    scannable_extensions = get_scannable_extensions()
    if file_path.suffix.lower() not in scannable_extensions:
        mime_type, _ = mimetypes.guess_type(str(file_path))
        if mime_type and not mime_type.startswith('text/'):
            return False
    if any(part.startswith('.') for part in file_path.parts):
        allowed_hidden = {'.env', '.gitignore', '.bashrc', '.profile', '.zshrc'}
        if file_path.name not in allowed_hidden:
            return False
    return True

def is_git_repo(path: Path) -> bool:
    try:
        result = subprocess.run(
            ['git', 'rev-parse', '--git-dir'],
            cwd=path if path.is_dir() else path.parent,
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False

def scan_git_history(repo_path: Path, rules: List, compiled_patterns: Dict[str, Pattern],
                    config: ScannerConfig) -> List[Dict]:
    secrets = []
    try:
        result = subprocess.run(
            ['git', 'log', '--pretty=format:%H', '--all'],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode != 0:
            logger.warning('Could not access Git history')
            return secrets
        commits = result.stdout.strip().split('\n')[:100] 
        for commit in commits:
            if not commit:
                continue
            try:
                diff_result = subprocess.run(
                    ['git', 'show', '--pretty=', '--name-only', commit],
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if diff_result.returncode == 0:
                    content_result = subprocess.run(
                        ['git', 'show', commit],
                        cwd=repo_path,
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if content_result.returncode == 0:
                        commit_secrets = scan_content(
                            content_result.stdout,
                            f'git:{commit[:8]}',
                            rules, compiled_patterns, config
                        )
                        secrets.extend(commit_secrets)
            except subprocess.TimeoutExpired:
                logger.warning(f'Timeout processing commit {commit[:8]}')
                continue
            except Exception as e:
                logger.debug(f'Error processing commit {commit[:8]}: {e}')
                continue
    except Exception as e:
        logger.warning(f'Error scanning Git history: {e}')
    return secrets
