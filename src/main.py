import argparse
import json
import sys
import logging

from pathlib import Path
from typing import Dict, List, Optional
from scanner import scan_path
from reporters import get_reporter
from config import ScannerConfig
from rules import load_rules, compile_rules


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Python Secrets Scanner - Find sensitive information in codebases',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s /path/to/project                    # Scan a project directory
  %(prog)s file.py --format json               # Scan single file, JSON output
  %(prog)s . --exclude node_modules --verbose  # Scan current dir, exclude node_modules
  %(prog)s . --custom-rules rules.yaml         # Use custom detection rules
        '''
    )
    parser.add_argument('path', help='Path to scan (file or directory)')
    parser.add_argument('--format', choices=['console', 'json', 'csv'], 
                       default='console', help='Output format (default: console)')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--exclude', action='append', default=[],
                       help='Patterns to exclude (can be used multiple times)')
    parser.add_argument('--include', action='append', default=[],
                       help='File patterns to include (can be used multiple times)')
    parser.add_argument('--custom-rules', help='Path to custom rules YAML file')
    parser.add_argument('--severity', choices=['low', 'medium', 'high'], 
                       help='Minimum severity level to report')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--no-git', action='store_true',
                       help='Disable Git history scanning')
    parser.add_argument('--max-file-size', type=int, default=10,
                       help='Maximum file size to scan in MB (default: 10)')
    return parser.parse_args()

def main():
    args = parse_arguments()
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    scan_path_input = Path(args.path)
    if not scan_path_input.exists():
        logger.error(f'Path does not exist: {scan_path_input}')
        sys.exit(1)
    try:
        config = ScannerConfig(
            custom_rules_path=args.custom_rules,
            exclude_patterns=args.exclude,
            include_patterns=args.include,
            min_severity=args.severity,
            scan_git_history=not args.no_git,
            max_file_size_mb=args.max_file_size
        )
        rules = load_rules(config)
        compiled_patterns = compile_rules(rules)
        logger.info(f'Starting scan of: {scan_path_input}')
        results = scan_path(scan_path_input, config, rules, compiled_patterns)
        reporter = get_reporter(args.format)
        if args.output:
            with open(args.output, 'w') as f:
                reporter(results, f)
            logger.info(f'Report saved to: {args.output}')
        else:
            reporter(results, sys.stdout)
        if results['secrets']:
            logger.warning(f"Found {len(results['secrets'])} potential secrets!")
            sys.exit(1)
        else:
            logger.info("No secrets detected.")
            sys.exit(0)
    except KeyboardInterrupt:
        logger.info('Scan interrupted by user')
        sys.exit(1)
    except Exception as e:
        logger.error(f'Scan failed: {e}')
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
