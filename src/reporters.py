import json
import csv

from typing import TextIO, Dict
from datetime import datetime
from models import scan_result_to_dict, Severity


def create_console_reporter(use_colors: bool = True) -> dict:
    colors = {
        'red': '\033[91m',
        'yellow': '\033[93m',
        'green': '\033[92m',
        'blue': '\033[94m',
        'magenta': '\033[95m',
        'cyan': '\033[96m',
        'white': '\033[97m',
        'bold': '\033[1m',
        'underline': '\033[4m',
        'reset': '\033[0m'
    } if use_colors else {k: '' for k in ['red', 'yellow', 'green', 'blue', 'magenta', 'cyan', 'white', 'bold', 'underline', 'reset']}
    return {
        'colors': colors,
        'generate_report': lambda result, output: generate_console_report(result, output, colors)
    }

def generate_console_report(result: Dict, output, colors: dict) -> None:
    print_header(output, result, colors)
    print_summary(output, result, colors)
    if result['secrets']:
        print_secrets(output, result, colors)
    else:
        output.write(f"\n{colors['green']}✓ No secrets detected!{colors['reset']}\n")
    print_footer(output, result, colors)

def print_header(output, result: Dict, colors: dict) -> None:
    output.write(f"\n{colors['bold']}{colors['blue']}")
    output.write("=" * 60 + "\n")
    output.write("🔍 PYTHON SECRETS SCANNER REPORT\n")
    output.write("=" * 60 + "\n")
    output.write(f"{colors['reset']}")
    if result['scan_time']:
        output.write(f"Scan completed: {result['scan_time'].strftime('%Y-%m-%d %H:%M:%S')}\n")

def print_summary(output, result: Dict, colors: dict) -> None:
    output.write(f"\n{colors['bold']}SUMMARY{colors['reset']}\n")
    output.write("-" * 20 + "\n")
    output.write(f"Files scanned: {result['total_files']}\n")
    output.write(f"Secrets found: {result['total_secrets']}\n")
    if result['secrets']:
        summary = get_severity_summary(result['secrets'])
        output.write(f"\nBy severity:\n")
        if summary['critical'] > 0:
            output.write(f"  {colors['red']}● CRITICAL: {summary['critical']}{colors['reset']}\n")
        if summary['high'] > 0:
            output.write(f"  {colors['magenta']}● HIGH:     {summary['high']}{colors['reset']}\n")
        if summary['medium'] > 0:
            output.write(f"  {colors['yellow']}● MEDIUM:   {summary['medium']}{colors['reset']}\n")
        if summary['low'] > 0:
            output.write(f"  {colors['cyan']}● LOW:      {summary['low']}{colors['reset']}\n")

def get_severity_summary(secrets: list) -> dict:
    return {
        'critical': len([s for s in secrets if s['severity'] == Severity.CRITICAL]),
        'high': len([s for s in secrets if s['severity'] == Severity.HIGH]),
        'medium': len([s for s in secrets if s['severity'] == Severity.MEDIUM]),
        'low': len([s for s in secrets if s['severity'] == Severity.LOW])
    }

def print_secrets(output, result: Dict, colors: dict) -> None:
    output.write(f"\n{colors['bold']}FINDINGS{colors['reset']}\n")
    output.write("-" * 20 + "\n")
    files_with_secrets = group_secrets_by_file(result['secrets'])
    for file_path, secrets in files_with_secrets.items():
        output.write(f"\n{colors['bold']}{colors['underline']}{file_path}{colors['reset']}\n")
        for secret in secrets:
            severity_color = get_severity_color(secret['severity'], colors)
            output.write(f"\n  {severity_color}[{secret['severity'].value.upper()}]{colors['reset']} {secret['rule_name']}\n")
            output.write(f"  Line {secret['line_number']}, Column {secret['column_start']}-{secret['column_end']}\n")
            output.write(f"  {secret['description']}\n")
            matched_text = secret['matched_text']
            if len(matched_text) > 80:
                matched_text = matched_text[:77] + "..."
            output.write(f"  Match: {colors['bold']}{matched_text}{colors['reset']}\n")
            if secret['confidence'] < 1.0:
                output.write(f"  Confidence: {secret['confidence']:.2f}\n")

def group_secrets_by_file(secrets: list) -> dict:
    files_with_secrets = {}
    for secret in secrets:
        if secret['file_path'] not in files_with_secrets:
            files_with_secrets[secret['file_path']] = []
        files_with_secrets[secret['file_path']].append(secret)
    return files_with_secrets

def print_footer(output, result: Dict, colors: dict) -> None:
    output.write(f"\n{colors['blue']}")
    output.write("=" * 60 + "\n")
    if result['errors']:
        output.write(f"{colors['yellow']}Errors encountered: {len(result['errors'])}{colors['reset']}\n")
        for error in result['errors'][:5]:
            output.write(f"  • {error}\n")
    output.write(f"{colors['reset']}")

def get_severity_color(severity: Severity, colors: dict) -> str:
    severity_colors = {
        Severity.CRITICAL: colors['red'],
        Severity.HIGH: colors['magenta'],
        Severity.MEDIUM: colors['yellow'],
        Severity.LOW: colors['cyan']
    }
    return severity_colors.get(severity, colors['white'])

def generate_json_report(result: Dict, output) -> None:
    json.dump(scan_result_to_dict(result), output, indent=2, ensure_ascii=False)
    output.write('\n')

def generate_csv_report(result: Dict, output: TextIO) -> None:
    if not result.secrets:
        writer = csv.writer(output)
        writer.writerow([
            'file_path', 'rule_name', 'severity', 'line_number',
            'column_start', 'column_end', 'description', 'matched_text', 'confidence'
        ])
        return
    writer = csv.writer(output)
    writer.writerow([
        'file_path', 'rule_name', 'severity', 'line_number',
        'column_start', 'column_end', 'description', 'matched_text', 'confidence'
    ])
    for secret in result.secrets:
        matched_text = secret.matched_text
        if len(matched_text) > 100:
            matched_text = matched_text[:97] + '...'
        writer.writerow([
            secret.file_path,
            secret.rule_name,
            secret.severity.value,
            secret.line_number,
            secret.column_start,
            secret.column_end,
            secret.description,
            matched_text,
            secret.confidence
        ])

def get_reporter(format_type: str, use_colors: bool = True):
    if format_type == 'json':
        return generate_json_report
    elif format_type == 'csv':
        return generate_csv_report
    else:
        return lambda result, output: generate_console_report(result, output, create_console_reporter(use_colors)['colors'])
