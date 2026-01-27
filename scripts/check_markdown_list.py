#!/usr/bin/env python3
"""
Check markdown files for missing blank lines before list items.

This script identifies places where text is immediately followed by a list item
without a blank line, which can cause rendering issues in markdown parsers.
"""

import argparse
import os
import re
import sys
from pathlib import Path


def get_indentation(line):
    """Get the number of leading spaces/tabs in a line."""
    return len(line) - len(line.lstrip())


def is_list_item(line):
    """Check if a line is a list item (ordered, unordered, or nested)."""
    stripped = line.lstrip()
    # Unordered list: starts with -, *, or +
    if re.match(r'^[-*+]\s', stripped):
        return True
    # Ordered list: starts with number followed by . or )
    if re.match(r'^\d+[.)]\s', stripped):
        return True
    return False


def is_blank(line):
    """Check if a line is blank or whitespace only."""
    return line.strip() == ''


def is_code_fence(line):
    """Check if a line is a code fence."""
    stripped = line.strip()
    return stripped.startswith('```') or stripped.startswith('~~~')


def is_within_list_context(lines, current_idx):
    """
    Check if we're currently within a list context by looking backwards.
    Returns True if there's a recent list item without intervening blank lines.
    """
    # Look back up to 10 lines for a list item
    for i in range(current_idx - 1, max(current_idx - 10, -1), -1):
        line = lines[i]

        if is_blank(line):
            # Hit a blank line, no longer in list context
            return False

        if is_list_item(line):
            # Found a list item, we're in list context
            return True

    return False


def needs_blank_line_before_list(lines, current_idx):
    """
    Determine if a blank line is needed before the current line.

    Returns True if:
    - Current line is a list item
    - Previous line is NOT blank
    - Previous line is NOT a code fence
    - We're NOT already within a list context
    - Previous line is NOT a list item
    - Current line is NOT more indented (nested list)
    """
    if current_idx == 0:
        return False

    curr_line = lines[current_idx]
    prev_line = lines[current_idx - 1]

    if not is_list_item(curr_line):
        return False

    if is_blank(prev_line):
        return False

    # If previous line is a code fence, no blank line needed
    if is_code_fence(prev_line):
        return False

    # If previous line is also a list item, no blank line needed
    if is_list_item(prev_line):
        return False

    # Check if we're within a list context (continuing list)
    if is_within_list_context(lines, current_idx):
        return False

    # Get indentation levels
    prev_indent = get_indentation(prev_line)
    curr_indent = get_indentation(curr_line)

    # If current line is more indented than previous, it's likely a nested list
    # Allow some flexibility (at least 2 spaces more for nesting)
    if curr_indent > prev_indent + 1:
        return False

    # If previous line ends with certain patterns, it might be okay
    prev_stripped = prev_line.strip()

    # Skip if previous line looks like a heading
    if prev_stripped.startswith('#'):
        return False

    # Skip if previous line is HTML/markdown directive
    if prev_stripped.startswith('<') or prev_stripped.startswith('>'):
        return False

    # Otherwise, we likely need a blank line
    return True


def check_file(filepath):
    """Check a single markdown file for formatting issues."""
    issues = []

    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    in_code_block = False

    for i, line in enumerate(lines):
        # Track code blocks to skip them
        if is_code_fence(line):
            in_code_block = not in_code_block
            continue

        if in_code_block:
            continue

        # Check if we need a blank line before this line
        if needs_blank_line_before_list(lines, i):
            issues.append({
                'line_num': i + 1,
                'line': line.rstrip(),
                'prev_line': lines[i - 1].rstrip()
            })

    return issues


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Check markdown files for missing blank lines before list items.'
    )
    parser.add_argument(
        'paths',
        nargs='*',
        help='Files or directories to check (default: docs/ directory)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show all files being checked, not just files with issues'
    )

    args = parser.parse_args()

    if args.paths:
        # Check if argument is a directory or file(s)
        files_to_check = []
        for path_str in args.paths:
            arg_path = Path(path_str)
            if arg_path.is_dir():
                # Recursively find all .md files in directory
                files_to_check.extend(arg_path.rglob('*.md'))
            elif arg_path.is_file():
                # Add specific file
                files_to_check.append(arg_path)
            else:
                print(f"Warning: {path_str} is not a valid file or directory")
    else:
        # Check all markdown files in docs/
        docs_dir = Path(__file__).parent.parent / 'docs'
        if not docs_dir.exists():
            print(f"Error: docs directory not found at {docs_dir}")
            return 1

        files_to_check = list(docs_dir.rglob('*.md'))

    total_issues = 0
    files_with_issues = []

    for filepath in files_to_check:
        filepath = Path(filepath)
        if not filepath.exists():
            print(f"Warning: {filepath} does not exist")
            continue

        if args.verbose:
            print(f"Checking {filepath}...", end='', flush=True)

        issues = check_file(filepath)

        if issues:
            if args.verbose:
                print(f" {len(issues)} issue(s) found")
            else:
                print(f"{filepath}: {len(issues)} issue(s) found")

            files_with_issues.append(filepath)
            total_issues += len(issues)
            for issue in issues:
                print(f"  Line {issue['line_num']}: Missing blank line before list item")
                print(f"    Previous: {issue['prev_line']}")
                print(f"    Current:  {issue['line']}")
        else:
            if args.verbose:
                print(" OK")

    if total_issues > 0:
        print(f"\nFound {total_issues} issue(s) in {len(files_with_issues)} file(s)")
        return 1
    else:
        if args.verbose:
            print("No issues found!")
        return 0


if __name__ == '__main__':
    sys.exit(main())
