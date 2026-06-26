#!/usr/bin/env python3
"""Git Leak Finder — search git history for accidentally committed secrets and sensitive data."""

import sys
import json
import re
import argparse
import subprocess
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor


SECRET_PATTERNS = [
    (r'(?i)-----BEGIN\s?(RSA|DSA|EC|OPENSSH|PGP)\s?PRIVATE KEY-----', 'Private Key'),
    (r'(?i)sk_live_[0-9a-zA-Z]{10,}', 'Stripe Live Key'),
    (r'(?i)sk_test_[0-9a-zA-Z]{10,}', 'Stripe Test Key'),
    (r'(?i)ghp_[0-9a-zA-Z]{36}', 'GitHub Token'),
    (r'(?i)ghs_[0-9a-zA-Z]{36}', 'GitHub Token'),
    (r'(?i)(?:AKIA|ASIA)[0-9A-Z]{16}', 'AWS Access Key'),
    (r'(?i)AKE[0-9A-Z]{13,}', 'AWS Access Key'),
    (r'(?i)AIza[0-9A-Za-z\-_]{35}', 'Google API Key'),
    (r'(?i)xox[pbarsa]-[0-9a-zA-Z]{10,}', 'Slack Token'),
    (r'(?i)pk_live_[0-9a-zA-Z]{24,}', 'Stripe Publishable Key'),
    (r'(?i)pk_test_[0-9a-zA-Z]{24,}', 'Stripe Test Publishable'),
    (r'(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']', 'Hardcoded Password'),
    (r'(?:secret|api[_-]?key|token)\s*[:=]\s*["\'][^"\']{8,}["\']', 'Secret'),
    (r'password\s*=\s*["\'][^"\']{4,}["\']', 'Password Assignment'),
    (r'mongodb(?:\+srv)?://[^\s\'"]+', 'MongoDB URI'),
    (r'postgresql?://[^\s\'"]+', 'PostgreSQL URI'),
    (r'mysql://[^\s\'"]+', 'MySQL URI'),
    (r'redis://[^\s\'"]+', 'Redis URI'),
    (r'\.pem\b|\.key\b|\.p12\b|\.pfx\b|\.crt\b', 'Certificate/Key File'),
    (r'(?i)-----BEGIN CERTIFICATE-----', 'Certificate'),
    (r'(?i)sqlite:///[^\s]+\.db', 'SQLite Database'),
    (r'\.env\b|\.env\.local\b|\.env\.prod', 'Environment File'),
    (r'credentials?\.(?:json|ini|conf|txt|yml|yaml)', 'Credentials File'),
]


def git_log(repo_path, max_count=1000):
    """Get git log with diffs."""
    try:
        r = subprocess.run(
            ['git', 'log', '--all', '--full-history', '--diff-filter=AM',
             f'-{max_count}', '--format=COMMIT %H %ai %s', '-p'],
            capture_output=True, text=True, timeout=120, cwd=repo_path
        )
        return r.stdout
    except subprocess.TimeoutExpired:
        print("  Git log timed out — limiting scope")
        return ''
    except subprocess.CalledProcessError as e:
        print(f"  Git error: {e.stderr[:200]}")
        return ''
    except FileNotFoundError:
        print("  Git not found — is this a git repository?")
        return ''


def parse_commits(log_output):
    """Parse git log output into commit objects with diffs."""
    commits = []
    current = None
    current_diff = []

    for line in log_output.split('\n'):
        if line.startswith('COMMIT '):
            if current:
                current['diff'] = '\n'.join(current_diff)
                commits.append(current)
            parts = line[7:].split(' ', 2)
            current = {
                'hash': parts[0],
                'date': parts[1] if len(parts) > 1 else '',
                'message': parts[2] if len(parts) > 2 else '',
                'diff': '',
            }
            current_diff = []
        elif current is not None:
            current_diff.append(line)

    if current:
        current['diff'] = '\n'.join(current_diff)
        commits.append(current)

    return commits


def scan_commit(commit, patterns):
    """Scan a commit's diff for secrets."""
    findings = []
    diff = commit.get('diff', '')
    lines = diff.split('\n')

    for i, line in enumerate(lines):
        # Only look at added lines (starting with +)
        if not line.startswith('+'):
            continue
        stripped = line[1:]  # Remove the + prefix

        for pattern, name in patterns:
            m = re.search(pattern, stripped)
            if m:
                findings.append({
                    'commit': commit['hash'][:8],
                    'date': commit['date'],
                    'message': commit['message'][:60],
                    'type': name,
                    'match': stripped.strip()[:80],
                    'line_in_diff': i + 1,
                })
                break  # One finding per line

    return findings


def main():
    parser = argparse.ArgumentParser(description='Git Leak Finder')
    parser.add_argument('repo', nargs='?', default='.', help='Git repository path')
    parser.add_argument('--commits', type=int, default=500, help='Max commits to scan')
    parser.add_argument('--output', '-o', help='Save findings to JSON')
    parser.add_argument('--context', type=int, default=3, help='Lines of context around match')
    args = parser.parse_args()

    repo = Path(args.repo)
    if not (repo / '.git').exists():
        print(f"Not a git repository: {repo}")
        sys.exit(1)

    print(f"Git Leak Finder")
    print(f"{'='*50}")
    print(f"Repository: {repo.resolve()}")
    print(f"Scanning last {args.commits} commits...\n")

    log = git_log(repo, args.commits)
    if not log:
        print("No git history found.")
        return

    commits = parse_commits(log)
    print(f"Parsed {len(commits)} commits")

    # Scan commits in parallel
    all_findings = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(scan_commit, c, SECRET_PATTERNS): c for c in commits}
        import concurrent.futures
        for f in concurrent.futures.as_completed(futures):
            try:
                all_findings.extend(f.result())
            except:
                pass

    all_findings.sort(key=lambda x: x['commit'])

    # Summary by type
    type_counts = {}
    for f in all_findings:
        type_counts[f['type']] = type_counts.get(f['type'], 0) + 1

    print(f"\n{'='*50}")
    print(f"  FOUND {len(all_findings)} POTENTIAL SECRETS")
    print(f"{'='*50}\n")

    for f in all_findings:
        sev = 'CRITICAL' if f['type'] in ('Private Key', 'Stripe Live Key', 'AWS Access Key') else 'HIGH'
        color = '\033[91m' if sev == 'CRITICAL' else '\033[93m'
        print(f"  {color}[{sev}]{'\033[0m'} {f['type']} — {f['commit']} ({f['date'][:10]})")
        print(f"    {f['message']}")
        print(f"    {f['match'][:100]}")

    print(f"\n{'='*50}")
    print(f"  BREAKDOWN BY TYPE")
    print(f"{'='*50}")
    for t, c in sorted(type_counts.items(), key=lambda x: -x[1]):
        print(f"  {t}: {c}")

    print(f"\n  \033[93m[!] Actions to take:\033[0m")
    print(f"  1. Rotate any exposed credentials immediately")
    print(f"  2. Use `git filter-branch` or BFG to remove from history")
    print(f"  3. Add a pre-commit hook to prevent future leaks")

    if args.output:
        with open(args.output, 'w') as f:
            json.dump({'repository': str(repo.resolve()), 'findings': all_findings,
                      'summary': dict(type_counts)}, f, indent=2)
        print(f"\nReport saved: {args.output}")


if __name__ == '__main__':
    main()
