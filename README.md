# Git Leak Finder

Search git history for accidentally committed secrets, API keys, credentials, and sensitive files. Scans all branches and full commit history with parallel processing.

## Detection Types

- Private keys (RSA, DSA, EC, OpenSSH, PGP)
- Cloud credentials (AWS, Stripe, GitHub, Google, Slack)
- Database connection strings (MongoDB, PostgreSQL, MySQL, Redis, SQLite)
- Hardcoded passwords and API secrets
- Certificate files (.pem, .key, .p12, .pfx)
- Environment files (.env, .env.local)
- Credential files (credentials.json, credentials.ini)

## Usage

```bash
# Scan current repo
python git-leak.py

# Scan a specific repo
python git-leak.py /path/to/repo

# Limit commits scanned
python git-leak.py ./repo --commits 100

# Save results
python git-leak.py /path/to/repo -o leak-report.json
```

## Requirements
```
git (must be run from within or pointed at a git repository)
Ollama
```
