# github-leak-scanner

[![CI](https://github.com/Dox46/github-leak-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/Dox46/github-leak-scanner/actions/workflows/ci.yml)
A command-line tool to scan GitHub repositories for accidentally exposed secrets.

Detects AWS keys, GitHub tokens, private keys, API keys, and more.

## Installation
```bash
pip install github-leak-scanner
```

## Key Features

- **Blazing Fast**: Uses Native Python Multiprocessing (`ProcessPoolExecutor`) to scan repositories on all available CPU cores.
- **Heuristic Detection**: Uses Shannon Entropy analysis to catch unknown high-entropy secrets and tokens that bypass standard regex.
- **Fail-Fast Validation**: Instantly validates GitHub URLs to prevent redundant network requests.
- **JSON Export**: Export detailed security findings for CI/CD pipelines.

## Usage
```bash
leak-scan https://github.com/user/repo
```

Export findings to JSON:
```bash
leak-scan https://github.com/user/repo --output report.json
```

## What it detects

| Pattern                   | Severity |
|---------------------------|----------|
| AWS Access Key ID         | HIGH     |
| AWS Secret Access Key     | HIGH     |
| GitHub Personal Token     | HIGH     |
| GitHub OAuth Token        | HIGH     |
| Private Key (RSA/SSH/EC)  | HIGH     |
| Generic API Key           | MEDIUM   |
| Generic Password          | MEDIUM   |
| Generic Token/Secret      | MEDIUM   |
| High Entropy String       | MEDIUM   |

## How it works

1. Validates the GitHub URL for correctness
2. Clones the target repository into an isolated temporary directory
3. Distributes the files across a Multiprocessing Pool for concurrent scanning
4. Scans every file using Regex pattern matching
5. Falls back to Shannon Entropy analysis on long unrecognised words
6. Reports findings with file name, line number, and severity
7. Automatically cleans up the temporary directory securely

## Limitations

- Scans public repositories only
- Does not modify or fix detected secrets

## Development
```bash
git clone https://github.com/your-username/github-leak-scanner
cd github-leak-scanner
pip install -e ".[dev]"
pytest tests/ -v
```

## License

MIT