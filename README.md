# AI Security Audit

A first public version of a GitHub-friendly security gate for projects written fully or partially with AI assistance.

It combines three layers:
- **Semgrep** for custom SAST rules focused on common AI-generated coding mistakes
- **Trivy** for vulnerabilities, secrets, and misconfigurations
- **OSV-Scanner** for dependency vulnerabilities

The scanner produces:
- `reports/security-report.json`
- `reports/security-report.html`

It also fails CI when it finds `CRITICAL` or `HIGH` issues by default.

## Why this exists

AI-generated code is often fast to produce, but it can introduce the same repeated mistakes:
- `eval()` and dynamic execution
- `shell=True` and command injection risk
- disabled TLS verification
- hardcoded secrets
- insecure defaults in configuration
- vulnerable dependencies

This repository adds a practical first gate before shipping code.

## Repository structure

```text
.
├── .github/workflows/security-gate.yml
├── rules/custom_ai_security.yml
├── scanner.py
└── reports/
```

## Local run

### 1. Install tools

Semgrep documents local scanning with `semgrep scan --config auto`, and custom rules can be passed with `--config`.

Trivy supports filesystem scans and JSON output for results.

OSV-Scanner supports `scan source`, recursive scans, and JSON output.

Example setup:

```bash
pip install semgrep
brew install trivy
# install osv-scanner from official releases or package manager
```

### 2. Run the scanner

```bash
python scanner.py .
```

Or scan another repository:

```bash
python scanner.py /path/to/project
```

### 3. Open the reports

```bash
open reports/security-report.html
cat reports/security-report.json
```

## GitHub setup

1. Create a new GitHub repository.
2. Copy these files into it.
3. Commit and push to `main`.
4. GitHub Actions will run automatically on pushes and pull requests.
5. Download the generated artifact `ai-security-report` from the workflow run.

GitHub recommends `actions/upload-artifact@v4` for workflow artifacts.

## How it fails builds

By default, the scanner exits with code `2` if any finding has severity:
- `CRITICAL`
- `HIGH`

You can change this locally:

```bash
python scanner.py . --fail-on CRITICAL,HIGH,MEDIUM
```

## Example output model

Each finding is normalized into one structure:

```json
{
  "tool": "semgrep",
  "category": "sast",
  "severity": "HIGH",
  "rule_id": "python-subprocess-shell-true",
  "title": "shell=True may enable command injection.",
  "file": "app/utils/export.py",
  "line": 54,
  "description": "shell=True may enable command injection.",
  "fix": "Pass command arguments as a list and validate untrusted input.",
  "owasp": ["A03:2021-Injection"],
  "ai_generated_pattern": true
}
```

## Good first improvements

- Add SARIF export for GitHub Code Scanning
- Add more language-specific rules for Java, Go, and C#
- Add Docker image scanning mode
- Add a baseline mode to suppress old accepted findings
- Add issue creation in GitHub or Jira
- Add a small public website where people can upload a report and compare scores

## Notes

This first version is intentionally simple. It is designed to be understandable, easy to fork, and easy to extend.