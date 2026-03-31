import json
import re
import shutil
import subprocess
import sys
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEFAULT_RULES = ROOT / "rules" / "custom_ai_security.yml"


def run_cmd(cmd, cwd=None, timeout=900):
    result = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )
    return {
        "command": cmd,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def tool_exists(name):
    return shutil.which(name) is not None


def normalize_severity(value):
    if not value:
        return "UNKNOWN"
    value = str(value).upper()
    return {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
        "NOTE": "LOW",
    }.get(value, value)


def should_skip_file(path: Path) -> bool:
    skip_parts = {
        ".git",
        "node_modules",
        "venv",
        ".venv",
        "dist",
        "build",
        "__pycache__",
        ".next",
        ".nuxt",
        ".idea",
        ".pytest_cache",
        ".mypy_cache",
    }
    return any(part in skip_parts for part in path.parts)


def safe_read_text(path: Path):
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return None


def run_semgrep(target):
    if not tool_exists("semgrep"):
        return {"findings": [], "debug": {"reason": "semgrep not installed"}}

    findings = []
    seen = set()
    debug_runs = []

    commands = []

    if DEFAULT_RULES.exists():
        commands.append([
            "semgrep",
            "scan",
            "--config",
            str(DEFAULT_RULES),
            "--json",
            str(target),
        ])

    commands.append([
        "semgrep",
        "scan",
        "--config",
        "p/security-audit",
        "--json",
        str(target),
    ])

    commands.append([
        "semgrep",
        "scan",
        "--config",
        "p/owasp-top-ten",
        "--json",
        str(target),
    ])

    commands.append([
        "semgrep",
        "scan",
        "--config",
        "p/secrets",
        "--json",
        str(target),
    ])

    for cmd in commands:
        raw = run_cmd(cmd, timeout=600)
        debug_runs.append({
            "command": cmd,
            "returncode": raw.get("returncode"),
            "stderr": raw.get("stderr", "")[:2000],
            "stdout_size": len(raw.get("stdout", "")),
        })

        if raw.get("stdout"):
            try:
                data = json.loads(raw["stdout"])
                for item in data.get("results", []):
                    extra = item.get("extra", {})
                    path = item.get("path")
                    line = item.get("start", {}).get("line")
                    rule_id = item.get("check_id", "semgrep.unknown")

                    dedupe_key = (rule_id, path, line)
                    if dedupe_key in seen:
                        continue
                    seen.add(dedupe_key)

                    findings.append({
                        "tool": "semgrep",
                        "rule_id": rule_id,
                        "severity": normalize_severity(extra.get("severity")),
                        "category": "sast",
                        "title": extra.get("message", "Semgrep finding"),
                        "message": extra.get("message", "Semgrep finding"),
                        "file": path,
                        "line": line,
                    })
            except Exception as exc:
                findings.append({
                    "tool": "semgrep",
                    "rule_id": "semgrep.parse.error",
                    "severity": "LOW",
                    "category": "tooling",
                    "title": "Could not parse Semgrep output",
                    "message": str(exc),
                    "file": None,
                    "line": None,
                })

    return {"findings": findings, "debug": {"runs": debug_runs}}


def run_trivy_fs(target):
    if not tool_exists("trivy"):
        return {"findings": [], "debug": {"reason": "trivy not installed"}}

    raw = run_cmd([
        "trivy",
        "fs",
        "--scanners",
        "vuln",
        "--skip-dirs",
        ".git,node_modules,venv,.venv,dist,build,__pycache__,.next,.nuxt",
        "--quiet",
        "--format",
        "json",
        str(target),
    ], timeout=600)

    findings = []
    debug = {
        "returncode": raw.get("returncode"),
        "stderr": raw.get("stderr", "")[:2000],
        "stdout_size": len(raw.get("stdout", "")),
    }

    if raw.get("stdout"):
        try:
            data = json.loads(raw["stdout"])
            for result in data.get("Results", []):
                target_name = result.get("Target")
                for vuln in result.get("Vulnerabilities", []) or []:
                    findings.append({
                        "tool": "trivy",
                        "rule_id": vuln.get("VulnerabilityID"),
                        "severity": normalize_severity(vuln.get("Severity")),
                        "category": "dependency",
                        "title": vuln.get("Title") or vuln.get("PkgName") or "Dependency vulnerability",
                        "message": vuln.get("Description") or "Dependency vulnerability",
                        "file": target_name,
                        "line": None,
                    })
        except Exception as exc:
            findings.append({
                "tool": "trivy",
                "rule_id": "trivy.parse.error",
                "severity": "LOW",
                "category": "tooling",
                "title": "Could not parse Trivy output",
                "message": str(exc),
                "file": None,
                "line": None,
            })

    return {"findings": findings, "debug": debug}


def run_osv(target):
    if not tool_exists("osv-scanner"):
        return {"findings": [], "debug": {"reason": "osv-scanner not installed"}}

    raw = run_cmd([
        "osv-scanner",
        "scan",
        "--recursive",
        "--format",
        "json",
        str(target),
    ], timeout=600)

    findings = []
    debug = {
        "returncode": raw.get("returncode"),
        "stderr": raw.get("stderr", "")[:2000],
        "stdout_size": len(raw.get("stdout", "")),
    }

    if raw.get("stdout"):
        try:
            data = json.loads(raw["stdout"])
            for result in data.get("results", []) or []:
                source_path = (result.get("source") or {}).get("path")
                for pkg in result.get("packages", []) or []:
                    package_name = (pkg.get("package") or {}).get("name")
                    for vuln in pkg.get("vulnerabilities", []) or []:
                        findings.append({
                            "tool": "osv-scanner",
                            "rule_id": vuln.get("id"),
                            "severity": "HIGH",
                            "category": "dependency",
                            "title": f"OSV finding in {package_name}",
                            "message": vuln.get("summary") or vuln.get("details") or "Dependency vulnerability",
                            "file": source_path,
                            "line": None,
                        })
        except Exception as exc:
            findings.append({
                "tool": "osv-scanner",
                "rule_id": "osv.parse.error",
                "severity": "LOW",
                "category": "tooling",
                "title": "Could not parse OSV output",
                "message": str(exc),
                "file": None,
                "line": None,
            })

    return {"findings": findings, "debug": debug}


def run_ai_checks(target):
    findings = []
    debug = {"files_checked": 0}

    for file in Path(target).rglob("*"):
        if not file.is_file() or should_skip_file(file):
            continue

        content = safe_read_text(file)
        if content is None:
            continue

        debug["files_checked"] += 1
        content_lower = content.lower()

        if "openai" in content_lower and "api_key" in content_lower:
            findings.append({
                "tool": "ai-check",
                "rule_id": "ai.exposed.api_key",
                "severity": "HIGH",
                "category": "ai-security",
                "title": "Possible OpenAI API key exposure",
                "message": "API key usage detected in code near OpenAI integration.",
                "file": str(file),
                "line": None,
            })

        if "anthropic" in content_lower and "api_key" in content_lower:
            findings.append({
                "tool": "ai-check",
                "rule_id": "ai.anthropic.api_key",
                "severity": "HIGH",
                "category": "ai-security",
                "title": "Possible Anthropic API key exposure",
                "message": "API key usage detected in code near Anthropic integration.",
                "file": str(file),
                "line": None,
            })

        if "eval(" in content:
            findings.append({
                "tool": "ai-check",
                "rule_id": "ai.eval.usage",
                "severity": "HIGH",
                "category": "ai-security",
                "title": "Dangerous eval() usage",
                "message": "eval() detected. This is a common insecure AI-generated pattern.",
                "file": str(file),
                "line": None,
            })

        if "exec(" in content:
            findings.append({
                "tool": "ai-check",
                "rule_id": "ai.exec.usage",
                "severity": "HIGH",
                "category": "ai-security",
                "title": "Dangerous exec() usage",
                "message": "exec() detected. This may allow arbitrary code execution.",
                "file": str(file),
                "line": None,
            })

        if "shell=true" in content_lower:
            findings.append({
                "tool": "ai-check",
                "rule_id": "ai.shell.true",
                "severity": "HIGH",
                "category": "ai-security",
                "title": "shell=True usage detected",
                "message": "shell=True is often unsafe and may enable command injection.",
                "file": str(file),
                "line": None,
            })

        if "verify=false" in content_lower:
            findings.append({
                "tool": "ai-check",
                "rule_id": "ai.tls.verify.false",
                "severity": "MEDIUM",
                "category": "ai-security",
                "title": "TLS verification disabled",
                "message": "verify=False detected. TLS certificate validation is disabled.",
                "file": str(file),
                "line": None,
            })

    return {"findings": findings, "debug": debug}


def run_secret_scan(target):
    findings = []
    debug = {"files_checked": 0}

    patterns = [
        ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
        ("GitHub Token", r"github_pat_[A-Za-z0-9_]{20,}"),
        ("OpenAI-style Key", r"sk-[A-Za-z0-9]{20,}"),
        ("Generic API Key", r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*[\"'][^\"'\n]{10,}[\"']"),
    ]

    for file in Path(target).rglob("*"):
        if not file.is_file() or should_skip_file(file):
            continue

        content = safe_read_text(file)
        if content is None:
            continue

        debug["files_checked"] += 1

        for name, pattern in patterns:
            if re.search(pattern, content):
                findings.append({
                    "tool": "secret-scan",
                    "rule_id": "secret.detected",
                    "severity": "HIGH",
                    "category": "secrets",
                    "title": f"{name} detected",
                    "message": "Possible secret found in repository files.",
                    "file": str(file),
                    "line": None,
                })

    return {"findings": findings, "debug": debug}


def run_docker_checks(target):
    findings = []
    debug = {"dockerfiles_checked": 0}

    dockerfiles = list(Path(target).rglob("Dockerfile"))

    for dockerfile in dockerfiles:
        if should_skip_file(dockerfile):
            continue

        content = safe_read_text(dockerfile)
        if content is None:
            continue

        debug["dockerfiles_checked"] += 1
        content_lower = content.lower()

        if ":latest" in content_lower:
            findings.append({
                "tool": "docker-check",
                "rule_id": "docker.latest.tag",
                "severity": "MEDIUM",
                "category": "misconfig",
                "title": "Using latest tag",
                "message": "Avoid using latest tag in Dockerfile base images.",
                "file": str(dockerfile),
                "line": None,
            })

        if "user root" in content_lower or "\nuser root" in content_lower:
            findings.append({
                "tool": "docker-check",
                "rule_id": "docker.root.user",
                "severity": "MEDIUM",
                "category": "misconfig",
                "title": "Container runs as root",
                "message": "Running containers as root increases risk.",
                "file": str(dockerfile),
                "line": None,
            })

        if "add http://" in content_lower or "curl http://" in content_lower or "wget http://" in content_lower:
            findings.append({
                "tool": "docker-check",
                "rule_id": "docker.insecure.download",
                "severity": "MEDIUM",
                "category": "misconfig",
                "title": "Insecure HTTP download in Dockerfile",
                "message": "HTTP downloads in build steps may be insecure.",
                "file": str(dockerfile),
                "line": None,
            })

    return {"findings": findings, "debug": debug}


def calculate_score(findings):
    weights = {
        "CRITICAL": 40,
        "HIGH": 20,
        "MEDIUM": 8,
        "LOW": 3,
        "UNKNOWN": 1,
    }
    return sum(weights.get(item.get("severity", "UNKNOWN"), 1) for item in findings)


def create_sarif(findings, target_name):
    rules = []
    results = []
    seen_rules = set()

    for item in findings:
        rule_id = item.get("rule_id") or "unknown.rule"

        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": item.get("title") or rule_id,
                "shortDescription": {"text": item.get("title") or rule_id},
                "fullDescription": {"text": item.get("message") or item.get("title") or rule_id},
            })

        level = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "UNKNOWN": "note",
        }.get(item.get("severity", "UNKNOWN"), "note")

        location = {
            "physicalLocation": {
                "artifactLocation": {"uri": item.get("file") or "unknown"}
            }
        }

        if item.get("line"):
            location["physicalLocation"]["region"] = {
                "startLine": int(item["line"])
            }

        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": item.get("message") or item.get("title") or rule_id},
            "locations": [location],
        })

    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ai-sec-audit",
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": target_name},
                "results": results,
            }
        ],
    }


def build_html(report):
    rows = []

    for finding in report["findings"]:
        sev = escape(finding.get("severity", "UNKNOWN"))
        cat = escape(finding.get("category", "unknown"))
        file_name = escape(str(finding.get("file") or "unknown"))
        line = finding.get("line") or ""
        title = escape(finding.get("title", "Finding"))
        tool = escape(finding.get("tool", "unknown"))

        rows.append(
            f"<tr><td>{sev}</td><td>{cat}</td><td>{file_name}</td><td>{line}</td><td>{title}</td><td>{tool}</td></tr>"
        )

    if not rows:
        rows = ['<tr><td colspan="6">No findings</td></tr>']

    return f"""<!doctype html>
<html>
<head>
<meta charset='utf-8'/>
<title>AI Security Report</title>
<style>
body {{
    font-family: Arial, sans-serif;
    margin: 24px;
    background: #f7f7fb;
    color: #111827;
}}
.grid {{
    display: grid;
    grid-template-columns: repeat(5, minmax(120px, 1fr));
    gap: 12px;
    margin-bottom: 18px;
}}
.card {{
    background: #fff;
    border-radius: 16px;
    padding: 16px;
    box-shadow: 0 2px 12px rgba(0,0,0,.08);
}}
.small {{
    color: #6b7280;
    font-size: 12px;
    text-transform: uppercase;
    margin-bottom: 8px;
}}
.big {{
    font-size: 28px;
    font-weight: 700;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    background: #fff;
    border-radius: 16px;
    overflow: hidden;
}}
th, td {{
    padding: 10px;
    border-bottom: 1px solid #ececf3;
    text-align: left;
    vertical-align: top;
}}
th {{
    background: #111827;
    color: #fff;
}}
.meta {{
    background: #fff;
    border-radius: 16px;
    padding: 16px;
    margin-bottom: 18px;
    box-shadow: 0 2px 12px rgba(0,0,0,.08);
}}
</style>
</head>
<body>
<h1>AI Security Report</h1>
<p><strong>Target:</strong> {escape(report["target"])}</p>
<p><strong>Scanned path:</strong> {escape(report["scanned_path"])}</p>

<div class='grid'>
    <div class='card'><div class='small'>Score</div><div class='big'>{report["score"]}</div></div>
    <div class='card'><div class='small'>Total</div><div class='big'>{report["findings_count"]}</div></div>
    <div class='card'><div class='small'>Critical</div><div class='big'>{report["severity_totals"]["CRITICAL"]}</div></div>
    <div class='card'><div class='small'>High</div><div class='big'>{report["severity_totals"]["HIGH"]}</div></div>
    <div class='card'><div class='small'>Medium</div><div class='big'>{report["severity_totals"]["MEDIUM"]}</div></div>
</div>

<div class="meta">
    <h2>Tool diagnostics</h2>
    <pre>{escape(json.dumps(report["tools"], ensure_ascii=False, indent=2))}</pre>
</div>

<table>
    <tr>
        <th>Severity</th>
        <th>Category</th>
        <th>File</th>
        <th>Line</th>
        <th>Title</th>
        <th>Tool</th>
    </tr>
    {''.join(rows)}
</table>
</body>
</html>"""


def main():
    if len(sys.argv) < 4:
        print("Usage: python scanner.py /path/to/project <target-name> <output-dir>")
        sys.exit(1)

    target = Path(sys.argv[1]).resolve()
    target_name = sys.argv[2]
    output_dir = Path(sys.argv[3]).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    semgrep_result = run_semgrep(target)
    trivy_result = run_trivy_fs(target)
    osv_result = run_osv(target)
    ai_result = run_ai_checks(target)
    secret_result = run_secret_scan(target)
    docker_result = run_docker_checks(target)

    findings = []
    findings.extend(semgrep_result.get("findings", []))
    findings.extend(trivy_result.get("findings", []))
    findings.extend(osv_result.get("findings", []))
    findings.extend(ai_result.get("findings", []))
    findings.extend(secret_result.get("findings", []))
    findings.extend(docker_result.get("findings", []))

    severity_totals = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }

    for item in findings:
        sev = item.get("severity", "UNKNOWN")
        severity_totals[sev] = severity_totals.get(sev, 0) + 1

    report = {
        "target": target_name,
        "scanned_path": str(target),
        "score": calculate_score(findings),
        "findings_count": len(findings),
        "severity_totals": severity_totals,
        "findings": findings,
        "tools": {
            "semgrep": {
                "available": tool_exists("semgrep"),
                "findings_count": len(semgrep_result.get("findings", [])),
                "debug": semgrep_result.get("debug", {}),
            },
            "trivy": {
                "available": tool_exists("trivy"),
                "findings_count": len(trivy_result.get("findings", [])),
                "debug": trivy_result.get("debug", {}),
            },
            "osv-scanner": {
                "available": tool_exists("osv-scanner"),
                "findings_count": len(osv_result.get("findings", [])),
                "debug": osv_result.get("debug", {}),
            },
            "ai-check": {
                "available": True,
                "findings_count": len(ai_result.get("findings", [])),
                "debug": ai_result.get("debug", {}),
            },
            "secret-scan": {
                "available": True,
                "findings_count": len(secret_result.get("findings", [])),
                "debug": secret_result.get("debug", {}),
            },
            "docker-check": {
                "available": True,
                "findings_count": len(docker_result.get("findings", [])),
                "debug": docker_result.get("debug", {}),
            },
        },
    }

    (output_dir / "security-report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    (output_dir / "security-report.html").write_text(
        build_html(report),
        encoding="utf-8",
    )

    (output_dir / "security-report.sarif").write_text(
        json.dumps(create_sarif(findings, target_name), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    critical_or_high = [
        x for x in findings
        if x.get("severity") in ("CRITICAL", "HIGH")
    ]

    sys.exit(2 if critical_or_high else 0)


if __name__ == "__main__":
    main()