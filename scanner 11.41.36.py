import json
import shutil
import subprocess
import sys
from html import escape
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPORTS_DIR = ROOT / "reports"
DEFAULT_RULES = ROOT / "rules" / "custom_ai_security.yml"


def run_cmd(cmd, cwd=None):
    result = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
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
    mapping = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
        "NOTE": "LOW",
    }
    return mapping.get(value, value)


def run_semgrep(target):
    if not tool_exists("semgrep"):
        return {"skipped": True, "reason": "semgrep not installed", "findings": []}

    findings = []
    commands = [["semgrep", "scan", "--config", "auto", "--json", str(target)]]
    if DEFAULT_RULES.exists():
        commands.append(["semgrep", "scan", "--config", str(DEFAULT_RULES), "--json", str(target)])

    for cmd in commands:
        raw = run_cmd(cmd)
        if raw.get("stdout"):
            try:
                data = json.loads(raw["stdout"])
                for item in data.get("results", []):
                    extra = item.get("extra", {})
                    findings.append({
                        "tool": "semgrep",
                        "rule_id": item.get("check_id", "semgrep.unknown"),
                        "severity": normalize_severity(extra.get("severity")),
                        "category": "sast",
                        "title": extra.get("message", "Semgrep finding"),
                        "message": extra.get("message", "Semgrep finding"),
                        "file": item.get("path"),
                        "line": item.get("start", {}).get("line"),
                        "owasp": extra.get("metadata", {}).get("owasp", []),
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
                    "owasp": [],
                })
    return {"findings": findings}


def run_trivy_fs(target):
    if not tool_exists("trivy"):
        return {"skipped": True, "reason": "trivy not installed", "findings": []}

    raw = run_cmd(["trivy", "fs", "--format", "json", str(target)])
    findings = []
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
                        "message": vuln.get("PrimaryURL") or vuln.get("Description") or "Dependency vulnerability",
                        "file": target_name,
                        "line": None,
                        "owasp": [],
                    })
                for secret in result.get("Secrets", []) or []:
                    findings.append({
                        "tool": "trivy",
                        "rule_id": secret.get("RuleID"),
                        "severity": normalize_severity(secret.get("Severity", "HIGH")),
                        "category": "secret",
                        "title": secret.get("Title", "Potential secret found"),
                        "message": secret.get("Match", "Potential secret found"),
                        "file": secret.get("Target") or target_name,
                        "line": secret.get("StartLine"),
                        "owasp": [],
                    })
                for misconf in result.get("Misconfigurations", []) or []:
                    findings.append({
                        "tool": "trivy",
                        "rule_id": misconf.get("ID"),
                        "severity": normalize_severity(misconf.get("Severity")),
                        "category": "misconfig",
                        "title": misconf.get("Title", "Misconfiguration found"),
                        "message": misconf.get("Description") or misconf.get("Message") or "Misconfiguration found",
                        "file": target_name,
                        "line": None,
                        "owasp": [],
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
                "owasp": [],
            })
    return {"findings": findings}


def run_osv(target):
    if not tool_exists("osv-scanner"):
        return {"skipped": True, "reason": "osv-scanner not installed", "findings": []}

    raw = run_cmd(["osv-scanner", "scan", "--recursive", "--format", "json", str(target)])
    findings = []
    if raw.get("stdout"):
        try:
            data = json.loads(raw["stdout"])
            for result in data.get("results", []) or []:
                source = result.get("source", {})
                source_path = source.get("path")
                for pkg in result.get("packages", []) or []:
                    package_name = pkg.get("package", {}).get("name")
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
                            "owasp": [],
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
                "owasp": [],
            })
    return {"findings": findings}


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
                "properties": {"tags": [item.get("category", "security"), item.get("tool", "scanner")]},
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
                "artifactLocation": {"uri": item.get("file") or "unknown"},
            }
        }
        if item.get("line"):
            location["physicalLocation"]["region"] = {"startLine": int(item["line"])}

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
                        "informationUri": "https://github.com/",
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
  <meta charset="utf-8"/>
  <title>AI Security Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; background: #f7f7fb; color: #111827; }}
    .grid {{ display:grid; grid-template-columns: repeat(5,minmax(120px,1fr)); gap: 12px; margin-bottom: 18px; }}
    .card {{ background:#fff; border-radius:16px; padding:16px; box-shadow:0 2px 12px rgba(0,0,0,.08); }}
    .small {{ color:#6b7280; font-size:12px; text-transform:uppercase; margin-bottom:8px; }}
    .big {{ font-size:28px; font-weight:700; }}
    table {{ width:100%; border-collapse:collapse; background:#fff; border-radius:16px; overflow:hidden; }}
    th, td {{ padding:10px; border-bottom:1px solid #ececf3; text-align:left; vertical-align:top; }}
    th {{ background:#111827; color:#fff; }}
  </style>
</head>
<body>
  <h1>AI Security Report</h1>
  <p><strong>Target:</strong> {escape(report["target"])}</p>
  <p><strong>Scanned path:</strong> {escape(report["scanned_path"])}</p>

  <div class="grid">
    <div class="card"><div class="small">Score</div><div class="big">{report["score"]}</div></div>
    <div class="card"><div class="small">Total</div><div class="big">{report["findings_count"]}</div></div>
    <div class="card"><div class="small">Critical</div><div class="big">{report["severity_totals"]["CRITICAL"]}</div></div>
    <div class="card"><div class="small">High</div><div class="big">{report["severity_totals"]["HIGH"]}</div></div>
    <div class="card"><div class="small">Medium</div><div class="big">{report["severity_totals"]["MEDIUM"]}</div></div>
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
    if len(sys.argv) < 2:
        print("Usage: python scanner.py /path/to/project [target-name] [output-dir]")
        sys.exit(1)

    target = Path(sys.argv[1]).resolve()
    target_name = sys.argv[2] if len(sys.argv) > 2 else target.name
    output_dir = Path(sys.argv[3]) if len(sys.argv) > 3 else REPORTS_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    semgrep = run_semgrep(target)
    trivy = run_trivy_fs(target)
    osv = run_osv(target)

    findings = []
    findings.extend(semgrep.get("findings", []))
    findings.extend(trivy.get("findings", []))
    findings.extend(osv.get("findings", []))

    severity_totals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for item in findings:
        severity = item.get("severity", "UNKNOWN")
        severity_totals[severity] = severity_totals.get(severity, 0) + 1

    score = calculate_score(findings)
    report = {
        "target": target_name,
        "scanned_path": str(target),
        "score": score,
        "findings_count": len(findings),
        "severity_totals": severity_totals,
        "findings": findings,
        "tools": {
            "semgrep": {"available": tool_exists("semgrep")},
            "trivy": {"available": tool_exists("trivy")},
            "osv-scanner": {"available": tool_exists("osv-scanner")},
        },
    }

    with open(output_dir / "security-report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    with open(output_dir / "security-report.html", "w", encoding="utf-8") as f:
        f.write(build_html(report))

    with open(output_dir / "security-report.sarif", "w", encoding="utf-8") as f:
        json.dump(create_sarif(findings, target_name), f, ensure_ascii=False, indent=2)

    critical_or_high = [x for x in findings if x.get("severity") in ("CRITICAL", "HIGH")]
    if critical_or_high:
        print(f"FAILED: found {len(critical_or_high)} critical/high findings")
        sys.exit(2)

    print("PASSED: no critical/high findings")
    sys.exit(0)


if __name__ == "__main__":
    main()
