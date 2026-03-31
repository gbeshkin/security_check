#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SEVERITY_WEIGHTS = {
    "CRITICAL": 40,
    "HIGH": 20,
    "MEDIUM": 8,
    "LOW": 3,
    "INFO": 1,
    "WARNING": 3,
    "ERROR": 20,
    "UNKNOWN": 1,
}

FAIL_SEVERITIES = {"CRITICAL", "HIGH"}


@dataclass
class Finding:
    tool: str
    category: str
    severity: str
    rule_id: str
    title: str
    file: str | None = None
    line: int | None = None
    description: str | None = None
    fix: str | None = None
    owasp: list[str] | None = None
    ai_generated_pattern: bool | None = None


@dataclass
class ToolRun:
    name: str
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    skipped: bool = False
    reason: str | None = None


def run_command(name: str, command: list[str]) -> ToolRun:
    binary = command[0]
    if shutil.which(binary) is None:
        return ToolRun(
            name=name,
            command=command,
            returncode=127,
            stdout="",
            stderr="",
            skipped=True,
            reason=f"'{binary}' is not installed or not available in PATH",
        )

    result = subprocess.run(command, capture_output=True, text=True, check=False)
    return ToolRun(
        name=name,
        command=command,
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )


def safe_json_loads(raw: str, fallback: Any) -> Any:
    try:
        return json.loads(raw) if raw.strip() else fallback
    except json.JSONDecodeError:
        return fallback


def normalize_semgrep(raw: str) -> list[Finding]:
    data = safe_json_loads(raw, {})
    findings: list[Finding] = []
    for item in data.get("results", []):
        meta = item.get("extra", {}).get("metadata", {}) or {}
        findings.append(
            Finding(
                tool="semgrep",
                category="sast",
                severity=(item.get("extra", {}).get("severity") or "UNKNOWN").upper(),
                rule_id=item.get("check_id") or "unknown",
                title=item.get("extra", {}).get("message") or "Semgrep finding",
                file=item.get("path"),
                line=(item.get("start") or {}).get("line"),
                description=item.get("extra", {}).get("message"),
                fix=meta.get("fix"),
                owasp=meta.get("owasp"),
                ai_generated_pattern=meta.get("ai_generated_pattern"),
            )
        )
    return findings


def normalize_trivy(raw: str) -> list[Finding]:
    data = safe_json_loads(raw, {})
    findings: list[Finding] = []

    for result in data.get("Results", []):
        target = result.get("Target")

        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append(
                Finding(
                    tool="trivy",
                    category="dependency",
                    severity=(vuln.get("Severity") or "UNKNOWN").upper(),
                    rule_id=vuln.get("VulnerabilityID") or "unknown",
                    title=vuln.get("Title") or f"Vulnerable package: {vuln.get('PkgName', 'unknown')}",
                    file=target,
                    description=vuln.get("Description"),
                    fix=vuln.get("FixedVersion"),
                )
            )

        for secret in result.get("Secrets", []) or []:
            findings.append(
                Finding(
                    tool="trivy",
                    category="secret",
                    severity=(secret.get("Severity") or "HIGH").upper(),
                    rule_id=secret.get("RuleID") or "secret",
                    title=secret.get("Title") or "Potential secret found",
                    file=secret.get("Target") or target,
                    line=secret.get("StartLine"),
                    description=secret.get("Match"),
                )
            )

        for misconf in result.get("Misconfigurations", []) or []:
            findings.append(
                Finding(
                    tool="trivy",
                    category="misconfig",
                    severity=(misconf.get("Severity") or "UNKNOWN").upper(),
                    rule_id=misconf.get("ID") or "misconfig",
                    title=misconf.get("Title") or "Misconfiguration",
                    file=target,
                    description=misconf.get("Description"),
                    fix=misconf.get("Resolution"),
                )
            )

    return findings


def normalize_osv(raw: str) -> list[Finding]:
    data = safe_json_loads(raw, {})
    findings: list[Finding] = []

    for result in data.get("results", []) or []:
        packages = result.get("packages", []) or []
        for pkg in packages:
            pkg_name = pkg.get("package", {}).get("name") or "unknown"
            for vuln in pkg.get("vulnerabilities", []) or []:
                findings.append(
                    Finding(
                        tool="osv-scanner",
                        category="dependency",
                        severity="HIGH",
                        rule_id=vuln.get("id") or "unknown",
                        title=f"Known vulnerability in dependency {pkg_name}",
                        file=result.get("source", {}).get("path"),
                        description=vuln.get("summary") or vuln.get("details"),
                    )
                )
    return findings


def calculate_score(findings: list[Finding]) -> int:
    return sum(SEVERITY_WEIGHTS.get(f.severity.upper(), 1) for f in findings)


def summarize(findings: list[Finding]) -> dict[str, Any]:
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    by_tool: dict[str, int] = {}

    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_category[finding.category] = by_category.get(finding.category, 0) + 1
        by_tool[finding.tool] = by_tool.get(finding.tool, 0) + 1

    return {
        "by_severity": dict(sorted(by_severity.items())),
        "by_category": dict(sorted(by_category.items())),
        "by_tool": dict(sorted(by_tool.items())),
    }


def write_html_report(path: Path, report: dict[str, Any]) -> None:
    findings_rows = []
    for f in report["findings"]:
        findings_rows.append(
            "<tr>"
            f"<td>{f['severity']}</td>"
            f"<td>{f['tool']}</td>"
            f"<td>{f['category']}</td>"
            f"<td>{f['rule_id']}</td>"
            f"<td>{f['title']}</td>"
            f"<td>{f.get('file') or ''}</td>"
            f"<td>{f.get('line') or ''}</td>"
            "</tr>"
        )

    html = f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <title>AI Security Audit Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; }}
    h1, h2 {{ margin-bottom: 0.4rem; }}
    .summary {{ display: flex; gap: 2rem; flex-wrap: wrap; margin-bottom: 2rem; }}
    .card {{ border: 1px solid #ddd; border-radius: 8px; padding: 1rem; min-width: 220px; }}
    table {{ border-collapse: collapse; width: 100%; font-size: 14px; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; vertical-align: top; text-align: left; }}
    th {{ background: #f6f6f6; }}
    code {{ background: #f3f3f3; padding: 2px 4px; }}
  </style>
</head>
<body>
  <h1>AI Security Audit Report</h1>
  <p><strong>Target:</strong> <code>{report['target']}</code></p>
  <p><strong>Generated:</strong> {report['generated_at']}</p>
  <div class=\"summary\">
    <div class=\"card\"><strong>Score</strong><br>{report['score']}</div>
    <div class=\"card\"><strong>Total findings</strong><br>{report['findings_count']}</div>
    <div class=\"card\"><strong>Fail severities</strong><br>{', '.join(report['fail_on'])}</div>
  </div>
  <h2>Summary</h2>
  <pre>{json.dumps(report['summary'], indent=2, ensure_ascii=False)}</pre>
  <h2>Findings</h2>
  <table>
    <thead>
      <tr>
        <th>Severity</th><th>Tool</th><th>Category</th><th>Rule ID</th><th>Title</th><th>File</th><th>Line</th>
      </tr>
    </thead>
    <tbody>
      {''.join(findings_rows) if findings_rows else '<tr><td colspan="7">No findings</td></tr>'}
    </tbody>
  </table>
</body>
</html>
"""
    path.write_text(html, encoding="utf-8")


def build_report(target: Path, tool_runs: list[ToolRun], findings: list[Finding], fail_on: set[str]) -> dict[str, Any]:
    return {
        "target": str(target),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "score": calculate_score(findings),
        "findings_count": len(findings),
        "summary": summarize(findings),
        "fail_on": sorted(fail_on),
        "findings": [asdict(f) for f in findings],
        "tools": [asdict(t) for t in tool_runs],
    }


def parse_fail_on(value: str) -> set[str]:
    return {part.strip().upper() for part in value.split(",") if part.strip()}


def main() -> int:
    parser = argparse.ArgumentParser(description="Unified security scanner for AI-assisted projects")
    parser.add_argument("target", nargs="?", default=".", help="Path to project")
    parser.add_argument("--report-dir", default="reports", help="Where to save output reports")
    parser.add_argument("--semgrep-config", default="rules/custom_ai_security.yml", help="Semgrep rules file")
    parser.add_argument("--fail-on", default="CRITICAL,HIGH", help="Comma-separated severities that fail the run")
    args = parser.parse_args()

    target = Path(args.target).resolve()
    report_dir = Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    fail_on = parse_fail_on(args.fail_on)

    tool_runs = [
        run_command(
            "semgrep",
            [
                "semgrep",
                "scan",
                "--config",
                args.semgrep_config,
                "--json",
                str(target),
            ],
        ),
        run_command(
            "trivy",
            [
                "trivy",
                "fs",
                "--scanners",
                "vuln,secret,misconfig",
                "--format",
                "json",
                str(target),
            ],
        ),
        run_command(
            "osv-scanner",
            [
                "osv-scanner",
                "scan",
                "source",
                "--recursive",
                "--json",
                str(target),
            ],
        ),
    ]

    findings: list[Finding] = []
    for tool_run in tool_runs:
        if tool_run.skipped:
            continue
        if tool_run.name == "semgrep":
            findings.extend(normalize_semgrep(tool_run.stdout))
        elif tool_run.name == "trivy":
            findings.extend(normalize_trivy(tool_run.stdout))
        elif tool_run.name == "osv-scanner":
            findings.extend(normalize_osv(tool_run.stdout))

    report = build_report(target, tool_runs, findings, fail_on)

    json_path = report_dir / "security-report.json"
    html_path = report_dir / "security-report.html"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    write_html_report(html_path, report)

    print(f"Saved JSON report to: {json_path}")
    print(f"Saved HTML report to: {html_path}")
    print(f"Total findings: {report['findings_count']}")
    print(f"Score: {report['score']}")

    failed = [f for f in findings if f.severity.upper() in fail_on]
    if failed:
        print(f"Security gate failed: {len(failed)} finding(s) match fail severities {sorted(fail_on)}")
        return 2

    print("Security gate passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())