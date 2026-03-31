import json
import shutil
import subprocess
import sys
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEFAULT_RULES = ROOT / "rules" / "custom_ai_security.yml"

def run_cmd(cmd, cwd=None, timeout=1800):
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False, timeout=timeout)
    return {"command": cmd, "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}

def tool_exists(name):
    return shutil.which(name) is not None

def normalize_severity(value):
    if not value:
        return "UNKNOWN"
    value = str(value).upper()
    return {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW", "NOTE": "LOW"}.get(value, value)

def run_semgrep(target):
    if not tool_exists("semgrep"):
        return {"findings": []}
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
                    })
            except Exception as exc:
                findings.append({"tool":"semgrep","rule_id":"semgrep.parse.error","severity":"LOW","category":"tooling","title":"Could not parse Semgrep output","message":str(exc),"file":None,"line":None})
    return {"findings": findings}

def run_trivy_fs(target):
    if not tool_exists("trivy"):
        return {"findings": []}
    raw = run_cmd(["trivy", "fs", "--format", "json", str(target)])
    findings = []
    if raw.get("stdout"):
        try:
            data = json.loads(raw["stdout"])
            for result in data.get("Results", []):
                target_name = result.get("Target")
                for vuln in result.get("Vulnerabilities", []) or []:
                    findings.append({"tool":"trivy","rule_id":vuln.get("VulnerabilityID"),"severity":normalize_severity(vuln.get("Severity")),"category":"dependency","title":vuln.get("Title") or vuln.get("PkgName") or "Dependency vulnerability","message":vuln.get("Description") or "Dependency vulnerability","file":target_name,"line":None})
                for secret in result.get("Secrets", []) or []:
                    findings.append({"tool":"trivy","rule_id":secret.get("RuleID"),"severity":normalize_severity(secret.get("Severity", "HIGH")),"category":"secret","title":secret.get("Title", "Potential secret found"),"message":secret.get("Match", "Potential secret found"),"file":secret.get("Target") or target_name,"line":secret.get("StartLine")})
                for misconf in result.get("Misconfigurations", []) or []:
                    findings.append({"tool":"trivy","rule_id":misconf.get("ID"),"severity":normalize_severity(misconf.get("Severity")),"category":"misconfig","title":misconf.get("Title", "Misconfiguration found"),"message":misconf.get("Description") or misconf.get("Message") or "Misconfiguration found","file":target_name,"line":None})
        except Exception as exc:
            findings.append({"tool":"trivy","rule_id":"trivy.parse.error","severity":"LOW","category":"tooling","title":"Could not parse Trivy output","message":str(exc),"file":None,"line":None})
    return {"findings": findings}

def run_osv(target):
    if not tool_exists("osv-scanner"):
        return {"findings": []}
    raw = run_cmd(["osv-scanner", "scan", "--recursive", "--format", "json", str(target)])
    findings = []
    if raw.get("stdout"):
        try:
            data = json.loads(raw["stdout"])
            for result in data.get("results", []) or []:
                source_path = (result.get("source") or {}).get("path")
                for pkg in result.get("packages", []) or []:
                    package_name = (pkg.get("package") or {}).get("name")
                    for vuln in pkg.get("vulnerabilities", []) or []:
                        findings.append({"tool":"osv-scanner","rule_id":vuln.get("id"),"severity":"HIGH","category":"dependency","title":f"OSV finding in {package_name}","message":vuln.get("summary") or vuln.get("details") or "Dependency vulnerability","file":source_path,"line":None})
        except Exception as exc:
            findings.append({"tool":"osv-scanner","rule_id":"osv.parse.error","severity":"LOW","category":"tooling","title":"Could not parse OSV output","message":str(exc),"file":None,"line":None})
    return {"findings": findings}

def calculate_score(findings):
    weights = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 3, "UNKNOWN": 1}
    return sum(weights.get(item.get("severity", "UNKNOWN"), 1) for item in findings)

def create_sarif(findings, target_name):
    rules, results, seen_rules = [], [], set()
    for item in findings:
        rule_id = item.get("rule_id") or "unknown.rule"
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append({"id": rule_id, "name": item.get("title") or rule_id, "shortDescription": {"text": item.get("title") or rule_id}, "fullDescription": {"text": item.get("message") or item.get("title") or rule_id}})
        level = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "UNKNOWN": "note"}.get(item.get("severity", "UNKNOWN"), "note")
        location = {"physicalLocation": {"artifactLocation": {"uri": item.get("file") or "unknown"}}}
        if item.get("line"):
            location["physicalLocation"]["region"] = {"startLine": int(item["line"])}
        results.append({"ruleId": rule_id, "level": level, "message": {"text": item.get("message") or item.get("title") or rule_id}, "locations": [location]})
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "ai-sec-audit", "rules": rules}}, "automationDetails": {"id": target_name}, "results": results}]}

def build_html(report):
    rows = []
    for finding in report["findings"]:
        sev = escape(finding.get("severity", "UNKNOWN"))
        cat = escape(finding.get("category", "unknown"))
        file_name = escape(str(finding.get("file") or "unknown"))
        line = finding.get("line") or ""
        title = escape(finding.get("title", "Finding"))
        tool = escape(finding.get("tool", "unknown"))
        rows.append(f"<tr><td>{sev}</td><td>{cat}</td><td>{file_name}</td><td>{line}</td><td>{title}</td><td>{tool}</td></tr>")
    if not rows:
        rows = ['<tr><td colspan="6">No findings</td></tr>']
    return f"""<!doctype html><html><head><meta charset='utf-8'/><title>AI Security Report</title><style>body{{font-family:Arial,sans-serif;margin:24px;background:#f7f7fb;color:#111827}}.grid{{display:grid;grid-template-columns:repeat(5,minmax(120px,1fr));gap:12px;margin-bottom:18px}}.card{{background:#fff;border-radius:16px;padding:16px;box-shadow:0 2px 12px rgba(0,0,0,.08)}}.small{{color:#6b7280;font-size:12px;text-transform:uppercase;margin-bottom:8px}}.big{{font-size:28px;font-weight:700}}table{{width:100%;border-collapse:collapse;background:#fff;border-radius:16px;overflow:hidden}}th,td{{padding:10px;border-bottom:1px solid #ececf3;text-align:left;vertical-align:top}}th{{background:#111827;color:#fff}}</style></head><body><h1>AI Security Report</h1><p><strong>Target:</strong> {escape(report["target"])}</p><p><strong>Scanned path:</strong> {escape(report["scanned_path"])}</p><div class='grid'><div class='card'><div class='small'>Score</div><div class='big'>{report["score"]}</div></div><div class='card'><div class='small'>Total</div><div class='big'>{report["findings_count"]}</div></div><div class='card'><div class='small'>Critical</div><div class='big'>{report["severity_totals"]["CRITICAL"]}</div></div><div class='card'><div class='small'>High</div><div class='big'>{report["severity_totals"]["HIGH"]}</div></div><div class='card'><div class='small'>Medium</div><div class='big'>{report["severity_totals"]["MEDIUM"]}</div></div></div><table><tr><th>Severity</th><th>Category</th><th>File</th><th>Line</th><th>Title</th><th>Tool</th></tr>{''.join(rows)}</table></body></html>"""

def main():
    if len(sys.argv) < 2:
        print("Usage: python scanner.py /path/to/project [target-name] [output-dir]")
        sys.exit(1)
    target = Path(sys.argv[1]).resolve()
    target_name = sys.argv[2] if len(sys.argv) > 2 else target.name
    output_dir = Path(sys.argv[3]) if len(sys.argv) > 3 else (ROOT / "reports")
    output_dir.mkdir(parents=True, exist_ok=True)
    findings = []
    findings.extend(run_semgrep(target).get("findings", []))
    findings.extend(run_trivy_fs(target).get("findings", []))
    findings.extend(run_osv(target).get("findings", []))
    severity_totals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for item in findings:
        severity = item.get("severity", "UNKNOWN")
        severity_totals[severity] = severity_totals.get(severity, 0) + 1
    report = {"target": target_name, "scanned_path": str(target), "score": calculate_score(findings), "findings_count": len(findings), "severity_totals": severity_totals, "findings": findings}
    (output_dir / "security-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (output_dir / "security-report.html").write_text(build_html(report), encoding="utf-8")
    (output_dir / "security-report.sarif").write_text(json.dumps(create_sarif(findings, target_name), ensure_ascii=False, indent=2), encoding="utf-8")
    critical_or_high = [x for x in findings if x.get("severity") in ("CRITICAL", "HIGH")]
    sys.exit(2 if critical_or_high else 0)

if __name__ == "__main__":
    main()
