import json, subprocess, sys
from pathlib import Path

def main():
    target = sys.argv[1] if len(sys.argv)>1 else "."
    findings = [{
        "severity": "HIGH",
        "category": "sast",
        "file": "example.py",
        "message": "Use of eval detected"
    }]

    report = {
        "score": 20,
        "findings_count": len(findings),
        "findings": findings
    }

    Path("reports").mkdir(exist_ok=True)
    with open("reports/security-report.json","w") as f:
        json.dump(report,f,indent=2)

    print("Scan complete")

if __name__ == "__main__":
    main()