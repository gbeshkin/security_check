import json
import re
import shutil
import subprocess
import sys
import uuid
from datetime import datetime
from pathlib import Path

from flask import Flask, abort, redirect, render_template, request, send_file, url_for

app = Flask(__name__)
ROOT = Path(__file__).resolve().parent.parent
REPORTS_ROOT = ROOT / "reports"
TMP_ROOT = ROOT / "tmp"
REPORTS_ROOT.mkdir(exist_ok=True)
TMP_ROOT.mkdir(exist_ok=True)

GITHUB_REPO_PATTERN = re.compile(r"^https://github\.com/[^/]+/[^/]+/?$")

def is_valid_github_repo_url(url: str) -> bool:
    return bool(GITHUB_REPO_PATTERN.match(url.strip()))

def normalize_repo_url(url: str) -> str:
    clean = url.strip().rstrip("/")
    return clean[:-4] if clean.endswith(".git") else clean

def repo_display_name(url: str) -> str:
    return normalize_repo_url(url).split("/")[-1]

def list_reports():
    reports = []
    for report_dir in sorted(REPORTS_ROOT.iterdir(), reverse=True):
        if not report_dir.is_dir():
            continue
        meta = report_dir / "meta.json"
        report_json = report_dir / "security-report.json"
        if not meta.exists() or not report_json.exists():
            continue
        try:
            meta_data = json.loads(meta.read_text(encoding="utf-8"))
            report_data = json.loads(report_json.read_text(encoding="utf-8"))
            reports.append({
                "scan_id": report_dir.name,
                "created_at": meta_data.get("created_at"),
                "source_type": meta_data.get("source_type"),
                "source_value": meta_data.get("source_value"),
                "score": report_data.get("score"),
                "findings_count": report_data.get("findings_count"),
            })
        except Exception:
            continue
    return reports

def run_scanner(scan_target: Path, target_name: str, output_dir: Path):
    cmd = [sys.executable, str(ROOT / "scanner.py"), str(scan_target), target_name, str(output_dir)]
    return subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, check=False, timeout=1800)

def save_meta(output_dir: Path, source_type: str, source_value: str, process_result):
    meta = {
        "created_at": datetime.utcnow().isoformat() + "Z",
        "source_type": source_type,
        "source_value": source_value,
        "scanner_returncode": process_result.returncode,
        "scanner_stdout": process_result.stdout,
        "scanner_stderr": process_result.stderr,
    }
    (output_dir / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", reports=list_reports())

@app.route("/scan/github", methods=["POST"])
def scan_github():
    repo_url = request.form.get("repo_url", "").strip()
    if not repo_url:
        return "GitHub URL is required.", 400
    if not is_valid_github_repo_url(repo_url):
        return "Only full URLs like https://github.com/owner/repo are supported.", 400
    repo_url = normalize_repo_url(repo_url)
    scan_id = str(uuid.uuid4())
    temp_repo_dir = TMP_ROOT / scan_id
    output_dir = REPORTS_ROOT / scan_id
    output_dir.mkdir(parents=True, exist_ok=True)
    clone_result = subprocess.run(["git", "clone", "--depth", "1", f"{repo_url}.git", str(temp_repo_dir)],
                                  cwd=str(ROOT), capture_output=True, text=True, check=False, timeout=600)
    if clone_result.returncode != 0:
        save_meta(output_dir, "github", repo_url, clone_result)
        (output_dir / "error.txt").write_text(clone_result.stderr or clone_result.stdout or "Clone failed", encoding="utf-8")
        return render_template("scan_error.html", repo_url=repo_url, error=clone_result.stderr or clone_result.stdout), 400
    try:
        result = run_scanner(temp_repo_dir, repo_display_name(repo_url), output_dir)
        save_meta(output_dir, "github", repo_url, result)
    finally:
        shutil.rmtree(temp_repo_dir, ignore_errors=True)
    return redirect(url_for("report", scan_id=scan_id))

@app.route("/report/<scan_id>", methods=["GET"])
def report(scan_id):
    output_dir = REPORTS_ROOT / scan_id
    report_json = output_dir / "security-report.json"
    meta_json = output_dir / "meta.json"
    if not report_json.exists():
        abort(404)
    data = json.loads(report_json.read_text(encoding="utf-8"))
    meta = json.loads(meta_json.read_text(encoding="utf-8")) if meta_json.exists() else {}
    return render_template("report.html", data=data, meta=meta, scan_id=scan_id)

@app.route("/download/<scan_id>/<kind>", methods=["GET"])
def download(scan_id, kind):
    allowed = {"json": "security-report.json", "html": "security-report.html", "sarif": "security-report.sarif"}
    filename = allowed.get(kind)
    if not filename:
        abort(404)
    path = REPORTS_ROOT / scan_id / filename
    if not path.exists():
        abort(404)
    return send_file(path, as_attachment=True, download_name=filename)

@app.route("/health", methods=["GET"])
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import os
        CMD sh -c "gunicorn --bind 0.0.0.0:$PORT wsgi:app"