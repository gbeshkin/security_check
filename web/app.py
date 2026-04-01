import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from flask import Flask, abort, jsonify, redirect, render_template, request, send_file, url_for

app = Flask(__name__)
ROOT = Path(__file__).resolve().parent.parent
REPORTS_ROOT = ROOT / "reports"
JOBS_ROOT = ROOT / "jobs"
REPORTS_ROOT.mkdir(exist_ok=True)
JOBS_ROOT.mkdir(exist_ok=True)
REPO_PATTERN = re.compile(r"^https://(github\.com|gitlab\.com)/[^/]+/[^/]+/?$")

def utc_now(): return datetime.now(timezone.utc).isoformat()
def load_json(path: Path): return json.loads(path.read_text(encoding="utf-8"))
def save_json(path: Path, data): path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
def is_valid_repo_url(url: str) -> bool: return bool(REPO_PATTERN.match(url.strip()))
def normalize_repo_url(url: str) -> str:
    clean = url.strip().rstrip("/")
    return clean[:-4] if clean.endswith(".git") else clean
def repo_display_name(url: str) -> str: return normalize_repo_url(url).split("/")[-1]
def detect_provider(url: str) -> str: return "gitlab" if "gitlab.com/" in url else "github"

def list_reports():
    reports = []
    for report_dir in sorted(REPORTS_ROOT.iterdir(), reverse=True):
        if not report_dir.is_dir(): continue
        meta = report_dir / "meta.json"
        report_json = report_dir / "security-report.json"
        if not meta.exists() or not report_json.exists(): continue
        try:
            meta_data = load_json(meta); report_data = load_json(report_json)
            reports.append({"scan_id": report_dir.name, "created_at": meta_data.get("created_at"), "source_type": meta_data.get("source_type"), "source_value": meta_data.get("source_value"), "score": report_data.get("score"), "findings_count": report_data.get("findings_count")})
        except Exception:
            continue
    return reports

def list_jobs():
    jobs = []
    for job_path in sorted(JOBS_ROOT.glob("*.json"), reverse=True):
        try: jobs.append(load_json(job_path))
        except Exception: continue
    return jobs[:20]

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", reports=list_reports(), jobs=list_jobs())

@app.route("/scan/repo", methods=["POST"])
def scan_repo():
    repo_url = request.form.get("repo_url", "").strip()
    if not repo_url: return "Repository URL is required.", 400
    if not is_valid_repo_url(repo_url): return "Only full GitHub or GitLab URLs are supported.", 400
    repo_url = normalize_repo_url(repo_url)
    scan_id = str(uuid.uuid4())
    job = {"scan_id": scan_id, "job_id": scan_id, "repo_url": repo_url, "target_name": repo_display_name(repo_url), "provider": detect_provider(repo_url), "status": "queued", "created_at": utc_now(), "updated_at": utc_now()}
    save_json(JOBS_ROOT / f"{scan_id}.json", job)
    return redirect(url_for("job_status_page", scan_id=scan_id))

@app.route("/jobs/<scan_id>", methods=["GET"])
def job_status_page(scan_id):
    if not (JOBS_ROOT / f"{scan_id}.json").exists(): abort(404)
    return render_template("job_status.html", scan_id=scan_id)

@app.route("/api/jobs/<scan_id>", methods=["GET"])
def job_status_api(scan_id):
    job_path = JOBS_ROOT / f"{scan_id}.json"
    if not job_path.exists(): return jsonify({"error": "not found"}), 404
    job = load_json(job_path)
    report_exists = (REPORTS_ROOT / scan_id / "security-report.json").exists()
    return jsonify({"scan_id": scan_id, "status": job.get("status"), "repo_url": job.get("repo_url"), "provider": job.get("provider"), "report_ready": report_exists, "error": job.get("error")})

@app.route("/report/<scan_id>", methods=["GET"])
def report(scan_id):
    output_dir = REPORTS_ROOT / scan_id
    report_json = output_dir / "security-report.json"
    meta_json = output_dir / "meta.json"
    if not report_json.exists(): abort(404)
    data = load_json(report_json)
    meta = load_json(meta_json) if meta_json.exists() else {}
    return render_template("report.html", data=data, meta=meta, scan_id=scan_id)

@app.route("/download/<scan_id>/<kind>", methods=["GET"])
def download(scan_id, kind):
    allowed = {"json": "security-report.json", "html": "security-report.html", "sarif": "security-report.sarif"}
    filename = allowed.get(kind)
    if not filename: abort(404)
    path = REPORTS_ROOT / scan_id / filename
    if not path.exists(): abort(404)
    return send_file(path, as_attachment=True, download_name=filename)

@app.route("/health", methods=["GET"])
def health():
    return {"status": "ok", "version": "v6"}

if __name__ == "__main__":
    import os
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
