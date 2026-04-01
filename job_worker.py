import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
JOBS_ROOT = ROOT / "jobs"
REPORTS_ROOT = ROOT / "reports"
TMP_ROOT = ROOT / "tmp"
JOBS_ROOT.mkdir(exist_ok=True)
REPORTS_ROOT.mkdir(exist_ok=True)
TMP_ROOT.mkdir(exist_ok=True)
MAX_REPO_FILES = 8000

def utc_now(): return datetime.now(timezone.utc).isoformat()
def load_json(path): return json.loads(path.read_text(encoding="utf-8"))
def save_json(path, data): path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

def update_status(job_path: Path, status: str, **extra):
    data = load_json(job_path)
    data["status"] = status
    data["updated_at"] = utc_now()
    data.update(extra)
    save_json(job_path, data)

def detect_provider(repo_url: str) -> str:
    return "gitlab" if "gitlab.com/" in repo_url else "github"

def count_repo_files(repo_path: Path) -> int:
    count = 0
    for p in repo_path.rglob("*"):
        if p.is_file():
            count += 1
            if count > MAX_REPO_FILES: break
    return count

def process_job(job_path: Path):
    job = load_json(job_path)
    scan_id = job["scan_id"]
    repo_url = job["repo_url"]
    target_name = job["target_name"]
    provider = job.get("provider", detect_provider(repo_url))
    output_dir = REPORTS_ROOT / scan_id
    output_dir.mkdir(parents=True, exist_ok=True)
    temp_repo_dir = TMP_ROOT / scan_id
    update_status(job_path, "running", started_at=utc_now())
    try:
        clone = subprocess.run(["git","clone","--depth","1","--filter=blob:none",f"{repo_url}.git",str(temp_repo_dir)], cwd=str(ROOT), capture_output=True, text=True, check=False, timeout=300)
        if clone.returncode != 0:
            (output_dir / "error.txt").write_text(clone.stderr or clone.stdout or "Clone failed", encoding="utf-8")
            save_json(output_dir / "meta.json", {"created_at": utc_now(), "source_type": provider, "source_value": repo_url, "scanner_returncode": 1, "scanner_stdout": clone.stdout, "scanner_stderr": clone.stderr})
            update_status(job_path, "failed", error="Clone failed", finished_at=utc_now())
            return
        file_count = count_repo_files(temp_repo_dir)
        if file_count > MAX_REPO_FILES:
            msg = f"Repository too large for live scan: {file_count} files (limit {MAX_REPO_FILES})"
            (output_dir / "error.txt").write_text(msg, encoding="utf-8")
            save_json(output_dir / "meta.json", {"created_at": utc_now(), "source_type": provider, "source_value": repo_url, "scanner_returncode": 1, "scanner_stdout": "", "scanner_stderr": msg})
            update_status(job_path, "failed", error=msg, finished_at=utc_now())
            return
        result = subprocess.run([sys.executable, str(ROOT / "scanner.py"), str(temp_repo_dir), target_name, str(output_dir)], cwd=str(ROOT), capture_output=True, text=True, check=False, timeout=900)
        save_json(output_dir / "meta.json", {"created_at": utc_now(), "source_type": provider, "source_value": repo_url, "scanner_returncode": result.returncode, "scanner_stdout": result.stdout, "scanner_stderr": result.stderr, "repo_file_count": file_count})
        status = "completed" if result.returncode in (0, 2) else "failed"
        update_status(job_path, status, finished_at=utc_now())
    except subprocess.TimeoutExpired:
        (output_dir / "error.txt").write_text("Job timed out", encoding="utf-8")
        update_status(job_path, "failed", error="Job timed out", finished_at=utc_now())
    except Exception as exc:
        (output_dir / "error.txt").write_text(str(exc), encoding="utf-8")
        update_status(job_path, "failed", error=str(exc), finished_at=utc_now())
    finally:
        shutil.rmtree(temp_repo_dir, ignore_errors=True)

def main():
    while True:
        pending = sorted(JOBS_ROOT.glob("*.json"))
        processed_any = False
        for job_path in pending:
            try: job = load_json(job_path)
            except Exception: continue
            if job.get("status") == "queued":
                process_job(job_path)
                processed_any = True
                break
        time.sleep(2 if processed_any else 3)

if __name__ == "__main__":
    main()
