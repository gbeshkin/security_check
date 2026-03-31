# AI Security Scanner v4

This version moves clone and scan work into a background worker.

## What changed
- the web request creates a job and returns immediately
- a background worker reads queued jobs from `jobs/`
- users see a "Scanning..." page with polling
- the report opens automatically when ready

## Quick start
```bash
pip install -r requirements.txt
pip install semgrep
python job_worker.py
```

In another terminal:
```bash
python web/app.py
```

## Docker / Railway
The Dockerfile starts:
- the background worker
- gunicorn web app

## Current scope
- public GitHub repositories only
- file-based queue
- single-process worker
