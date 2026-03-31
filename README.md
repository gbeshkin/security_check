# AI Security Scanner Live

English UI + live deployment-ready build.

## Features

- scan public GitHub repositories by URL
- report history
- downloadable JSON / HTML / SARIF
- deployment-ready with Dockerfile, Procfile, wsgi.py, and render.yaml

## Local run

```bash
pip install -r requirements.txt
pip install semgrep
python web/app.py
```

Open `http://localhost:5000`

## Live deployment

### Docker
```bash
docker build -t ai-sec-audit-live .
docker run -p 5000:5000 ai-sec-audit-live
```

### VPS
```bash
pip install -r requirements.txt
pip install semgrep
gunicorn --bind 0.0.0.0:5000 wsgi:app
```

### Notes
- Public GitHub repositories only
- Add rate limiting and cleanup policy before large-scale public use
