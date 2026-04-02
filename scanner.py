#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

VERSION = "2.0.0"

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None

SOURCE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php", ".sh"
}

TEXT_EXTENSIONS = SOURCE_EXTENSIONS | {
    ".tf", ".tfvars", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".properties", ".md", ".txt", ".xml", ".sql", ".dockerfile"
}

EXCLUDED_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", ".venv", "venv", "env",
    "dist", "build", ".next", ".nuxt", "coverage", "htmlcov", ".pytest_cache",
    "__pycache__", ".idea", ".mypy_cache", ".terraform", ".scanner_cache", "target",
    ".tox", ".gradle", ".cache", ".yarn", ".pnpm-store"
}

DEFAULT_IGNORE_PATTERNS = [
    re.compile(r"package-lock\.json$"),
    re.compile(r"yarn\.lock$"),
    re.compile(r"pnpm-lock\.yaml$"),
    re.compile(r"poetry\.lock$"),
    re.compile(r"Cargo\.lock$"),
    re.compile(r"\.min\.(js|css)$"),
]

TEST_DIR_NAMES = {"tests", "test", "__tests__", "spec", "specs"}
CRITICAL_KEYWORDS = {
    "auth", "login", "password", "token", "jwt", "permission", "role", "admin",
    "payment", "billing", "checkout", "webhook", "upload", "config", "secret",
    "api", "controller", "middleware", "session", "oauth", "crypto", "sign",
    "verify", "callback"
}

ENV_SENSITIVE_KEYS = {
    "password", "passwd", "secret", "token", "api_key", "apikey", "private_key", "access_key",
    "client_secret", "auth_token", "db_url", "database_url", "aws_secret_access_key"
}

SECRET_PATTERNS = [
    ("AWS Access Key", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub Token", "high", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("Slack Token", "high", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Stripe Live Secret", "high", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")),
    ("Private Key Block", "critical", re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----")),
    ("Generic API Key Assignment", "high", re.compile(r"(?i)\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*[\"'][^\"'\n]{8,}[\"']")),
    ("JWT-like Token", "high", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b")),
]

AI_RISK_PATTERNS = [
    ("Dangerous eval/exec", "high", re.compile(r"\b(eval|exec)\s*\(")),
    ("Shell execution with shell=True", "high", re.compile(r"subprocess\.(run|Popen|call|check_output|check_call)\([^\n]*shell\s*=\s*True")),
    ("Potential command injection", "high", re.compile(r"(?i)(os\.system\(|child_process\.exec\(|Runtime\.getRuntime\(\)\.exec\()")),
    ("YAML unsafe load", "high", re.compile(r"yaml\.load\s*\(")),
    ("TLS verification disabled", "high", re.compile(r"(?i)(verify\s*=\s*False|rejectUnauthorized\s*:\s*false)")),
    ("MD5 usage", "medium", re.compile(r"\bmd5\s*\(")),
    ("SHA1 usage", "medium", re.compile(r"\bsha1\s*\(")),
    ("Random for security use", "medium", re.compile(r"\brandom\.(random|randint|choice|choices)\s*\(")),
    ("TODO/FIXME in code", "low", re.compile(r"(?i)\b(TODO|FIXME|HACK|XXX)\b")),
    ("Debug mode enabled", "medium", re.compile(r"(?i)(debug\s*=\s*True|app\.run\([^\n]*debug\s*=\s*True)")),
]

NEGATIVE_TEST_MARKERS = [
    "raises", "throw", "throws", "exception", "rejects", "unauthorized", "forbidden",
    "invalid", "bad request", "400", "401", "403", "404", "timeout", "error", "fail", "denied"
]
POSITIVE_TEST_MARKERS = [
    "mock", "patch", "stub", "parametrize", "fixture", "beforeeach", "aftereach",
    "setup", "teardown", "integration", "e2e", "table driven"
]
WEAK_TEST_MARKERS = ["it.skip", "describe.skip", "xit(", "xdescribe(", "todo", "fixme"]


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    description: str
    path: str | None = None
    line: int | None = None
    rule_id: str | None = None
    evidence: str | None = None
    confidence: str = "medium"


@dataclass
class FileIndex:
    all_files: list[Path]
    text_files: list[Path]
    source_files: list[Path]
    test_files: list[Path]
    yaml_files: list[Path]
    tf_files: list[Path]
    env_files: list[Path]
    docker_compose_files: list[Path]
    ci_files: list[Path]


def is_test_file(path: Path) -> bool:
    parts = {part.lower() for part in path.parts}
    if parts & TEST_DIR_NAMES:
        return True
    name = path.name.lower()
    return any(token in name for token in [
        ".test.", ".spec.", "_test.", "test_", "tests.py", "spectest", "spec.js", "spec.ts"
    ])


class Scanner:
    def __init__(self, repo_path: str, config: dict[str, Any]) -> None:
        self.repo_path = Path(repo_path).resolve()
        self.config = config
        self.findings: list[Finding] = []
        self._head_cache: dict[str, str] = {}
        self._full_cache: dict[str, str] = {}
        self.index: FileIndex | None = None

    # ---------- public ----------
    def run(self) -> dict[str, Any]:
        if not self.repo_path.exists() or not self.repo_path.is_dir():
            raise FileNotFoundError(f"Repository path does not exist or is not a directory: {self.repo_path}")

        self.index = self.build_index()
        metadata: dict[str, Any] = {
            "repo_path": str(self.repo_path),
            "generated_at": int(time.time()),
            "scanner_version": VERSION,
            "files_indexed": len(self.index.all_files),
            "text_files_indexed": len(self.index.text_files),
        }
        summary: dict[str, Any] = {}

        self.scan_secrets()
        self.scan_ai_risks()
        self.scan_terraform()
        self.scan_kubernetes()
        self.scan_env_files()
        self.scan_docker_compose()
        self.scan_ci_configs()
        self.scan_gitignore_and_hygiene()

        if self.config.get("check_tests", True):
            tests = self.analyze_tests()
            metadata["tests"] = tests["metadata"]
            summary["tests"] = tests["summary"]

        summary["severity_counts"] = self.severity_counts()
        summary["category_counts"] = self.category_counts()
        summary["raw_risk_score"] = self.calculate_raw_risk_score()
        summary["display_score"] = self.calculate_display_score(summary["raw_risk_score"])
        summary["total_findings"] = len(self.findings)

        return {
            "summary": summary,
            "metadata": metadata,
            "findings": [asdict(f) for f in self.findings],
        }

    # ---------- indexing ----------
    def build_index(self) -> FileIndex:
        all_files: list[Path] = []
        text_files: list[Path] = []
        source_files: list[Path] = []
        test_files: list[Path] = []
        yaml_files: list[Path] = []
        tf_files: list[Path] = []
        env_files: list[Path] = []
        docker_compose_files: list[Path] = []
        ci_files: list[Path] = []

        for path in self.repo_path.rglob("*"):
            if not path.is_file():
                continue
            if self.is_excluded(path):
                continue
            rel = self.rel(path)
            if any(regex.search(rel) for regex in DEFAULT_IGNORE_PATTERNS):
                continue

            all_files.append(path)
            if self.is_text_file(path):
                text_files.append(path)
            if path.suffix.lower() in SOURCE_EXTENSIONS or path.name.lower() == "dockerfile":
                if is_test_file(path):
                    test_files.append(path)
                else:
                    source_files.append(path)
            if path.suffix.lower() in {".yml", ".yaml"}:
                yaml_files.append(path)
            if path.suffix.lower() in {".tf", ".tfvars"}:
                tf_files.append(path)
            if path.name.startswith(".env") or path.suffix.lower() == ".env":
                env_files.append(path)
            if path.name.lower() in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
                docker_compose_files.append(path)
            if rel == ".gitlab-ci.yml" or rel.startswith(".github/workflows/"):
                ci_files.append(path)

        return FileIndex(
            all_files=all_files,
            text_files=text_files,
            source_files=source_files,
            test_files=test_files,
            yaml_files=yaml_files,
            tf_files=tf_files,
            env_files=env_files,
            docker_compose_files=docker_compose_files,
            ci_files=ci_files,
        )

    # ---------- helpers ----------
    def add_finding(
        self,
        severity: str,
        category: str,
        title: str,
        description: str,
        path: str | None = None,
        line: int | None = None,
        rule_id: str | None = None,
        evidence: str | None = None,
        confidence: str = "medium",
    ) -> None:
        self.findings.append(Finding(severity, category, title, description, path, line, rule_id, evidence, confidence))

    def severity_counts(self) -> dict[str, int]:
        counts = Counter(f.severity for f in self.findings)
        return {k: counts.get(k, 0) for k in ["critical", "high", "medium", "low", "info"]}

    def category_counts(self) -> dict[str, int]:
        counts = Counter(f.category for f in self.findings)
        return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))

    def calculate_raw_risk_score(self) -> int:
        weights = {"critical": 100, "high": 30, "medium": 10, "low": 3, "info": 0}
        return sum(weights.get(f.severity, 0) for f in self.findings)

    def calculate_display_score(self, raw_score: int) -> int:
        # Log scaling keeps big repos comparable and avoids every large repo dropping to zero.
        score = 100 - round(math.log1p(max(raw_score, 0)) * 11)
        return max(0, min(100, score))

    def is_excluded(self, path: Path) -> bool:
        return any(part in EXCLUDED_DIRS for part in path.parts)

    def is_text_file(self, path: Path) -> bool:
        suffix = path.suffix.lower()
        if suffix in TEXT_EXTENSIONS:
            return True
        if path.name.lower() == "dockerfile" or path.name.startswith(".env"):
            return True
        return False

    def rel(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.repo_path))
        except Exception:
            return str(path)

    def read_head(self, path: Path, max_bytes: int | None = None) -> str:
        max_bytes = max_bytes or int(self.config.get("max_read_bytes", 12000))
        key = f"head:{path}:{max_bytes}"
        if key in self._head_cache:
            return self._head_cache[key]
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                data = handle.read(max_bytes)
        except Exception:
            data = ""
        self._head_cache[key] = data
        return data

    def read_text(self, path: Path, max_bytes: int | None = None) -> str:
        if max_bytes is not None:
            return self.read_head(path, max_bytes=max_bytes)
        key = str(path)
        if key in self._full_cache:
            return self._full_cache[key]
        try:
            self._full_cache[key] = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            self._full_cache[key] = ""
        return self._full_cache[key]

    def read_lines(self, path: Path, max_bytes: int | None = None) -> list[str]:
        return self.read_text(path, max_bytes=max_bytes).splitlines()

    def guess_line(self, path: Path, pattern: re.Pattern[str], max_bytes: int | None = None) -> tuple[int | None, str | None]:
        for i, line in enumerate(self.read_lines(path, max_bytes=max_bytes), start=1):
            if pattern.search(line):
                return i, line.strip()[:300]
        return None, None

    def sha256(self, value: str) -> str:
        return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:12]

    # ---------- scanners ----------
    def scan_secrets(self) -> None:
        assert self.index is not None
        for path in self.index.text_files:
            content = self.read_head(path, max_bytes=30000)
            if not content:
                continue
            rel = self.rel(path)
            for title, severity, pattern in SECRET_PATTERNS:
                match = pattern.search(content)
                if match:
                    line, evidence = self.guess_line(path, pattern, max_bytes=30000)
                    self.add_finding(
                        severity=severity,
                        category="secrets",
                        title=title,
                        description=f"Potential secret detected in {rel}.",
                        path=rel,
                        line=line,
                        rule_id="secret_detected",
                        evidence=evidence,
                        confidence="high",
                    )

    def scan_ai_risks(self) -> None:
        assert self.index is not None
        for path in self.index.source_files:
            content = self.read_head(path, max_bytes=25000)
            if not content:
                continue
            rel = self.rel(path)
            for title, severity, pattern in AI_RISK_PATTERNS:
                if pattern.search(content):
                    line, evidence = self.guess_line(path, pattern, max_bytes=25000)
                    self.add_finding(
                        severity=severity,
                        category="ai_risk",
                        title=title,
                        description=f"Potential risky implementation pattern detected in {rel}.",
                        path=rel,
                        line=line,
                        rule_id="ai_risk_pattern",
                        evidence=evidence,
                        confidence="medium",
                    )
            if path.suffix.lower() == ".py":
                self.scan_python_specific(path)

    def scan_python_specific(self, path: Path) -> None:
        content = self.read_head(path, max_bytes=50000)
        if not content:
            return
        try:
            tree = ast.parse(content)
        except Exception:
            return
        rel = self.rel(path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func_name = self._ast_call_name(node.func)
            if func_name in {
                "requests.get", "requests.post", "requests.put", "requests.delete", "requests.patch", "requests.request"
            }:
                has_timeout = any(kw.arg == "timeout" for kw in node.keywords if kw.arg)
                if not has_timeout:
                    self.add_finding(
                        severity="medium",
                        category="code_quality",
                        title="HTTP request without timeout",
                        description=f"requests call without timeout detected in {rel}.",
                        path=rel,
                        line=getattr(node, "lineno", None),
                        rule_id="requests_no_timeout",
                        confidence="high",
                    )

    def _ast_call_name(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parts: list[str] = []
            current: ast.AST | None = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
                return ".".join(reversed(parts))
        return None

    def scan_terraform(self) -> None:
        assert self.index is not None
        if not self.index.tf_files:
            return
        checks = [
            ("Public S3 ACL", "high", re.compile(r'(?is)resource\s+"aws_s3_bucket[^\n]*.*?acl\s*=\s*"public-read"')),
            ("0.0.0.0/0 ingress", "high", re.compile(r'(?is)cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0/0"')),
            ("Security group allows all traffic", "high", re.compile(r'(?is)from_port\s*=\s*0.*?to_port\s*=\s*0.*?protocol\s*=\s*"-1"')),
            ("DB storage not encrypted", "high", re.compile(r'(?is)resource\s+"aws_db_instance".*?(storage_encrypted\s*=\s*false|kms_key_id\s*=\s*null)')),
            ("Terraform hardcoded secret", "critical", re.compile(r'(?i)(password|secret|token)\s*=\s*"[^"]{8,}"')),
        ]
        for path in self.index.tf_files:
            content = self.read_head(path, max_bytes=40000)
            if not content:
                continue
            rel = self.rel(path)
            for title, severity, pattern in checks:
                if pattern.search(content):
                    line, evidence = self.guess_line(path, pattern, max_bytes=40000)
                    self.add_finding(severity, "terraform", title, f"Potential Terraform issue detected in {rel}.", rel, line, "terraform_risk", evidence, "medium")
        filenames = {p.name for p in self.index.tf_files}
        if "versions.tf" not in filenames and "terraform.tf" not in filenames:
            self.add_finding(
                "low", "terraform", "Terraform version pinning not obvious",
                "Terraform files found, but versions.tf or terraform.tf was not found. Consider pinning required_version and providers.",
                rule_id="terraform_version_pinning", confidence="medium"
            )

    def scan_kubernetes(self) -> None:
        assert self.index is not None
        for path in self.index.yaml_files:
            content = self.read_head(path, max_bytes=50000)
            if not content or "apiVersion:" not in content or "kind:" not in content:
                continue
            if not any(kind in content for kind in ["Deployment", "StatefulSet", "DaemonSet", "Pod", "CronJob", "Job"]):
                continue
            rel = self.rel(path)
            checks = [
                ("Container running as root", "high", re.compile(r"(?is)runAsNonRoot\s*:\s*false")),
                ("Privileged container", "high", re.compile(r"(?is)privileged\s*:\s*true")),
                ("Latest tag used", "medium", re.compile(r"(?im)^\s*image\s*:\s*.+:latest\s*$")),
                ("Secret value in manifest", "critical", re.compile(r"(?i)(password|secret|token|api[_-]?key)\s*:\s*[\"']?[A-Za-z0-9_./+=-]{8,}")),
            ]
            for title, severity, pattern in checks:
                if pattern.search(content):
                    line, evidence = self.guess_line(path, pattern, max_bytes=50000)
                    self.add_finding(severity, "kubernetes", title, f"Potential Kubernetes manifest issue detected in {rel}.", rel, line, "k8s_risk", evidence, "medium")
            if "resources:" not in content:
                self.add_finding("low", "kubernetes", "No resource requests/limits detected", f"Kubernetes workload manifest in {rel} does not appear to define resources.", rel, rule_id="k8s_no_resources", confidence="high")
            if "readinessProbe:" not in content and "livenessProbe:" not in content:
                self.add_finding("low", "kubernetes", "No health probes detected", f"Kubernetes workload manifest in {rel} does not appear to define readiness/liveness probes.", rel, rule_id="k8s_no_probes", confidence="high")

    def scan_env_files(self) -> None:
        assert self.index is not None
        for path in self.index.env_files:
            rel = self.rel(path)
            for i, line in enumerate(self.read_lines(path, max_bytes=20000), start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or "=" not in stripped:
                    continue
                key, _, value = stripped.partition("=")
                key_lower = key.strip().lower()
                clean_value = value.strip().strip('"').strip("'")
                if key_lower in ENV_SENSITIVE_KEYS and clean_value and not any(x in clean_value.lower() for x in ["changeme", "example", "localhost", "<", "{"]):
                    self.add_finding("high", "env", "Sensitive value in .env file", f"Sensitive-looking environment variable found in {rel}: {key.strip()}.", rel, i, "env_sensitive_value", f"{key.strip()}=<redacted:{self.sha256(clean_value)}>", "high")
                if key.strip().upper() == "DEBUG" and clean_value.lower() in {"1", "true", "yes", "on"}:
                    self.add_finding("medium", "env", "DEBUG enabled in env file", f"DEBUG appears enabled in {rel}.", rel, i, "env_debug_enabled", stripped, "high")

    def scan_docker_compose(self) -> None:
        assert self.index is not None
        for path in self.index.docker_compose_files:
            rel = self.rel(path)
            content = self.read_head(path, max_bytes=60000)
            if not content:
                continue
            if re.search(r"(?im)^\s*ports\s*:\s*$", content) and re.search(r"(?m)^\s*-\s*[\"']?\d+:\d+[\"']?\s*$", content):
                self.add_finding("medium", "docker", "Published container ports detected", f"Docker Compose file {rel} publishes container ports. Verify exposure is intentional.", rel, rule_id="docker_published_ports", confidence="medium")
            if re.search(r"(?im)^\s*privileged\s*:\s*true\s*$", content):
                line, evidence = self.guess_line(path, re.compile(r"(?im)^\s*privileged\s*:\s*true\s*$"), max_bytes=60000)
                self.add_finding("high", "docker", "Privileged container in Compose", f"Docker Compose file {rel} enables privileged mode.", rel, line, "docker_privileged", evidence, "high")
            if re.search(r"(?im)^\s*image\s*:\s*.+:latest\s*$", content):
                self.add_finding("low", "docker", "Latest tag used in Compose", f"Docker Compose file {rel} uses the latest image tag.", rel, rule_id="docker_latest_tag", confidence="high")

    def scan_ci_configs(self) -> None:
        assert self.index is not None
        if not self.index.ci_files:
            self.add_finding("low", "ci", "No CI configuration detected", "No GitHub Actions or GitLab CI configuration was detected.", rule_id="ci_missing", confidence="medium")
            return
        for path in self.index.ci_files:
            rel = self.rel(path)
            content = self.read_head(path, max_bytes=50000).lower()
            if "test" not in content and "pytest" not in content and "jest" not in content and "go test" not in content:
                self.add_finding("low", "ci", "CI file without obvious test step", f"CI configuration {rel} does not appear to include an obvious test step.", rel, rule_id="ci_no_tests", confidence="low")

    def scan_gitignore_and_hygiene(self) -> None:
        gitignore = self.repo_path / ".gitignore"
        if not gitignore.exists():
            self.add_finding("medium", "hygiene", "Missing .gitignore", "Repository does not appear to contain a .gitignore file.", rule_id="gitignore_missing", confidence="high")
            return
        content = self.read_text(gitignore, max_bytes=10000)
        missing: list[str] = []
        for item in [".env", ".venv", "node_modules", "coverage", "dist"]:
            if item not in content:
                missing.append(item)
        if missing:
            self.add_finding("low", "hygiene", "Common local or sensitive files not ignored", f".gitignore may be missing common entries: {', '.join(missing)}.", ".gitignore", rule_id="gitignore_common_entries", confidence="medium")

    # ---------- tests ----------
    def analyze_tests(self) -> dict[str, Any]:
        assert self.index is not None
        source_files = self.index.source_files
        test_files = self.index.test_files

        metadata: dict[str, Any] = {
            "source_files": len(source_files),
            "test_files": len(test_files),
            "frameworks": sorted(self.detect_test_frameworks()),
            "test_commands": self.detect_test_commands(),
            "critical_paths_without_tests": [],
            "negative_test_signals": [],
            "positive_test_signals": [],
            "weak_test_markers": [],
            "coverage_report_found": False,
            "coverage_percent": None,
        }

        ratio = len(test_files) / max(len(source_files), 1)
        if source_files and not test_files:
            self.add_finding("high", "tests", "No tests detected", "Repository contains source code but no test files were detected.", rule_id="tests_missing", confidence="high")
        elif ratio < 0.15:
            self.add_finding("medium", "tests", "Low test-to-source ratio", f"Detected {len(test_files)} test files for {len(source_files)} source files.", rule_id="tests_low_ratio", confidence="medium")

        if not metadata["frameworks"]:
            self.add_finding("medium", "tests", "No test framework detected", "No known testing framework was found in dependencies or project files.", rule_id="tests_no_framework", confidence="medium")
        if not metadata["test_commands"]:
            self.add_finding("low", "tests", "No test command detected", "No obvious test command was found in package.json, Makefile, CI, or build config.", rule_id="tests_no_command", confidence="medium")

        critical = self.analyze_critical_code_test_presence(source_files, test_files)
        metadata["critical_paths_without_tests"] = critical

        quality = self.analyze_test_quality_signals(test_files)
        metadata["negative_test_signals"] = quality["negative"]
        metadata["positive_test_signals"] = quality["positive"]
        metadata["weak_test_markers"] = quality["weak"]

        existing_cov = self.detect_existing_coverage_report()
        if existing_cov:
            metadata["coverage_report_found"] = True
            metadata["coverage_percent"] = existing_cov.get("percent")
            metadata["coverage_source"] = existing_cov.get("source")

        if self.config.get("run_coverage"):
            runtime_cov = self.try_run_coverage()
            if runtime_cov.get("coverage_percent") is not None:
                metadata["coverage_report_found"] = True
                metadata["coverage_percent"] = runtime_cov["coverage_percent"]
                metadata["coverage_source"] = runtime_cov.get("source")

        metadata["test_confidence_score"] = self.calculate_test_confidence(metadata)
        summary = {
            "source_files": metadata["source_files"],
            "test_files": metadata["test_files"],
            "test_to_source_ratio": round(ratio, 2),
            "frameworks": metadata["frameworks"],
            "coverage_percent": metadata["coverage_percent"],
            "test_confidence_score": metadata["test_confidence_score"],
        }
        return {"summary": summary, "metadata": metadata}

    def detect_test_frameworks(self) -> set[str]:
        frameworks: set[str] = set()
        candidates = [
            "package.json", "requirements.txt", "pyproject.toml", "setup.py", "setup.cfg",
            "pom.xml", "build.gradle", "build.gradle.kts", "go.mod", "Gemfile"
        ]
        for name in candidates:
            path = self.repo_path / name
            if not path.exists():
                continue
            content = self.read_text(path, max_bytes=60000).lower()
            for fw in [
                "jest", "vitest", "mocha", "playwright", "cypress", "ava", "pytest",
                "unittest", "nose", "tox", "junit", "testng", "mockito", "jacoco",
                "rspec", "minitest", "cucumber"
            ]:
                if fw in content:
                    frameworks.add(fw)
            if name == "go.mod":
                frameworks.add("go test")
        return frameworks

    def detect_test_commands(self) -> list[str]:
        commands: list[str] = []

        package_json = self.repo_path / "package.json"
        if package_json.exists():
            try:
                data = json.loads(self.read_text(package_json, max_bytes=200000))
                scripts = data.get("scripts", {})
                for key, value in scripts.items():
                    if "test" in key.lower() or "coverage" in key.lower():
                        commands.append(f"package.json:{key} -> {value}")
            except Exception:
                pass

        makefile = self.repo_path / "Makefile"
        if makefile.exists():
            for line in self.read_lines(makefile, max_bytes=40000):
                stripped = line.strip()
                if stripped.startswith("test") or any(marker in stripped for marker in ["pytest", "jest", "go test", "gradle test", "mvn test"]):
                    commands.append(f"Makefile -> {stripped}")

        assert self.index is not None
        for path in self.index.ci_files:
            rel = self.rel(path)
            content = self.read_text(path, max_bytes=50000).lower()
            for marker in ["pytest", "jest", "vitest", "go test", "mvn test", "gradle test", "coverage", "playwright"]:
                if marker in content:
                    commands.append(f"{rel} -> contains {marker}")
        return commands[:50]

    def analyze_critical_code_test_presence(self, source_files: list[Path], test_files: list[Path]) -> list[str]:
        test_names = " ".join(p.name.lower() for p in test_files)
        missing: list[str] = []
        max_source = int(self.config.get("max_source_files", 800))
        for src in source_files[:max_source]:
            rel = self.rel(src)
            rel_lower = rel.lower()
            if not any(keyword in rel_lower for keyword in CRITICAL_KEYWORDS):
                continue
            stem = src.stem.lower().replace(".service", "").replace(".controller", "").replace(".api", "")
            if stem and stem not in test_names:
                missing.append(rel)
        if missing:
            sample = missing[:20]
            for item in sample:
                self.add_finding("medium", "tests", "Critical module may lack direct tests", f"No obvious matching test file detected for critical module: {item}", item, rule_id="tests_critical_missing", confidence="low")
            if len(missing) > len(sample):
                self.add_finding("medium", "tests", "Multiple critical modules may lack tests", f"{len(missing)} critical files have no obvious matching test.", rule_id="tests_critical_missing_many", confidence="low")
        return missing

    def analyze_test_quality_signals(self, test_files: list[Path]) -> dict[str, list[str]]:
        max_test_files = int(self.config.get("max_test_files", 250))
        max_bytes = int(self.config.get("test_read_bytes", 8000))
        candidates = [p for p in test_files[:max_test_files] if p.exists() and p.stat().st_size <= int(self.config.get("max_test_file_size", 300_000))]

        def worker(path: Path) -> dict[str, list[str]]:
            content = self.read_head(path, max_bytes=max_bytes).lower()
            rel = self.rel(path)
            out = {"negative": [], "positive": [], "weak": []}
            for marker in NEGATIVE_TEST_MARKERS:
                if marker in content:
                    out["negative"].append(f"{rel}: {marker}")
            for marker in POSITIVE_TEST_MARKERS:
                if marker in content:
                    out["positive"].append(f"{rel}: {marker}")
            for marker in WEAK_TEST_MARKERS:
                if marker in content:
                    out["weak"].append(f"{rel}: {marker}")
            return out

        max_workers = int(self.config.get("max_workers", min(16, (os.cpu_count() or 4) * 2)))
        merged = {"negative": [], "positive": [], "weak": []}
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for partial in executor.map(worker, candidates):
                for key in merged:
                    merged[key].extend(partial[key])
                    if len(merged[key]) > 100:
                        merged[key] = merged[key][:100]

        if test_files and not merged["negative"]:
            self.add_finding("medium", "tests", "No obvious negative test scenarios detected", "Tests were found, but no obvious signals of invalid input, auth failures, exceptions, or error handling were detected.", rule_id="tests_no_negative_signals", confidence="medium")
        if test_files and not merged["positive"]:
            self.add_finding("low", "tests", "Limited advanced testing signals detected", "No obvious mocks, parametrization, fixtures, or integration patterns were found.", rule_id="tests_limited_signals", confidence="medium")
        if merged["weak"]:
            self.add_finding("low", "tests", "Skipped or unfinished tests detected", f"Detected {len(merged['weak'])} skipped/TODO/FIXME test markers.", rule_id="tests_skipped_or_todo", confidence="high")
        return merged

    def detect_existing_coverage_report(self) -> dict[str, Any] | None:
        candidates = [
            self.repo_path / "coverage.xml",
            self.repo_path / "coverage-summary.json",
            self.repo_path / "lcov.info",
            self.repo_path / "jacoco.xml",
            self.repo_path / "coverage" / "coverage-summary.json",
        ]
        for path in candidates:
            if not path.exists():
                continue
            try:
                if path.name == "coverage-summary.json":
                    data = json.loads(self.read_text(path, max_bytes=500000))
                    pct = data.get("total", {}).get("lines", {}).get("pct")
                    if pct is not None:
                        return {"source": self.rel(path), "percent": float(pct)}
                elif path.name == "coverage.xml":
                    match = re.search(r'line-rate="([\d.]+)"', self.read_text(path, max_bytes=500000))
                    if match:
                        return {"source": self.rel(path), "percent": round(float(match.group(1)) * 100, 2)}
                elif path.name == "jacoco.xml":
                    match = re.search(r'<counter type="LINE" missed="(\d+)" covered="(\d+)"', self.read_text(path, max_bytes=500000))
                    if match:
                        missed, covered = int(match.group(1)), int(match.group(2))
                        return {"source": self.rel(path), "percent": round(covered * 100 / max(missed + covered, 1), 2)}
                elif path.name == "lcov.info":
                    lf = 0
                    lh = 0
                    for line in self.read_lines(path, max_bytes=500000):
                        if line.startswith("LF:"):
                            lf += int(line[3:])
                        elif line.startswith("LH:"):
                            lh += int(line[3:])
                    if lf:
                        return {"source": self.rel(path), "percent": round(lh * 100 / lf, 2)}
            except Exception:
                continue
        return None

    def try_run_coverage(self) -> dict[str, Any]:
        if self.config.get("safe_mode", True):
            self.add_finding("info", "tests", "Coverage execution skipped", "Runtime coverage execution is disabled in safe mode.", rule_id="coverage_skipped_safe_mode", confidence="high")
            return {"coverage_percent": None, "source": None}

        commands = [
            ["pytest", "--cov=.", "--cov-report=xml"],
            [sys.executable, "-m", "pytest", "--cov=.", "--cov-report=xml"],
            ["npm", "test", "--", "--coverage"],
            ["npx", "vitest", "run", "--coverage"],
            ["go", "test", "./...", "-coverprofile=coverage.out"],
        ]
        timeout = int(self.config.get("coverage_timeout", 180))
        for command in commands:
            try:
                proc = subprocess.run(command, cwd=str(self.repo_path), capture_output=True, text=True, timeout=timeout)
                if proc.returncode == 0:
                    coverage = self.detect_existing_coverage_report()
                    self.add_finding("info", "tests", "Coverage run succeeded", f"Coverage command succeeded: {' '.join(command)}", rule_id="coverage_run_succeeded", confidence="high")
                    if coverage:
                        return {"coverage_percent": coverage.get("percent"), "source": coverage.get("source")}
                    return {"coverage_percent": None, "source": " ".join(command)}
            except Exception:
                continue
        self.add_finding("low", "tests", "Coverage run failed or unsupported", "The scanner could not successfully run a supported coverage command.", rule_id="coverage_run_failed", confidence="medium")
        return {"coverage_percent": None, "source": None}

    def calculate_test_confidence(self, metadata: dict[str, Any]) -> int:
        score = 100
        source_files = metadata.get("source_files", 0)
        test_files = metadata.get("test_files", 0)
        if source_files and test_files == 0:
            return 10
        ratio = test_files / max(source_files, 1)
        if ratio < 0.10:
            score -= 35
        elif ratio < 0.20:
            score -= 20
        elif ratio < 0.35:
            score -= 10
        if not metadata.get("frameworks"):
            score -= 15
        if not metadata.get("test_commands"):
            score -= 10
        score -= min(len(metadata.get("critical_paths_without_tests") or []) * 2, 30)
        if not metadata.get("negative_test_signals"):
            score -= 15
        pct = metadata.get("coverage_percent")
        if pct is not None:
            try:
                pct_f = float(pct)
                if pct_f >= 80:
                    score += 5
                elif pct_f < 50:
                    score -= 15
            except Exception:
                pass
        return max(0, min(score, 100))


def render_text_report(result: dict[str, Any]) -> str:
    summary = result["summary"]
    findings = result["findings"]
    metadata = result["metadata"]
    tests = metadata.get("tests", {})

    lines: list[str] = []
    lines.append("AI Code Scanner Report")
    lines.append("=" * 88)
    lines.append(f"Repository: {metadata.get('repo_path')}")
    lines.append(f"Scanner version: {metadata.get('scanner_version')}")
    lines.append(f"Files indexed: {metadata.get('files_indexed')} (text: {metadata.get('text_files_indexed')})")
    lines.append("")
    lines.append("Summary")
    lines.append("-" * 88)
    lines.append(f"Total findings: {summary.get('total_findings')}")
    lines.append(f"Display score: {summary.get('display_score')}/100")
    lines.append(f"Raw risk score: {summary.get('raw_risk_score')}")
    severities = summary.get("severity_counts", {})
    lines.append(
        "Severities: "
        f"critical={severities.get('critical', 0)}, high={severities.get('high', 0)}, "
        f"medium={severities.get('medium', 0)}, low={severities.get('low', 0)}, info={severities.get('info', 0)}"
    )

    if tests:
        lines.append("")
        lines.append("Test Analysis")
        lines.append("-" * 88)
        lines.append(f"Source files: {tests.get('source_files')}")
        lines.append(f"Test files: {tests.get('test_files')}")
        lines.append(f"Test-to-source ratio: {summary.get('tests', {}).get('test_to_source_ratio')}")
        lines.append(f"Frameworks: {', '.join(tests.get('frameworks', [])) or 'none'}")
        lines.append(f"Test commands detected: {len(tests.get('test_commands', []))}")
        lines.append(f"Coverage report found: {'yes' if tests.get('coverage_report_found') else 'no'}")
        if tests.get("coverage_percent") is not None:
            lines.append(f"Coverage percent: {tests.get('coverage_percent')}%")
        lines.append(f"Test confidence score: {tests.get('test_confidence_score')}/100")
        if tests.get("critical_paths_without_tests"):
            lines.append("Likely under-tested critical files:")
            for item in tests["critical_paths_without_tests"][:10]:
                lines.append(f"  - {item}")

    lines.append("")
    lines.append("Findings")
    lines.append("-" * 88)
    if not findings:
        lines.append("No findings.")
    else:
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for i, finding in enumerate(sorted(findings, key=lambda item: (severity_rank.get(item["severity"], 9), item["category"], item["title"])), start=1):
            location = ""
            if finding.get("path"):
                location = f" [{finding['path']}"
                if finding.get("line"):
                    location += f":{finding['line']}"
                location += "]"
            lines.append(f"{i}. {finding['severity'].upper()} | {finding['category']} | {finding['title']}{location}")
            lines.append(f"   {finding['description']}")
            if finding.get("confidence"):
                lines.append(f"   Confidence: {finding['confidence']}")
            if finding.get("evidence"):
                lines.append(f"   Evidence: {finding['evidence']}")
    return "\n".join(lines)


def save_json(path: Path, result: dict[str, Any]) -> None:
    path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")


def save_csv(path: Path, result: dict[str, Any]) -> None:
    findings = result.get("findings", [])
    headers = ["severity", "category", "title", "description", "path", "line", "rule_id", "evidence", "confidence"]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        for item in findings:
            writer.writerow({key: item.get(key) for key in headers})


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AI code scanner for repository risk, infra, and test hygiene.")
    parser.add_argument("repo_path", help="Path to local repository")
    parser.add_argument("--check-tests", action="store_true", default=True, help="Analyze tests, frameworks, and coverage signals")
    parser.add_argument("--no-check-tests", action="store_false", dest="check_tests", help="Disable test analysis")
    parser.add_argument("--run-coverage", action="store_true", help="Attempt to run coverage tools")
    parser.add_argument("--unsafe-exec", action="store_true", help="Allow executing repository test commands")
    parser.add_argument("--coverage-timeout", type=int, default=180, help="Timeout for runtime coverage commands")
    parser.add_argument("--output-text", help="Save human-readable report to file")
    parser.add_argument("--output-json", help="Save JSON report to file")
    parser.add_argument("--output-csv", help="Save findings CSV to file")
    parser.add_argument("--max-read-bytes", type=int, default=12000, help="Default max bytes to read for text heuristics")
    parser.add_argument("--test-read-bytes", type=int, default=8000, help="Max bytes to read per test file for static analysis")
    parser.add_argument("--max-test-files", type=int, default=250, help="Max number of test files to inspect deeply")
    parser.add_argument("--max-source-files", type=int, default=800, help="Max number of source files to inspect for critical mapping")
    parser.add_argument("--max-test-file-size", type=int, default=300000, help="Skip very large test files during quality signal analysis")
    parser.add_argument("--max-workers", type=int, default=min(16, (os.cpu_count() or 4) * 2), help="Worker count for threaded file analysis")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    config = {
        "check_tests": args.check_tests,
        "run_coverage": args.run_coverage,
        "safe_mode": not args.unsafe_exec,
        "coverage_timeout": args.coverage_timeout,
        "max_read_bytes": args.max_read_bytes,
        "test_read_bytes": args.test_read_bytes,
        "max_test_files": args.max_test_files,
        "max_source_files": args.max_source_files,
        "max_test_file_size": args.max_test_file_size,
        "max_workers": args.max_workers,
    }

    scanner = Scanner(args.repo_path, config)
    result = scanner.run()
    report_text = render_text_report(result)
    print(report_text)

    if args.output_text:
        Path(args.output_text).write_text(report_text, encoding="utf-8")
    if args.output_json:
        save_json(Path(args.output_json), result)
    if args.output_csv:
        save_csv(Path(args.output_csv), result)

    sev = result["summary"]["severity_counts"]
    if sev.get("critical", 0) > 0 or sev.get("high", 0) > 0:
        return 2
    if result["summary"].get("total_findings", 0) > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())