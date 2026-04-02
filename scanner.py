#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

try:
    import yaml  # type: ignore
except Exception:
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
    "__pycache__", ".idea", ".mypy_cache", ".terraform", ".scanner_cache", "target"
}

TEST_DIR_NAMES = {"tests", "test", "__tests__", "spec", "specs"}

CRITICAL_KEYWORDS = [
    "auth", "login", "password", "token", "jwt", "permission", "role",
    "admin", "payment", "billing", "checkout", "webhook", "upload",
    "config", "secret", "api", "controller", "middleware", "session",
    "oauth", "crypto", "sign", "verify", "callback"
]

SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Stripe Live Secret", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")),
    ("Private Key Block", re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----")),
    ("Generic API Key Assignment", re.compile(r"(?i)\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*[\"'][^\"'\n]{8,}[\"']")),
    ("JWT-like Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b")),
]

ENV_SENSITIVE_KEYS = {
    "password", "passwd", "secret", "token", "api_key", "apikey", "private_key", "access_key",
    "client_secret", "auth_token", "db_url", "database_url"
}

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

DEFAULT_IGNORE_PATTERNS = [
    re.compile(r"package-lock\.json$"),
    re.compile(r"yarn\.lock$"),
    re.compile(r"pnpm-lock\.yaml$"),
    re.compile(r"poetry\.lock$"),
    re.compile(r"Cargo\.lock$"),
    re.compile(r"\.min\.(js|css)$"),
]


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


class Scanner:
    def __init__(self, repo_path: str, config: dict[str, Any]) -> None:
        self.repo_path = Path(repo_path).resolve()
        self.config = config
        self.findings: list[Finding] = []
        self._text_cache: dict[str, str] = {}
        self._line_cache: dict[str, list[str]] = {}

    def run(self) -> dict[str, Any]:
        if not self.repo_path.exists() or not self.repo_path.is_dir():
            raise FileNotFoundError(f"Repository path does not exist or is not a directory: {self.repo_path}")

        summary: dict[str, Any] = {}
        metadata: dict[str, Any] = {
            "repo_path": str(self.repo_path),
            "generated_at": int(time.time()),
            "scanner_version": "1.0.0",
        }

        self.scan_secrets()
        self.scan_ai_risks()
        self.scan_terraform()
        self.scan_kubernetes()
        self.scan_env_files()
        self.scan_docker_compose()
        self.scan_ci_configs()
        self.scan_gitignore_and_hygiene()

        if self.config.get("check_tests", True):
            tests_data = self.analyze_tests()
            summary["tests"] = tests_data["summary"]
            metadata["tests"] = tests_data["metadata"]

        summary["severity_counts"] = self.severity_counts()
        summary["category_counts"] = self.category_counts()
        summary["risk_score"] = self.calculate_risk_score()
        summary["test_confidence_score"] = metadata.get("tests", {}).get("test_confidence_score")
        summary["total_findings"] = len(self.findings)

        return {
            "summary": summary,
            "metadata": metadata,
            "findings": [asdict(f) for f in self.findings],
        }

    # ---------- generic helpers ----------
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
    ) -> None:
        self.findings.append(Finding(
            severity=severity,
            category=category,
            title=title,
            description=description,
            path=path,
            line=line,
            rule_id=rule_id,
            evidence=evidence,
        ))

    def severity_counts(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def category_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.category] = counts.get(f.category, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))

    def calculate_risk_score(self) -> int:
        weights = {"critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0}
        raw = sum(weights.get(f.severity, 0) for f in self.findings)
        return max(0, min(100, raw))

    def is_excluded(self, path: Path) -> bool:
        return any(part in EXCLUDED_DIRS for part in path.parts)

    def iter_files(self) -> Iterable[Path]:
        for p in self.repo_path.rglob("*"):
            if p.is_file() and not self.is_excluded(p):
                if any(r.search(str(p)) for r in DEFAULT_IGNORE_PATTERNS):
                    continue
                yield p

    def is_text_file(self, path: Path) -> bool:
        suffix = path.suffix.lower()
        if suffix in TEXT_EXTENSIONS:
            return True
        if path.name.lower() == "dockerfile":
            return True
        if path.name.startswith(".env"):
            return True
        return False

    def read_text(self, path: Path) -> str:
        key = str(path)
        if key not in self._text_cache:
            try:
                self._text_cache[key] = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                self._text_cache[key] = ""
        return self._text_cache[key]

    def read_lines(self, path: Path) -> list[str]:
        key = str(path)
        if key not in self._line_cache:
            self._line_cache[key] = self.read_text(path).splitlines()
        return self._line_cache[key]

    def rel(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.repo_path))
        except Exception:
            return str(path)

    def guess_line(self, path: Path, pattern: re.Pattern[str]) -> tuple[int | None, str | None]:
        for i, line in enumerate(self.read_lines(path), start=1):
            if pattern.search(line):
                return i, line.strip()[:300]
        return None, None

    def sha256(self, value: str) -> str:
        return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:12]

    # ---------- secrets ----------
    def scan_secrets(self) -> None:
        for path in self.iter_files():
            if not self.is_text_file(path):
                continue
            content = self.read_text(path)
            if not content:
                continue
            rel = self.rel(path)

            for title, pattern in SECRET_PATTERNS:
                match = pattern.search(content)
                if match:
                    line, evidence = self.guess_line(path, pattern)
                    sev = "critical" if "Private Key" in title else "high"
                    self.add_finding(
                        severity=sev,
                        category="secrets",
                        title=title,
                        description=f"Potential secret detected in {rel}.",
                        path=rel,
                        line=line,
                        rule_id="secret_detected",
                        evidence=evidence,
                    )

    # ---------- generic code / AI-risk heuristics ----------
    def scan_ai_risks(self) -> None:
        for path in self.iter_files():
            if path.suffix.lower() not in SOURCE_EXTENSIONS and path.name.lower() != "dockerfile":
                continue
            content = self.read_text(path)
            if not content:
                continue
            rel = self.rel(path)

            for title, severity, pattern in AI_RISK_PATTERNS:
                if pattern.search(content):
                    line, evidence = self.guess_line(path, pattern)
                    self.add_finding(
                        severity=severity,
                        category="ai_risk",
                        title=title,
                        description=f"Potential AI-generated or risky implementation pattern detected in {rel}.",
                        path=rel,
                        line=line,
                        rule_id="ai_risk_pattern",
                        evidence=evidence,
                    )

            if path.suffix.lower() == ".py":
                self.scan_python_specific(path)

    def scan_python_specific(self, path: Path) -> None:
        content = self.read_text(path)
        rel = self.rel(path)
        try:
            tree = ast.parse(content)
        except Exception:
            return

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # requests without timeout
                func_name = self._ast_call_name(node.func)
                if func_name in {"requests.get", "requests.post", "requests.put", "requests.delete", "requests.patch", "requests.request"}:
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
                        )
                if func_name in {"open"}:
                    # weak heuristic for writing secrets/tokens to logs or files not done here
                    pass

    def _ast_call_name(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parts: list[str] = []
            cur: ast.AST | None = node
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
                return ".".join(reversed(parts))
        return None

    # ---------- Terraform ----------
    def scan_terraform(self) -> None:
        tf_files = [p for p in self.iter_files() if p.suffix.lower() in {".tf", ".tfvars"}]
        if not tf_files:
            return

        for path in tf_files:
            content = self.read_text(path)
            rel = self.rel(path)
            checks = [
                ("Public S3 ACL", "high", re.compile(r'(?is)resource\s+"aws_s3_bucket[^\n]*.*?acl\s*=\s*"public-read"')),
                ("0.0.0.0/0 ingress", "high", re.compile(r'(?is)cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0/0"')),
                ("Security group allows all traffic", "high", re.compile(r'(?is)from_port\s*=\s*0.*?to_port\s*=\s*0.*?protocol\s*=\s*"-1"')),
                ("DB storage not encrypted", "high", re.compile(r'(?is)resource\s+"aws_db_instance".*?(storage_encrypted\s*=\s*false|kms_key_id\s*=\s*null)')),
                ("Terraform hardcoded secret", "critical", re.compile(r'(?i)(password|secret|token)\s*=\s*"[^"]{8,}"')),
            ]
            for title, severity, pattern in checks:
                if pattern.search(content):
                    line, evidence = self.guess_line(path, pattern)
                    self.add_finding(
                        severity=severity,
                        category="terraform",
                        title=title,
                        description=f"Potential Terraform issue detected in {rel}.",
                        path=rel,
                        line=line,
                        rule_id="terraform_risk",
                        evidence=evidence,
                    )

        filenames = {p.name for p in tf_files}
        if "versions.tf" not in filenames and "terraform.tf" not in filenames:
            self.add_finding(
                severity="low",
                category="terraform",
                title="Terraform version pinning not obvious",
                description="Terraform files found, but versions.tf or terraform.tf was not found. Consider pinning required_version and providers.",
                rule_id="terraform_version_pinning",
            )

    # ---------- Kubernetes ----------
    def scan_kubernetes(self) -> None:
        yaml_files = [p for p in self.iter_files() if p.suffix.lower() in {".yml", ".yaml"}]
        if not yaml_files:
            return

        for path in yaml_files:
            content = self.read_text(path)
            if not any(k in content for k in ["apiVersion:", "kind:"]):
                continue
            rel = self.rel(path)
            if not any(kind in content for kind in ["Deployment", "StatefulSet", "DaemonSet", "Pod", "CronJob", "Job"]):
                continue

            patterns = [
                ("Container running as root", "high", re.compile(r'(?is)runAsNonRoot\s*:\s*false')),
                ("Privileged container", "high", re.compile(r'(?is)privileged\s*:\s*true')),
                ("Latest tag used", "medium", re.compile(r'(?im)^\s*image\s*:\s*.+:latest\s*$')),
                ("Image pull policy Always missing with latest", "low", re.compile(r'(?im)^\s*image\s*:\s*.+:latest\s*$')),
                ("Secret value in manifest", "critical", re.compile(r'(?i)(password|secret|token|api[_-]?key)\s*:\s*["\']?[A-Za-z0-9_./+=-]{8,}')),
            ]
            for title, severity, pattern in patterns:
                if pattern.search(content):
                    line, evidence = self.guess_line(path, pattern)
                    self.add_finding(
                        severity=severity,
                        category="kubernetes",
                        title=title,
                        description=f"Potential Kubernetes manifest issue detected in {rel}.",
                        path=rel,
                        line=line,
                        rule_id="k8s_risk",
                        evidence=evidence,
                    )

            if "resources:" not in content:
                self.add_finding(
                    severity="low",
                    category="kubernetes",
                    title="No resource requests/limits detected",
                    description=f"Kubernetes workload manifest in {rel} does not appear to define resources.",
                    path=rel,
                    rule_id="k8s_no_resources",
                )
            if "readinessProbe:" not in content and "livenessProbe:" not in content:
                self.add_finding(
                    severity="low",
                    category="kubernetes",
                    title="No health probes detected",
                    description=f"Kubernetes workload manifest in {rel} does not appear to define readiness/liveness probes.",
                    path=rel,
                    rule_id="k8s_no_probes",
                )

    # ---------- .env ----------
    def scan_env_files(self) -> None:
        env_files = [p for p in self.iter_files() if p.name.startswith(".env") or p.suffix.lower() == ".env"]
        for path in env_files:
            rel = self.rel(path)
            for i, line in enumerate(self.read_lines(path), start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or "=" not in stripped:
                    continue
                key, _, value = stripped.partition("=")
                key_l = key.strip().lower()
                val = value.strip().strip('"').strip("'")
                if key_l in ENV_SENSITIVE_KEYS and val and not any(x in val for x in ["changeme", "example", "localhost", "<", "{"]):
                    self.add_finding(
                        severity="high",
                        category="env",
                        title="Sensitive value in .env file",
                        description=f"Sensitive-looking environment variable found in {rel}: {key.strip()}.",
                        path=rel,
                        line=i,
                        rule_id="env_sensitive_value",
                        evidence=f"{key.strip()}=<redacted:{self.sha256(val)}>",
                    )
                if key.strip().upper() == "DEBUG" and val.lower() in {"1", "true", "yes", "on"}:
                    self.add_finding(
                        severity="medium",
                        category="env",
                        title="DEBUG enabled in env file",
                        description=f"DEBUG appears enabled in {rel}.",
                        path=rel,
                        line=i,
                        rule_id="env_debug_enabled",
                        evidence=stripped,
                    )

    # ---------- Docker Compose ----------
    def scan_docker_compose(self) -> None:
        compose_candidates = [
            p for p in self.iter_files()
            if p.name.lower() in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
        ]
        for path in compose_candidates:
            rel = self.rel(path)
            content = self.read_text(path)
            patterns = [
                ("Privileged container in compose", "high", re.compile(r'(?im)^\s*privileged\s*:\s*true\s*$')),
                ("Container with host network", "high", re.compile(r'(?im)^\s*network_mode\s*:\s*["\']?host["\']?\s*$')),
                ("Container runs as root user", "medium", re.compile(r'(?im)^\s*user\s*:\s*["\']?0(:0)?["\']?\s*$')),
                ("Docker socket mounted", "high", re.compile(r'/var/run/docker\.sock')),
                ("Latest image tag in compose", "low", re.compile(r'(?im)^\s*image\s*:\s*.+:latest\s*$')),
            ]
            for title, severity, pattern in patterns:
                if pattern.search(content):
                    line, evidence = self.guess_line(path, pattern)
                    self.add_finding(
                        severity=severity,
                        category="docker_compose",
                        title=title,
                        description=f"Potential Docker Compose issue detected in {rel}.",
                        path=rel,
                        line=line,
                        rule_id="docker_compose_risk",
                        evidence=evidence,
                    )

    # ---------- CI / hygiene ----------
    def scan_ci_configs(self) -> None:
        ci_paths = [
            self.repo_path / ".gitlab-ci.yml",
            self.repo_path / "azure-pipelines.yml",
            self.repo_path / "bitbucket-pipelines.yml",
        ]
        github_dir = self.repo_path / ".github" / "workflows"
        if github_dir.exists():
            ci_paths.extend(list(github_dir.glob("*.yml")) + list(github_dir.glob("*.yaml")))

        for path in ci_paths:
            if not path.exists() or not path.is_file():
                continue
            rel = self.rel(path)
            content = self.read_text(path)
            if re.search(r'(?i)(curl|wget).*(sh|bash)', content):
                self.add_finding(
                    severity="medium",
                    category="ci",
                    title="Remote script execution in CI",
                    description=f"CI config {rel} appears to pipe remote content into a shell.",
                    path=rel,
                    rule_id="ci_remote_script",
                )
            if "npm audit" not in content and "pip-audit" not in content and "trivy" not in content and "snyk" not in content:
                self.add_finding(
                    severity="low",
                    category="ci",
                    title="No obvious dependency/security scan in CI",
                    description=f"CI config {rel} does not show an obvious dependency or container security scan.",
                    path=rel,
                    rule_id="ci_no_security_scan",
                )

    def scan_gitignore_and_hygiene(self) -> None:
        gitignore = self.repo_path / ".gitignore"
        if not gitignore.exists():
            self.add_finding(
                severity="low",
                category="repo_hygiene",
                title="Missing .gitignore",
                description="Repository does not contain a .gitignore file.",
                rule_id="missing_gitignore",
            )
            return
        content = self.read_text(gitignore)
        for required in [".env", "node_modules", "__pycache__", ".pytest_cache", ".terraform"]:
            if required not in content:
                self.add_finding(
                    severity="info",
                    category="repo_hygiene",
                    title="Potential missing ignore rule",
                    description=f".gitignore does not visibly contain '{required}'.",
                    path=".gitignore",
                    rule_id="gitignore_missing_common_rule",
                )

    # ---------- Test analysis ----------
    def analyze_tests(self) -> dict[str, Any]:
        source_files = self.collect_source_files()
        test_files = self.collect_test_files()
        frameworks = sorted(self.detect_test_frameworks())
        test_commands = self.detect_test_commands()
        coverage_info = self.detect_existing_coverage_report()

        metadata: dict[str, Any] = {
            "source_files": len(source_files),
            "test_files": len(test_files),
            "frameworks": frameworks,
            "test_commands": test_commands,
            "coverage_report_found": bool(coverage_info),
            "coverage_percent": coverage_info.get("percent") if coverage_info else None,
            "coverage_source": coverage_info.get("source") if coverage_info else None,
            "critical_paths_without_tests": [],
            "negative_test_signals": [],
            "positive_test_signals": [],
        }

        ratio = len(test_files) / max(len(source_files), 1)

        if source_files and not test_files:
            self.add_finding(
                severity="high",
                category="tests",
                title="No tests detected",
                description="Repository contains source files but no test files were detected.",
                rule_id="tests_none",
            )
        elif test_files and ratio < 0.15:
            self.add_finding(
                severity="medium",
                category="tests",
                title="Low test-to-source ratio",
                description=f"Detected {len(test_files)} test files for {len(source_files)} source files.",
                rule_id="tests_low_ratio",
            )

        if source_files and not frameworks:
            self.add_finding(
                severity="medium",
                category="tests",
                title="No test framework detected",
                description="No known testing framework was found in common project files.",
                rule_id="tests_no_framework",
            )

        if source_files and not test_commands:
            self.add_finding(
                severity="low",
                category="tests",
                title="No obvious test command detected",
                description="No obvious test command was found in package.json, Makefile, or CI configuration.",
                rule_id="tests_no_command",
            )

        critical_without_tests = self.analyze_critical_code_test_presence(source_files, test_files)
        metadata["critical_paths_without_tests"] = critical_without_tests

        quality = self.analyze_test_quality_signals(test_files)
        metadata["negative_test_signals"] = quality["negative"]
        metadata["positive_test_signals"] = quality["positive"]

        if self.config.get("run_coverage"):
            runtime = self.try_run_coverage()
            if runtime.get("coverage_percent") is not None:
                metadata["coverage_report_found"] = True
                metadata["coverage_percent"] = runtime["coverage_percent"]
                metadata["coverage_source"] = runtime.get("source")

        test_confidence_score = self.calculate_test_confidence(metadata)
        metadata["test_confidence_score"] = test_confidence_score

        summary = {
            "source_files": len(source_files),
            "test_files": len(test_files),
            "test_to_source_ratio": round(ratio, 2),
            "frameworks": frameworks,
            "test_commands_detected": len(test_commands),
            "coverage_report_found": metadata["coverage_report_found"],
            "coverage_percent": metadata["coverage_percent"],
            "critical_paths_without_tests": len(metadata["critical_paths_without_tests"]),
            "test_confidence_score": test_confidence_score,
        }
        return {"summary": summary, "metadata": metadata}

    def collect_source_files(self) -> list[str]:
        results: list[str] = []
        for p in self.iter_files():
            if p.suffix.lower() in SOURCE_EXTENSIONS and not self.is_test_file(p):
                results.append(self.rel(p))
        return results

    def collect_test_files(self) -> list[str]:
        results: list[str] = []
        for p in self.iter_files():
            if self.is_test_file(p):
                results.append(self.rel(p))
        return results

    def is_test_file(self, path: Path) -> bool:
        name = path.name.lower()
        parts = {part.lower() for part in path.parts}
        if parts & TEST_DIR_NAMES:
            return True
        markers = [".test.", ".spec.", "_test.", "test_", "tests.py", "tests.ts", "tests.js"]
        if any(m in name for m in markers):
            return True
        if name.endswith("test.java") or name.endswith("tests.java"):
            return True
        return False

    def detect_test_frameworks(self) -> set[str]:
        frameworks: set[str] = set()
        candidates = [
            "package.json", "requirements.txt", "pyproject.toml", "setup.py", "setup.cfg",
            "pom.xml", "build.gradle", "build.gradle.kts", "go.mod", "Gemfile"
        ]
        tokens = [
            "pytest", "unittest", "nose", "tox", "jest", "vitest", "mocha", "playwright",
            "cypress", "ava", "junit", "testng", "mockito", "jacoco", "rspec", "minitest", "cucumber"
        ]
        for name in candidates:
            p = self.repo_path / name
            if not p.exists():
                continue
            content = self.read_text(p).lower()
            for token in tokens:
                if token in content:
                    frameworks.add(token)
        if (self.repo_path / "go.mod").exists():
            frameworks.add("go test")
        return frameworks

    def detect_test_commands(self) -> list[str]:
        commands: list[str] = []
        package_json = self.repo_path / "package.json"
        if package_json.exists():
            try:
                data = json.loads(self.read_text(package_json))
                scripts = data.get("scripts", {})
                for key, value in scripts.items():
                    if "test" in key.lower() or "cover" in key.lower():
                        commands.append(f"package.json:{key} -> {value}")
            except Exception:
                pass

        makefile = self.repo_path / "Makefile"
        if makefile.exists():
            for line in self.read_lines(makefile):
                line_s = line.strip()
                if line_s.startswith("test") or any(t in line_s for t in ["pytest", "jest", "vitest", "go test", "mvn test", "gradle test"]):
                    commands.append(f"Makefile -> {line_s}")

        ci_files: list[Path] = []
        for name in [".gitlab-ci.yml", "azure-pipelines.yml", "bitbucket-pipelines.yml"]:
            p = self.repo_path / name
            if p.exists():
                ci_files.append(p)
        gh = self.repo_path / ".github" / "workflows"
        if gh.exists():
            ci_files.extend(list(gh.glob("*.yml")) + list(gh.glob("*.yaml")))

        for ci in ci_files:
            content = self.read_text(ci)
            for marker in ["pytest", "jest", "vitest", "go test", "mvn test", "gradle test", "coverage", "playwright test"]:
                if marker in content:
                    commands.append(f"{self.rel(ci)} -> contains {marker}")
        return sorted(set(commands))

    def analyze_critical_code_test_presence(self, source_files: list[str], test_files: list[str]) -> list[str]:
        critical_without: list[str] = []
        test_names = " ".join(Path(t).name.lower() for t in test_files)
        for src in source_files:
            src_l = src.lower()
            if not any(keyword in src_l for keyword in CRITICAL_KEYWORDS):
                continue
            stem = Path(src).stem.lower()
            guesses = {stem, stem.replace(".service", ""), stem.replace(".controller", ""), stem.replace(".api", "")}
            if not any(g and g in test_names for g in guesses):
                critical_without.append(src)

        for item in critical_without[:20]:
            self.add_finding(
                severity="medium",
                category="tests",
                title="Critical module may lack direct tests",
                description=f"No obvious matching test file detected for critical module: {item}",
                path=item,
                rule_id="tests_critical_uncovered",
            )
        if len(critical_without) > 20:
            self.add_finding(
                severity="medium",
                category="tests",
                title="Multiple critical modules may lack tests",
                description=f"{len(critical_without)} critical files have no obvious matching test.",
                rule_id="tests_many_critical_uncovered",
            )
        return critical_without

    def analyze_test_quality_signals(self, test_files: list[str]) -> dict[str, list[str]]:
        negative: list[str] = []
        positive: list[str] = []
        weak: list[str] = []

        for rel_path in test_files[:500]:
            path = self.repo_path / rel_path
            content = self.read_text(path).lower()
            for marker in NEGATIVE_TEST_MARKERS:
                if marker in content:
                    negative.append(f"{rel_path}: {marker}")
            for marker in POSITIVE_TEST_MARKERS:
                if marker in content:
                    positive.append(f"{rel_path}: {marker}")
            for marker in WEAK_TEST_MARKERS:
                if marker in content:
                    weak.append(f"{rel_path}: {marker}")

        if test_files and not negative:
            self.add_finding(
                severity="medium",
                category="tests",
                title="No obvious negative test scenarios detected",
                description="Tests were found, but no obvious signals of invalid input, auth failures, exceptions, or error handling were detected.",
                rule_id="tests_no_negative_signals",
            )
        if test_files and not positive:
            self.add_finding(
                severity="low",
                category="tests",
                title="Limited advanced testing signals detected",
                description="No obvious mocks, parametrization, fixtures, or integration patterns were found.",
                rule_id="tests_limited_signals",
            )
        if weak:
            self.add_finding(
                severity="low",
                category="tests",
                title="Skipped or unfinished tests detected",
                description=f"Detected {len(weak)} skipped/TODO/FIXME test markers.",
                rule_id="tests_skipped_or_todo",
            )
        return {"negative": negative[:50], "positive": positive[:50]}

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
                    data = json.loads(self.read_text(path))
                    total = data.get("total", {})
                    lines = total.get("lines", {})
                    pct = lines.get("pct")
                    if pct is not None:
                        return {"source": self.rel(path), "percent": float(pct)}
                if path.name == "coverage.xml":
                    m = re.search(r'line-rate="([\d.]+)"', self.read_text(path))
                    if m:
                        return {"source": self.rel(path), "percent": round(float(m.group(1)) * 100, 2)}
                if path.name == "jacoco.xml":
                    m = re.search(r'<counter type="LINE" missed="(\d+)" covered="(\d+)"', self.read_text(path))
                    if m:
                        missed_n, covered_n = int(m.group(1)), int(m.group(2))
                        pct = round(covered_n * 100 / max(covered_n + missed_n, 1), 2)
                        return {"source": self.rel(path), "percent": pct}
                if path.name == "lcov.info":
                    lf = 0
                    lh = 0
                    for line in self.read_lines(path):
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
            self.add_finding(
                severity="info",
                category="tests",
                title="Coverage execution skipped",
                description="Runtime coverage execution is disabled in safe mode.",
                rule_id="coverage_skipped_safe_mode",
            )
            return {"coverage_percent": None, "source": None}

        commands = [
            ["pytest", "--cov=.", "--cov-report=xml"],
            ["python", "-m", "pytest", "--cov=.", "--cov-report=xml"],
            ["npm", "test", "--", "--coverage"],
            ["npx", "vitest", "run", "--coverage"],
            ["go", "test", "./...", "-coverprofile=coverage.out"],
        ]
        timeout = int(self.config.get("coverage_timeout", 180))
        for cmd in commands:
            try:
                proc = subprocess.run(
                    cmd,
                    cwd=str(self.repo_path),
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                if proc.returncode == 0:
                    cov = self.detect_existing_coverage_report()
                    self.add_finding(
                        severity="info",
                        category="tests",
                        title="Coverage run succeeded",
                        description=f"Coverage command succeeded: {' '.join(cmd)}",
                        rule_id="coverage_run_succeeded",
                    )
                    if cov:
                        return {"coverage_percent": cov.get("percent"), "source": cov.get("source")}
                    return {"coverage_percent": None, "source": " ".join(cmd)}
            except Exception:
                continue

        self.add_finding(
            severity="low",
            category="tests",
            title="Coverage run failed or unsupported",
            description="The scanner could not successfully run a supported coverage command.",
            rule_id="coverage_run_failed",
        )
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
        critical_paths = metadata.get("critical_paths_without_tests") or []
        score -= min(len(critical_paths) * 3, 30)
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
    lines.append("=" * 80)
    lines.append(f"Repository: {metadata.get('repo_path')}")
    lines.append(f"Scanner version: {metadata.get('scanner_version')}")
    lines.append("")
    lines.append("Summary")
    lines.append("-" * 80)
    lines.append(f"Total findings: {summary.get('total_findings')}")
    lines.append(f"Risk score: {summary.get('risk_score')}/100")
    sc = summary.get("severity_counts", {})
    lines.append(
        f"Severities: critical={sc.get('critical', 0)}, high={sc.get('high', 0)}, medium={sc.get('medium', 0)}, low={sc.get('low', 0)}, info={sc.get('info', 0)}"
    )

    if tests:
        lines.append("")
        lines.append("Test Analysis")
        lines.append("-" * 80)
        lines.append(f"Source files: {tests.get('source_files')}")
        lines.append(f"Test files: {tests.get('test_files')}")
        ratio = round((tests.get('test_files', 0) / max(tests.get('source_files', 1), 1)), 2)
        lines.append(f"Test-to-source ratio: {ratio}")
        lines.append(f"Frameworks: {', '.join(tests.get('frameworks', [])) or 'none'}")
        lines.append(f"Test commands detected: {len(tests.get('test_commands', []))}")
        lines.append(f"Coverage report found: {'yes' if tests.get('coverage_report_found') else 'no'}")
        if tests.get("coverage_percent") is not None:
            lines.append(f"Coverage percent: {tests.get('coverage_percent')}%")
        lines.append(f"Test confidence score: {tests.get('test_confidence_score')}/100")
        critical_missing = tests.get("critical_paths_without_tests", [])
        if critical_missing:
            lines.append("Likely under-tested critical files:")
            for item in critical_missing[:10]:
                lines.append(f"  - {item}")

    lines.append("")
    lines.append("Findings")
    lines.append("-" * 80)
    if not findings:
        lines.append("No findings.")
    else:
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for idx, f in enumerate(sorted(findings, key=lambda x: (severity_rank.get(x["severity"], 9), x["category"], x["title"])), start=1):
            loc = ""
            if f.get("path"):
                loc = f" [{f['path']}"
                if f.get("line"):
                    loc += f":{f['line']}"
                loc += "]"
            lines.append(f"{idx}. {f['severity'].upper()} | {f['category']} | {f['title']}{loc}")
            lines.append(f"   {f['description']}")
            if f.get("evidence"):
                lines.append(f"   Evidence: {f['evidence']}")

    return "\n".join(lines)


def save_json(path: Path, result: dict[str, Any]) -> None:
    path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")


def save_csv(path: Path, result: dict[str, Any]) -> None:
    fields = ["severity", "category", "title", "description", "path", "line", "rule_id", "evidence"]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in result["findings"]:
            writer.writerow({k: row.get(k) for k in fields})


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Static AI code scanner with test analysis and infra checks.")
    parser.add_argument("repo", help="Path to repository directory")
    parser.add_argument("--output-json", dest="output_json", help="Write JSON report to file")
    parser.add_argument("--output-csv", dest="output_csv", help="Write findings CSV to file")
    parser.add_argument("--output-text", dest="output_text", help="Write human-readable text report to file")
    parser.add_argument("--check-tests", action="store_true", default=True, help="Analyze tests and coverage signals")
    parser.add_argument("--run-coverage", action="store_true", help="Attempt to run coverage tools")
    parser.add_argument("--unsafe-exec", action="store_true", help="Allow executing repository test/coverage commands")
    parser.add_argument("--coverage-timeout", type=int, default=180, help="Timeout for coverage commands in seconds")
    parser.add_argument("--quiet", action="store_true", help="Print only minimal output")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    config = {
        "check_tests": args.check_tests,
        "run_coverage": args.run_coverage,
        "safe_mode": not args.unsafe_exec,
        "coverage_timeout": args.coverage_timeout,
    }

    scanner = Scanner(args.repo, config)
    result = scanner.run()
    text_report = render_text_report(result)

    if args.output_json:
        save_json(Path(args.output_json), result)
    if args.output_csv:
        save_csv(Path(args.output_csv), result)
    if args.output_text:
        Path(args.output_text).write_text(text_report, encoding="utf-8")

    if not args.quiet:
        print(text_report)
    else:
        print(json.dumps(result["summary"], ensure_ascii=False))

    sev = result["summary"].get("severity_counts", {})
    if sev.get("critical", 0) or sev.get("high", 0):
        return 2
    if result["findings"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())