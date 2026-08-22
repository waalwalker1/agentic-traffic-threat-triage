"""Public repository normalization and residue audit script."""

import os
import re
import subprocess
import sys
from pathlib import Path


DISALLOWED_PATTERNS = [
    r"\brecruiter\b",
    r"\bhiring manager\b",
    r"\btarget role\b",
    r"\bcandidate\b",
    r"\bportfolio\b",
    r"\bproof-of-work\b",
    r"\bjob application\b",
    r"\brole-to-proof\b",
    r"\b9/10\b",
]

ALLOWED_FILES = {
    "scripts/check_public_normalization.py",
}


def audit_normalization() -> None:
    print("=== Checking Public Repository Normalization ===")
    violations = []
    root = Path(".")

    skip_dirs = {".git", ".venv", "node_modules", ".build", "__pycache__", "dist", "artifacts"}

    # 1. Verify BUILD_SPEC.md and .build are not tracked by git
    try:
        git_tracked = subprocess.check_output(["git", "ls-files"], text=True).splitlines()
        for f in git_tracked:
            if f.startswith(".build") or f == "BUILD_SPEC.md":
                violations.append((f, [f"Forbidden build file tracked in git: {f}"]))
    except Exception:
        pass

    # 2. Verify no disallowed terms in public files
    for path in root.rglob("*"):
        if path.is_dir() or any(skip in path.parts for skip in skip_dirs):
            continue
        rel_path = str(path)
        if rel_path in ALLOWED_FILES or "BUILD_SPEC.md" in rel_path or ".build" in rel_path:
            continue
        if path.suffix not in (".py", ".ts", ".tsx", ".md", ".json", ".html", ".yml", ".yaml", ".txt", ".toml"):
            continue

        try:
            content = path.read_text(encoding="utf-8")
            file_findings = []
            for pat in DISALLOWED_PATTERNS:
                matches = re.findall(pat, content, re.IGNORECASE)
                if matches:
                    file_findings.append(f"Disallowed term matched '{pat}': {set(matches)}")
            if file_findings:
                violations.append((rel_path, file_findings))
        except Exception:
            pass

    if violations:
        print(f"FAILED: Found {len(violations)} normalization violations in public files:")
        for file_path, findings in violations:
            print(f"  {file_path}: {findings}")
        sys.exit(1)
    else:
        print("PASS: Public repository normalization clean. Zero job/recruiter/self-score residue.")


if __name__ == "__main__":
    audit_normalization()
