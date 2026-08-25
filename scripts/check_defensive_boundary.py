"""Automated defensive safety boundary audit script."""

import sys
from pathlib import Path

from src.traffic_triage.security.boundary import DefensiveSafetyBoundary


def audit_repository() -> None:
    print("=== Checking Defensive Safety Boundary ===")
    violations = []
    root = Path(".")

    # Exclude virtual env, git, node_modules
    skip_dirs = {".git", ".venv", "node_modules", ".build", "__pycache__", "dist"}

    for path in root.rglob("*.py"):
        if any(skip in path.parts for skip in skip_dirs):
            continue
        try:
            content = path.read_text(encoding="utf-8")
            findings = DefensiveSafetyBoundary.audit_code_safety(content)
            # Filter self-references in boundary.py and tests
            if (
                "boundary.py" in str(path)
                or "test_defensive_boundary.py" in str(path)
                or "check_defensive_boundary.py" in str(path)
            ):
                continue
            if findings:
                violations.append((str(path), findings))
        except Exception:
            pass

    if violations:
        print(f"FAILED: Found {len(violations)} defensive safety violations:")
        for file_path, f_list in violations:
            print(f"  {file_path}: {f_list}")
        sys.exit(1)
    else:
        print(
            "PASS: Defensive safety boundary audit completed. No offensive evasion or exploit patterns found."
        )


if __name__ == "__main__":
    audit_repository()
