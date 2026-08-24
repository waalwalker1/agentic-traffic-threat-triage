"""Audits all markdown documentation in the repository to ensure all internal links and references resolve."""

from pathlib import Path
import re
import sys


def check_markdown_links() -> list[str]:
    repo_root = Path.cwd()
    md_files = list(repo_root.glob("*.md")) + list(repo_root.glob("docs/**/*.md")) + list(repo_root.glob("evals/**/*.md"))
    broken_links: list[str] = []

    link_pattern = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")

    for md_path in md_files:
        content = md_path.read_text(encoding="utf-8")
        matches = link_pattern.findall(content)

        for text, target in matches:
            # Skip external web links, mailto, anchor-only links
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue

            # Strip anchor fragment from target if present
            file_target = target.split("#")[0]
            if not file_target:
                continue

            # Resolve path relative to current markdown file
            resolved_path = (md_path.parent / file_target).resolve()
            if not resolved_path.exists():
                broken_links.append(f"{md_path.relative_to(repo_root)}: Broken link [{text}]({target}) -> {file_target}")

    return broken_links


def main() -> None:
    print("Checking markdown document links across repository...")
    broken = check_markdown_links()
    if broken:
        print(f"FAILED: Found {len(broken)} broken link(s):")
        for b in broken:
            print(f"  - {b}")
        sys.exit(1)
    else:
        print("SUCCESS: All internal markdown links and references verified!")


if __name__ == "__main__":
    main()
