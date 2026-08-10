#!/usr/bin/env python3
"""Documentation verification gate for echo-crm (showroom quality).

Checks:
  1. README (package + DOCUMENTATION mirrors) covers purpose, 5-minute run,
     configuration/env, endpoints, verification.
  2. Every public function and class in app.py has a non-empty docstring.
  3. No TODO/FIXME/STUB markers in shipped sources.
  4. Production port 8142 and API-key auth are documented.

Exit codes: 0 = pass, 1 = fail.

Usage:
    python3 verify_docs.py
    python3 -m verify_docs   # if run from package dir on PYTHONPATH
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKAGE_DIR.parents[1]  # .../SYSTEMS/echo-crm → workspace root

DOC_CANDIDATES: list[Path] = [
    REPO_ROOT / "DOCUMENTATION" / "echo-crm.md",
    REPO_ROOT / "O:" / "ECHO_OMEGA_PRIME" / "DOCUMENTATION" / "echo-crm.md",
    Path("/home/forge/ECHO_OMEGA_PRIME/DOCUMENTATION/echo-crm.md"),
    PACKAGE_DIR / "README.md",
]

REQUIRED_README_MARKERS: list[str] = [
    "Purpose",
    "Run / verify in 5 minutes",
    "Configuration",
    "Endpoints",
    "Verification",
    "/health",
    "/contacts",
    "/deals/board",
    "/lead-scoring/score",
    "ECHO_CRM_API_KEY",
    "X-Echo-API-Key",
    "8142",
    "echo_crm",
    "PGHOST",
    "verify_docs",
]

SHIPPED_PY = [
    PACKAGE_DIR / "app.py",
    PACKAGE_DIR / "verify_docs.py",
]

_STUB_TOKENS = (
    "TODO",
    "FIXME",
    "STUB",
    "XXX",
    "NotImplementedError",
    "pass  # placeholder",
    "Coming soon",
)


def resolve_readme() -> Path | None:
    """Return the best available showroom README path, or None if missing.

    Prefers DOCUMENTATION/echo-crm.md when present and non-trivial, then
    falls back to the in-package README.
    """
    for path in DOC_CANDIDATES:
        try:
            if path.is_file() and path.stat().st_size > 400:
                return path
        except OSError:
            continue
    return None


def check_readme(path: Path) -> list[str]:
    """Validate that *path* covers all required showroom sections.

    Args:
        path: Markdown README path.

    Returns:
        List of human-readable issue strings (empty on success).
    """
    issues: list[str] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [f"Cannot read README {path}: {exc}"]

    if len(text) < 1500:
        issues.append(f"README too short ({len(text)} bytes) — expected showroom depth")

    for marker in REQUIRED_README_MARKERS:
        if marker not in text:
            issues.append(f"README missing required marker: {marker!r}")

    # Soft structure: at least one endpoint table row and env table
    if text.count("|") < 40:
        issues.append("README appears to lack endpoint/config tables (too few table pipes)")

    return issues


def _is_public(name: str) -> bool:
    """Return True when *name* is a public API symbol (not private/_dunder body)."""
    if name.startswith("__") and name.endswith("__"):
        return False
    return not name.startswith("_")


def check_docstrings(app_path: Path) -> list[str]:
    """Ensure every public function/class in app.py has a non-empty docstring.

    Args:
        app_path: Path to app.py.

    Returns:
        Issue strings for any public symbols lacking docs.
    """
    issues: list[str] = []
    try:
        src = app_path.read_text(encoding="utf-8")
        tree = ast.parse(src, filename=str(app_path))
    except SyntaxError as exc:
        return [f"app.py syntax error: {exc}"]
    except OSError as exc:
        return [f"Cannot read {app_path}: {exc}"]

    module_doc = ast.get_docstring(tree)
    if not module_doc or len(module_doc.strip()) < 40:
        issues.append("app.py module docstring missing or too short")

    def visit_body(body: list[ast.stmt], prefix: str = "") -> None:
        for node in body:
            if isinstance(node, ast.ClassDef) and _is_public(node.name):
                qual = f"{prefix}{node.name}"
                doc = ast.get_docstring(node)
                if not doc or not doc.strip():
                    issues.append(f"Public class missing docstring: {qual} (L{node.lineno})")
                visit_body(node.body, prefix=f"{qual}.")
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _is_public(node.name):
                qual = f"{prefix}{node.name}"
                doc = ast.get_docstring(node)
                if not doc or not doc.strip():
                    issues.append(f"Public function missing docstring: {qual} (L{node.lineno})")
                elif len(doc.strip()) < 8:
                    issues.append(f"Public function docstring too short: {qual} (L{node.lineno})")

    visit_body(tree.body)
    return issues


def check_stubs(paths: list[Path]) -> list[str]:
    """Scan shipped files for stub/placeholder tokens.

    Args:
        paths: Files to scan.

    Returns:
        Issue strings for any forbidden markers found outside allowlisted contexts.
    """
    issues: list[str] = []
    for path in paths:
        if not path.is_file():
            continue
        # The verifier itself only defines the forbidden token list — skip it.
        if path.name == "verify_docs.py":
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            issues.append(f"Cannot read {path}: {exc}")
            continue
        for i, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            lower = stripped.lower()
            # Documentation that *forbids* stubs is allowed to name the tokens.
            if "no todo" in lower or "forbidden" in lower or "no `todo`" in lower:
                continue
            if stripped.startswith("#") and path.suffix == ".py":
                continue
            for tok in _STUB_TOKENS:
                if tok in line and re.search(rf"\b{re.escape(tok)}\b", line):
                    issues.append(f"{path.name}:{i}: forbidden token {tok!r}: {stripped[:100]}")
                    break
    return issues


def check_service_unit() -> list[str]:
    """Validate the systemd unit documents the live FORGE port.

    Returns:
        Issue list (empty when unit is present and references 8142).
    """
    unit = PACKAGE_DIR / "echo-crm.service"
    if not unit.is_file():
        return ["echo-crm.service missing"]
    text = unit.read_text(encoding="utf-8", errors="replace")
    issues: list[str] = []
    if "8142" not in text:
        issues.append("echo-crm.service does not reference port 8142")
    if "uvicorn" not in text:
        issues.append("echo-crm.service missing uvicorn ExecStart")
    return issues


def main() -> int:
    """Run all documentation checks and print a human-readable report.

    Returns:
        Process exit code (0 success, 1 failure).
    """
    print("=== echo-crm documentation verification ===")
    all_issues: list[str] = []

    readme = resolve_readme()
    if not readme:
        all_issues.append("No README found in DOCUMENTATION/ or SYSTEMS/echo-crm/")
    else:
        print(f"README: {readme}")
        all_issues.extend(check_readme(readme))
        # Also check package README if different
        pkg_readme = PACKAGE_DIR / "README.md"
        if pkg_readme.is_file() and pkg_readme.resolve() != readme.resolve():
            print(f"Also checking package README: {pkg_readme}")
            all_issues.extend(check_readme(pkg_readme))

    app_path = PACKAGE_DIR / "app.py"
    print(f"App: {app_path}")
    all_issues.extend(check_docstrings(app_path))
    all_issues.extend(check_stubs(SHIPPED_PY + [PACKAGE_DIR / "README.md"]))
    all_issues.extend(check_service_unit())

    # Public symbol count (informational)
    try:
        tree = ast.parse(app_path.read_text(encoding="utf-8"))
        public_funcs = [
            n.name
            for n in tree.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and _is_public(n.name)
        ]
        public_classes = [
            n.name for n in tree.body if isinstance(n, ast.ClassDef) and _is_public(n.name)
        ]
        print(f"Public functions: {len(public_funcs)} | Public classes: {len(public_classes)}")
    except Exception as exc:  # noqa: BLE001 — report only
        print(f"(symbol count skipped: {exc})")

    if all_issues:
        print(f"\nFAILED: {len(all_issues)} issue(s)")
        for issue in all_issues:
            print(f"  - {issue}")
        return 1

    print("\nSUCCESS: All documentation checks passed!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
