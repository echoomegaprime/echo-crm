"""Critical journey for the ECHO Certification Forge.

The Forge runs this argv (declared in ``.echo/certification.json``) inside its
isolated ``python:3.12-alpine`` sandbox, against the exact acquired commit,
with no network and no project dependencies installed -- there is no Node
here, so the Worker itself cannot actually run. The full behavioural suite
(``npm test`` -- typecheck plus real unit + end-to-end middleware tests,
imported and executed against the actual ``src/index.ts`` via Node's native
TypeScript support) runs in CI on this same commit; this journey proves the
artifact the Forge actually acquired is the intact, complete Worker source --
not that it currently boots.

This repository is TypeScript-only (a single Cloudflare Worker using Hono);
this journey therefore checks structural and textual invariants rather than
parsing Python.

Checks:
  1. The critical surfaces exist -- the Worker entrypoint, its test file,
     the pinned Node dependency manifest, and the TypeScript config.
  2. ``src/index.ts``'s bracket counts are balanced -- a cheap, tokenizer-free
     corruption/truncation check. It cannot prove syntax validity by itself
     (that is `tsc --noEmit` in `npm test`/CI); it can only prove the file
     was not truncated or grossly corrupted in transit.
  3. No install-lifecycle scripts have crept into ``package.json``.
  4. No hardcoded secret-shaped literals in the acquired source.
  5. The auth middleware still gates on an explicit PUBLIC_PATHS allowlist
     rather than exempting every GET request -- a regression here reopens
     the real bug found in this repo (the entire CRM read surface --
     contacts, companies, deals, revenue analytics, and a bulk
     /export/contacts dump -- was previously unauthenticated for every GET
     request regardless of path), and still calls the constant-time
     comparison rather than a raw ``!==``.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
from typing import NoReturn

CRITICAL_SURFACES = (
    "src/index.ts",
    "tests/auth.test.mjs",
    "package.json",
    "tsconfig.json",
)

INSTALL_LIFECYCLE_HOOKS = ("preinstall", "install", "postinstall", "prepare")

SECRET_LITERAL_PATTERN = re.compile(
    r'(?:api_key|secret|password|token)\s*=\s*["\'][a-zA-Z0-9_\-]{16,}["\']',
    re.IGNORECASE,
)

BALANCE_PAIRS = {"(": ")", "{": "}", "[": "]"}


def _fail(message: str) -> NoReturn:
    print(f"ECHO_CRM_CRITICAL_JOURNEY_FAILED: {message}", file=sys.stderr)
    raise SystemExit(1)


def check_critical_surfaces() -> None:
    for surface in CRITICAL_SURFACES:
        if not pathlib.Path(surface).exists():
            _fail(f"missing critical surface: {surface}")


def _source_text() -> str:
    return pathlib.Path("src/index.ts").read_text(encoding="utf-8")


def check_index_ts_balanced() -> None:
    text = _source_text()
    for open_ch, close_ch in BALANCE_PAIRS.items():
        opens, closes = text.count(open_ch), text.count(close_ch)
        if opens != closes:
            _fail(
                f"src/index.ts has mismatched '{open_ch}'/'{close_ch}' counts "
                f"({opens} vs {closes}) -- possible truncation or corruption"
            )


def check_no_install_hooks() -> None:
    manifest = pathlib.Path("package.json")
    try:
        scripts = json.loads(manifest.read_text(encoding="utf-8")).get("scripts", {})
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        _fail(f"package.json is not valid JSON: {exc}")
    present = sorted(hook for hook in INSTALL_LIFECYCLE_HOOKS if hook in scripts)
    if present:
        _fail(f"package.json reintroduced install-lifecycle script(s): {', '.join(present)}")


def check_no_hardcoded_secrets() -> None:
    match = SECRET_LITERAL_PATTERN.search(_source_text())
    if match:
        _fail(f"src/index.ts contains a hardcoded secret-shaped literal: {match.group(0)[:40]}...")


def check_auth_allowlist_not_blanket_get() -> None:
    text = _source_text()
    if "PUBLIC_PATHS.has(path)" not in text:
        _fail("auth middleware no longer gates on the PUBLIC_PATHS allowlist")
    if re.search(r"method\s*===\s*'GET'.*?\|\|.*?return next\(\)", text):
        _fail(
            "auth middleware appears to exempt GET requests broadly again -- "
            "this is the exact bug that exposed the entire CRM read surface"
        )
    if "timingSafeEqual(apiKey, expected)" not in text or "timingSafeEqual(bearer, expected)" not in text:
        _fail("auth middleware no longer calls timingSafeEqual for both credential paths")


def main() -> None:
    check_critical_surfaces()
    check_index_ts_balanced()
    check_no_install_hooks()
    check_no_hardcoded_secrets()
    check_auth_allowlist_not_blanket_get()
    print(
        "ECHO_CRM_CRITICAL_JOURNEY_OK "
        "critical_surfaces=4 install_hooks=0 hardcoded_secrets=0 auth_allowlist_intact=1"
    )


if __name__ == "__main__":
    main()
