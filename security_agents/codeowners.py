from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from fnmatch import fnmatch


@dataclass
class CodeownersRule:
    pattern: str
    owners: list[str]


def parse_codeowners(path: str | Path) -> list[CodeownersRule]:
    p = Path(path)
    if not p.exists():
        return []
    rules: list[CodeownersRule] = []
    for line in p.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        pattern = parts[0]
        owners = [o.lstrip("@") for o in parts[1:] if o.startswith("@")]
        if not owners:
            continue
        if pattern.startswith("/"):
            pattern = pattern[1:]
        rules.append(CodeownersRule(pattern=pattern, owners=owners))
    return rules


def _matches(pattern: str, path: str) -> bool:
    if pattern.endswith("/"):
        return path.startswith(pattern)
    if "*" in pattern or "?" in pattern or "[" in pattern:
        return fnmatch(path, pattern)
    return path == pattern or path.startswith(pattern + "/")


def owners_for_paths(paths: list[str], rules: list[CodeownersRule]) -> list[str]:
    owners: list[str] = []
    for path in paths:
        matched: list[str] = []
        for rule in rules:
            if _matches(rule.pattern, path):
                matched = rule.owners
        for owner in matched:
            if owner not in owners:
                owners.append(owner)
    return owners
