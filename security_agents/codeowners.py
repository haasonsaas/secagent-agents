from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from fnmatch import fnmatch
from typing import Any

import yaml


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


def resolve_codeowners_path(repo: Path, preferred_path: str | Path | None = None) -> Path | None:
    if preferred_path:
        preferred = Path(preferred_path)
        if preferred.is_absolute():
            return preferred if preferred.exists() else None
        candidate = repo / preferred
        return candidate if candidate.exists() else None

    candidates = [
        repo / "CODEOWNERS",
        repo / ".github" / "CODEOWNERS",
        repo / "docs" / "CODEOWNERS",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def load_reviewer_aliases(path: str | Path | None) -> dict[str, list[str]]:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    raw = yaml.safe_load(p.read_text()) or {}
    aliases: dict[str, list[str]] = {}
    for key, value in (raw.get("aliases", {}) or {}).items():
        names = [str(x).lstrip("@") for x in value] if isinstance(value, list) else [str(value).lstrip("@")]
        aliases[str(key).lstrip("@")] = [name for name in names if name]
    return aliases


def expand_owner_aliases(owners: list[str], aliases: dict[str, list[str]]) -> list[str]:
    expanded: list[str] = []
    for owner in owners:
        alias_targets = aliases.get(owner)
        if alias_targets:
            for target in alias_targets:
                if target not in expanded:
                    expanded.append(target)
            continue
        if owner not in expanded:
            expanded.append(owner)
    return expanded


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
