from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass
class SecagentPolicy:
    min_confidence: float
    min_risk_score: float
    require_validation_for_critical: bool
    deny_path_prefixes: list[str]


DEFAULT_POLICY = SecagentPolicy(
    min_confidence=0.0,
    min_risk_score=0.0,
    require_validation_for_critical=False,
    deny_path_prefixes=["auth/", "security/", "crypto/", "migrations/"],
)


def load_policy(path: str | Path | None) -> SecagentPolicy:
    if not path:
        return DEFAULT_POLICY
    p = Path(path)
    if not p.exists():
        return DEFAULT_POLICY
    raw = yaml.safe_load(p.read_text()) or {}
    auto_fix = raw.get("auto_fix", {})
    return SecagentPolicy(
        min_confidence=float(auto_fix.get("min_confidence", DEFAULT_POLICY.min_confidence)),
        min_risk_score=float(auto_fix.get("min_risk_score", DEFAULT_POLICY.min_risk_score)),
        require_validation_for_critical=bool(
            auto_fix.get("require_validation_for_critical", DEFAULT_POLICY.require_validation_for_critical)
        ),
        deny_path_prefixes=[str(x) for x in auto_fix.get("deny_path_prefixes", DEFAULT_POLICY.deny_path_prefixes)],
    )
