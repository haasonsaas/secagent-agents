from __future__ import annotations

from pydantic import BaseModel, Field


class Finding(BaseModel):
    id: str = Field(description="Stable short identifier")
    title: str
    severity: str
    confidence: float
    file: str
    line: int
    summary: str
    exploit_scenario: str
    evidence: list[str]
    recommended_fix: str


class DetectorOutput(BaseModel):
    vulnerability_class: str
    findings: list[Finding] = Field(default_factory=list)


class AcceptedFinding(BaseModel):
    id: str
    decision: str
    rationale: str
    updated_severity: str


class RejectedFinding(BaseModel):
    id: str
    decision: str
    rationale: str


class ManagerOutput(BaseModel):
    accepted: list[AcceptedFinding] = Field(default_factory=list)
    rejected: list[RejectedFinding] = Field(default_factory=list)


class ExploitabilityItem(BaseModel):
    id: str
    exploitability_score: float
    attacker_preconditions: list[str] = Field(default_factory=list)
    asset_impact: str
    confidence_rationale: str


class ExploitabilityOutput(BaseModel):
    assessments: list[ExploitabilityItem] = Field(default_factory=list)


class ValidationItem(BaseModel):
    id: str
    test_file_suggestion: str
    test_name: str
    preconditions: list[str] = Field(default_factory=list)
    steps: list[str] = Field(default_factory=list)
    assertions: list[str] = Field(default_factory=list)
    execution_commands: list[str] = Field(default_factory=list)
    expected_failure_before_fix: str


class ValidatorOutput(BaseModel):
    validation: list[ValidationItem] = Field(default_factory=list)


class FixItem(BaseModel):
    id: str
    strategy: str
    files_to_change: list[str] = Field(default_factory=list)
    patch_diff: str
    post_fix_checks: list[str] = Field(default_factory=list)


class FixerOutput(BaseModel):
    fixes: list[FixItem] = Field(default_factory=list)
