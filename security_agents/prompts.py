from __future__ import annotations

from dataclasses import dataclass


@dataclass
class StagePrompts:
    system: str
    user: str


DETECTOR_SYSTEM = """You are a specialized application security detector.
Find concrete, plausible vulnerabilities in the provided code.
Return high-signal, specific findings only."""

MANAGER_SYSTEM = """You are an adversarial security manager.
Your task is to reject weak findings and retain only actionable vulnerabilities.
Be skeptical and bias toward rejecting weak findings."""

VALIDATOR_SYSTEM = """You are a security validator focused on test-driven confirmation.
For each accepted finding, provide integration-style test ideas and exact test assertions.
Make validation steps executable and precise."""

FIXER_SYSTEM = """You are a security fixer.
Produce minimal, low-risk remediation plans and code patch diffs for validated vulnerabilities.
Keep changes focused and avoid broad refactors."""


def detector_user_prompt(vuln_name: str, vuln_desc: str, vuln_instr: str, code_context: str) -> str:
    return f"""
Vulnerability class: {vuln_name}
Description: {vuln_desc}
Detector instructions:
{vuln_instr}

Analyze the code context and return JSON:
{{
  "vulnerability_class": "{vuln_name}",
  "findings": [
    {{
      "id": "short-id",
      "title": "finding title",
      "severity": "low|medium|high|critical",
      "confidence": 0.0,
      "file": "path",
      "line": 1,
      "summary": "short summary",
      "exploit_scenario": "how attacker exploits",
      "evidence": ["specific code references"],
      "recommended_fix": "brief recommendation"
    }}
  ]
}}

Code context:
{code_context}
""".strip()


def manager_user_prompt(detector_json: str, manager_checks: list[str]) -> str:
    checks = "\n".join(f"- {item}" for item in manager_checks)
    return f"""
Review this detector output critically:
{detector_json}

Validation checks:
{checks}

Return JSON:
{{
  "accepted": [
    {{
      "id": "short-id",
      "decision": "accept",
      "rationale": "why real and impactful",
      "updated_severity": "low|medium|high|critical"
    }}
  ],
  "rejected": [
    {{
      "id": "short-id",
      "decision": "reject",
      "rationale": "why false positive or non-issue"
    }}
  ]
}}
""".strip()


def validator_user_prompt(accepted_findings_json: str, code_context: str) -> str:
    return f"""
Generate validation plans for these accepted findings:
{accepted_findings_json}

Return JSON:
{{
  "validation": [
    {{
      "id": "short-id",
      "test_file_suggestion": "path/to/test_file",
      "test_name": "test_name",
      "preconditions": ["..."],
      "steps": ["..."],
      "assertions": ["..."],
      "execution_commands": ["pytest tests/path.py -k test_name"],
      "expected_failure_before_fix": "what should fail"
    }}
  ]
}}

Code context:
{code_context}
""".strip()


def fixer_user_prompt(accepted_findings_json: str, validation_json: str, code_context: str) -> str:
    return f"""
Create minimal-risk remediation patch plans.
Findings:
{accepted_findings_json}

Validation:
{validation_json}

Return JSON:
{{
  "fixes": [
    {{
      "id": "short-id",
      "strategy": "brief strategy",
      "files_to_change": ["path"],
      "patch_diff": "unified diff text",
      "post_fix_checks": ["tests to run"]
    }}
  ]
}}

Code context:
{code_context}
""".strip()
