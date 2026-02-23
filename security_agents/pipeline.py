from __future__ import annotations

import asyncio
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from agents import Agent, Runner

from security_agents.config import AppConfig, VulnerabilityClass
from security_agents.models import (
    DetectorOutput,
    FixerOutput,
    ManagerOutput,
    ValidatorOutput,
)
from security_agents.prompts import (
    DETECTOR_SYSTEM,
    FIXER_SYSTEM,
    MANAGER_SYSTEM,
    VALIDATOR_SYSTEM,
    detector_user_prompt,
    fixer_user_prompt,
    manager_user_prompt,
    validator_user_prompt,
)


@dataclass
class DetectorResult:
    vulnerability_class: str
    raw: DetectorOutput


@dataclass
class PipelineOutput:
    detector_results: list[DetectorResult]
    accepted_findings: list[dict[str, Any]]
    rejected_findings: list[dict[str, Any]]
    validation: list[dict[str, Any]]
    fixes: list[dict[str, Any]]
    scanned_files: list[str]


def _should_include(path: Path, include_globs: list[str], exclude_globs: list[str]) -> bool:
    posix = path.as_posix()
    if any(fnmatch(posix, g) for g in exclude_globs):
        return False
    if include_globs and not any(fnmatch(posix, g) for g in include_globs):
        return False
    return True


def build_code_context(root: Path, config: AppConfig) -> str:
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if _should_include(path.relative_to(root), config.include_globs, config.exclude_globs):
            files.append(path)
        if len(files) >= config.max_files:
            break

    chunks: list[str] = []
    for path in files:
        rel = path.relative_to(root).as_posix()
        raw = path.read_bytes()[: config.max_file_bytes]
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        chunks.append(f"\n### FILE: {rel}\n{text}\n")
    return "\n".join(chunks)


def list_scanned_files(root: Path, config: AppConfig) -> list[str]:
    scanned: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if _should_include(rel, config.include_globs, config.exclude_globs):
            scanned.append(rel.as_posix())
        if len(scanned) >= config.max_files:
            break
    return scanned


def _detector_agent(model: str, vuln: VulnerabilityClass) -> Agent:
    instructions = (
        f"{DETECTOR_SYSTEM}\n\n"
        f"You specialize in: {vuln.name}.\n"
        f"Definition: {vuln.description}\n"
        f"Specific analysis guidance:\n{vuln.detector_instructions}"
    )
    return Agent(
        name=f"Detector::{vuln.name}",
        instructions=instructions,
        model=model,
        output_type=DetectorOutput,
    )


def _manager_agent(model: str, vuln: VulnerabilityClass) -> Agent:
    checks = "\n".join(f"- {item}" for item in vuln.manager_checks)
    instructions = (
        f"{MANAGER_SYSTEM}\n\n"
        f"You are validating findings for: {vuln.name}.\n"
        f"Apply these checks:\n{checks}"
    )
    return Agent(
        name=f"Manager::{vuln.name}",
        instructions=instructions,
        model=model,
        output_type=ManagerOutput,
    )


def _validator_agent(model: str) -> Agent:
    return Agent(
        name="Validator",
        instructions=VALIDATOR_SYSTEM,
        model=model,
        output_type=ValidatorOutput,
    )


def _fixer_agent(model: str) -> Agent:
    return Agent(
        name="Fixer",
        instructions=FIXER_SYSTEM,
        model=model,
        output_type=FixerOutput,
    )


async def run_detector(vuln: VulnerabilityClass, model: str, code_context: str) -> DetectorResult:
    agent = _detector_agent(model, vuln)
    prompt = detector_user_prompt(vuln.name, vuln.description, vuln.detector_instructions, code_context)
    result = await Runner.run(agent, prompt)
    return DetectorResult(vulnerability_class=vuln.name, raw=result.final_output)


async def run_manager(
    vuln: VulnerabilityClass, model: str, detector_result: DetectorResult
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    agent = _manager_agent(model, vuln)
    prompt = manager_user_prompt(detector_result.raw.model_dump_json(), vuln.manager_checks)
    result = await Runner.run(agent, prompt)

    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    finding_by_id = {finding.id: finding for finding in detector_result.raw.findings}
    for item in result.final_output.accepted:
        payload: dict[str, Any] = item.model_dump()
        source = finding_by_id.get(item.id)
        if source:
            payload["finding"] = source.model_dump()
        else:
            payload["finding"] = {
                "id": item.id,
                "title": "Unknown finding id returned by manager",
                "severity": item.updated_severity,
                "confidence": 0.0,
                "file": "",
                "line": 0,
                "summary": "Manager accepted an id not present in detector output.",
                "exploit_scenario": "",
                "evidence": [],
                "recommended_fix": "",
            }
            payload["decision_warning"] = "accepted_id_not_found_in_detector_output"
        payload["vulnerability_class"] = vuln.name
        accepted.append(payload)
    for item in result.final_output.rejected:
        payload: dict[str, Any] = item.model_dump()
        payload["vulnerability_class"] = vuln.name
        if item.id in finding_by_id:
            payload["finding"] = finding_by_id[item.id].model_dump()
        rejected.append(payload)
    return accepted, rejected


async def run_validator(model: str, accepted_findings: list[dict[str, Any]], code_context: str) -> list[dict[str, Any]]:
    if not accepted_findings:
        return []
    agent = _validator_agent(model)
    prompt = validator_user_prompt(str(accepted_findings), code_context)
    result = await Runner.run(agent, prompt)
    return [item.model_dump() for item in result.final_output.validation]


async def run_fixer(
    model: str,
    accepted_findings: list[dict[str, Any]],
    validation: list[dict[str, Any]],
    code_context: str,
) -> list[dict[str, Any]]:
    if not accepted_findings:
        return []
    agent = _fixer_agent(model)
    prompt = fixer_user_prompt(str(accepted_findings), str(validation), code_context)
    result = await Runner.run(agent, prompt)
    return [item.model_dump() for item in result.final_output.fixes]


async def run_pipeline_async(root: Path, config: AppConfig) -> PipelineOutput:
    scanned_files = list_scanned_files(root, config)
    code_context = build_code_context(root, config)

    detector_results = await asyncio.gather(
        *(run_detector(vuln, config.model, code_context) for vuln in config.vulnerability_classes)
    )

    accepted_findings: list[dict[str, Any]] = []
    rejected_findings: list[dict[str, Any]] = []

    for vuln, result in zip(config.vulnerability_classes, detector_results):
        accepted, rejected = await run_manager(vuln, config.model, result)
        accepted_findings.extend(accepted)
        rejected_findings.extend(rejected)

    validation = await run_validator(config.model, accepted_findings, code_context)
    fixes = await run_fixer(config.model, accepted_findings, validation, code_context)

    return PipelineOutput(
        detector_results=detector_results,
        accepted_findings=accepted_findings,
        rejected_findings=rejected_findings,
        validation=validation,
        fixes=fixes,
        scanned_files=scanned_files,
    )


def run_pipeline(root: Path, config: AppConfig) -> PipelineOutput:
    return asyncio.run(run_pipeline_async(root, config))
