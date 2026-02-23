from __future__ import annotations

import asyncio
from dataclasses import dataclass
from fnmatch import fnmatch
import hashlib
from pathlib import Path
import subprocess
import time
from typing import Any

from agents import Agent, Runner

from security_agents.config import AppConfig, VulnerabilityClass
from security_agents.models import (
    DetectorOutput,
    ExploitabilityOutput,
    FixerOutput,
    ManagerOutput,
    ValidatorOutput,
)
from security_agents.prompts import (
    DETECTOR_SYSTEM,
    EXPLOITABILITY_SYSTEM,
    FIXER_SYSTEM,
    MANAGER_SYSTEM,
    VALIDATOR_SYSTEM,
    detector_user_prompt,
    exploitability_user_prompt,
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
    stage_artifacts: dict[str, Any]
    context_cache_hit: bool
    context_cache_key: str | None


def _should_include(path: Path, include_globs: list[str], exclude_globs: list[str]) -> bool:
    posix = path.as_posix()
    if any(fnmatch(posix, g) for g in exclude_globs):
        return False
    if include_globs and not any(fnmatch(posix, g) for g in include_globs):
        return False
    return True


def _git_head_sha(root: Path) -> str | None:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(root),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def _context_cache_key(root: Path, config: AppConfig) -> str:
    sha = _git_head_sha(root) or "nogit"
    raw = f"{sha}|{config.max_files}|{config.max_file_bytes}|{'|'.join(config.include_globs)}|{'|'.join(config.exclude_globs)}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def _context_cache_path(root: Path, cache_key: str) -> Path:
    cache_dir = root / ".secagent_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / f"context_{cache_key}.txt"


def _is_within_focus(path: Path, focus_files: set[str] | None, focus_radius: int) -> bool:
    if not focus_files:
        return True
    posix = path.as_posix()
    if posix in focus_files:
        return True
    if focus_radius <= 0:
        return False
    for focus in focus_files:
        focus_parent = Path(focus).parent
        current = path.parent
        for _ in range(focus_radius):
            if str(current.as_posix()) == str(focus_parent.as_posix()):
                return True
            if str(current) == ".":
                break
            current = current.parent
    return False


def build_code_context(
    root: Path,
    config: AppConfig,
    focus_files: set[str] | None = None,
    focus_radius: int = 0,
) -> tuple[str, bool, str | None]:
    cache_key = _context_cache_key(root, config)
    cache_path = _context_cache_path(root, cache_key)
    if config.use_context_cache and cache_path.exists():
        return cache_path.read_text(), True, cache_key

    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if not _is_within_focus(rel, focus_files, focus_radius):
            continue
        if _should_include(rel, config.include_globs, config.exclude_globs):
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
    context = "\n".join(chunks)
    if config.use_context_cache:
        cache_path.write_text(context)
    return context, False, cache_key


def list_scanned_files(
    root: Path,
    config: AppConfig,
    focus_files: set[str] | None = None,
    focus_radius: int = 0,
) -> list[str]:
    scanned: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if not _is_within_focus(rel, focus_files, focus_radius):
            continue
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


def _exploitability_agent(model: str) -> Agent:
    return Agent(
        name="ExploitabilityScorer",
        instructions=EXPLOITABILITY_SYSTEM,
        model=model,
        output_type=ExploitabilityOutput,
    )


def _fixer_agent(model: str) -> Agent:
    return Agent(
        name="Fixer",
        instructions=FIXER_SYSTEM,
        model=model,
        output_type=FixerOutput,
    )


async def _run_with_timeout(agent: Agent, prompt: str, timeout_seconds: int):
    return await asyncio.wait_for(Runner.run(agent, prompt), timeout=timeout_seconds)


async def run_detector(vuln: VulnerabilityClass, model: str, code_context: str, timeout_seconds: int) -> DetectorResult:
    agent = _detector_agent(model, vuln)
    prompt = detector_user_prompt(vuln.name, vuln.description, vuln.detector_instructions, code_context)
    result = await _run_with_timeout(agent, prompt, timeout_seconds)
    return DetectorResult(vulnerability_class=vuln.name, raw=result.final_output)


async def run_manager(
    vuln: VulnerabilityClass,
    model: str,
    detector_result: DetectorResult,
    timeout_seconds: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    agent = _manager_agent(model, vuln)
    prompt = manager_user_prompt(detector_result.raw.model_dump_json(), vuln.manager_checks)
    result = await _run_with_timeout(agent, prompt, timeout_seconds)

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
        payload = item.model_dump()
        payload["vulnerability_class"] = vuln.name
        if item.id in finding_by_id:
            payload["finding"] = finding_by_id[item.id].model_dump()
        rejected.append(payload)

    artifact = {
        "vulnerability_class": vuln.name,
        "accepted_ids": [x.get("id") for x in accepted],
        "rejected_ids": [x.get("id") for x in rejected],
    }
    return accepted, rejected, artifact


async def run_exploitability(
    model: str,
    accepted_findings: list[dict[str, Any]],
    code_context: str,
    timeout_seconds: int,
) -> list[dict[str, Any]]:
    if not accepted_findings:
        return []
    agent = _exploitability_agent(model)
    prompt = exploitability_user_prompt(str(accepted_findings), code_context)
    result = await _run_with_timeout(agent, prompt, timeout_seconds)
    return [item.model_dump() for item in result.final_output.assessments]


async def run_validator(
    model: str,
    accepted_findings: list[dict[str, Any]],
    code_context: str,
    timeout_seconds: int,
    max_validation_items: int,
) -> list[dict[str, Any]]:
    if not accepted_findings:
        return []
    agent = _validator_agent(model)
    prompt = validator_user_prompt(str(accepted_findings[:max_validation_items]), code_context)
    result = await _run_with_timeout(agent, prompt, timeout_seconds)
    return [item.model_dump() for item in result.final_output.validation]


async def run_fixer(
    model: str,
    accepted_findings: list[dict[str, Any]],
    validation: list[dict[str, Any]],
    code_context: str,
    timeout_seconds: int,
    max_fix_items: int,
) -> list[dict[str, Any]]:
    if not accepted_findings:
        return []
    agent = _fixer_agent(model)
    prompt = fixer_user_prompt(str(accepted_findings[:max_fix_items]), str(validation[:max_fix_items]), code_context)
    result = await _run_with_timeout(agent, prompt, timeout_seconds)
    return [item.model_dump() for item in result.final_output.fixes]


async def run_pipeline_async(
    root: Path,
    config: AppConfig,
    focus_files: set[str] | None = None,
    focus_radius: int = 0,
) -> PipelineOutput:
    stage_timing: dict[str, float] = {}

    t0 = time.monotonic()
    scanned_files = list_scanned_files(root, config, focus_files=focus_files, focus_radius=focus_radius)
    code_context, context_cache_hit, context_cache_key = build_code_context(
        root,
        config,
        focus_files=focus_files,
        focus_radius=focus_radius,
    )
    stage_timing["context_build_seconds"] = round(time.monotonic() - t0, 3)

    t1 = time.monotonic()
    detector_results = await asyncio.gather(
        *(
            run_detector(vuln, config.model, code_context, config.stage_timeout_seconds)
            for vuln in config.vulnerability_classes
        )
    )
    stage_timing["detectors_seconds"] = round(time.monotonic() - t1, 3)

    accepted_findings: list[dict[str, Any]] = []
    rejected_findings: list[dict[str, Any]] = []
    manager_artifacts: list[dict[str, Any]] = []

    t2 = time.monotonic()
    for vuln, result in zip(config.vulnerability_classes, detector_results):
        accepted, rejected, mgr_art = await run_manager(vuln, config.model, result, config.stage_timeout_seconds)
        accepted_findings.extend(accepted)
        rejected_findings.extend(rejected)
        manager_artifacts.append(mgr_art)
    stage_timing["managers_seconds"] = round(time.monotonic() - t2, 3)

    t3 = time.monotonic()
    exploitability = await run_exploitability(config.model, accepted_findings, code_context, config.stage_timeout_seconds)
    stage_timing["exploitability_seconds"] = round(time.monotonic() - t3, 3)
    exploit_by_id = {str(item.get("id", "")): item for item in exploitability}
    for finding in accepted_findings:
        finding_id = str(finding.get("id", ""))
        if finding_id in exploit_by_id:
            finding["exploitability"] = exploit_by_id[finding_id]

    t4 = time.monotonic()
    validation = await run_validator(
        config.model,
        accepted_findings,
        code_context,
        config.stage_timeout_seconds,
        config.max_validation_items,
    )
    stage_timing["validator_seconds"] = round(time.monotonic() - t4, 3)
    t5 = time.monotonic()
    fixes = await run_fixer(
        config.model,
        accepted_findings,
        validation,
        code_context,
        config.stage_timeout_seconds,
        config.max_fix_items,
    )
    stage_timing["fixer_seconds"] = round(time.monotonic() - t5, 3)

    stage_artifacts = {
        "detectors": [
            {"vulnerability_class": item.vulnerability_class, "findings_count": len(item.raw.findings)}
            for item in detector_results
        ],
        "managers": manager_artifacts,
        "exploitability": exploitability,
        "validation_count": len(validation),
        "fixes_count": len(fixes),
        "timing": stage_timing,
    }

    return PipelineOutput(
        detector_results=detector_results,
        accepted_findings=accepted_findings,
        rejected_findings=rejected_findings,
        validation=validation,
        fixes=fixes,
        scanned_files=scanned_files,
        stage_artifacts=stage_artifacts,
        context_cache_hit=context_cache_hit,
        context_cache_key=context_cache_key,
    )


def run_pipeline(
    root: Path,
    config: AppConfig,
    focus_files: set[str] | None = None,
    focus_radius: int = 0,
) -> PipelineOutput:
    return asyncio.run(run_pipeline_async(root, config, focus_files=focus_files, focus_radius=focus_radius))
