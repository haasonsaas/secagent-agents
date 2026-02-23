# secagent

Generic security-agent software implementing the architecture from the blog post:

- specialized detectors
- adversarial manager/judge
- validator for test-driven confirmation
- fixer for minimal remediation diffs

Built with the OpenAI Agents Python SDK.

## Quickstart (uv)

```bash
uv sync
export OPENAI_API_KEY="..."
```

Run against any repository:

```bash
uv run secagent --repo /path/to/target/repo --out security_report.json
```

Use built-in profile shortcuts:

```bash
uv run secagent --repo /path/to/target/repo --profile general
uv run secagent --repo /path/to/target/repo --profile llm
uv run secagent --repo /path/to/target/repo --profile fintech
uv run secagent --repo /path/to/target/repo --profile health
```

CI gate example:

```bash
uv run secagent --repo /path/to/target/repo --fail-on-severity high
```

Fast PR scan (diff-aware):

```bash
uv run secagent \
  --repo /path/to/target/repo \
  --changed-only \
  --changed-base origin/main \
  --changed-radius 1
```

Prioritize only strong/high-impact fixes:

```bash
uv run secagent \
  --repo /path/to/target/repo \
  --min-severity high \
  --min-confidence 0.75 \
  --max-fixes 15
```

Use policy-as-code defaults and suppressions:

```bash
uv run secagent \
  --repo /path/to/target/repo \
  --policy secagent.policy.yaml \
  --suppressions secagent.ignore.yaml
```

Run validator command execution (test-executor stage):

```bash
uv run secagent \
  --repo /path/to/target/repo \
  --run-validation \
  --validation-command-template "pytest {test_file} -k {test_name}"
```

Run validation in isolated worktree:

```bash
uv run secagent \
  --repo /path/to/target/repo \
  --run-validation \
  --validation-in-worktree
```

Auto-apply fixes and open a PR:

```bash
uv run secagent \
  --repo /path/to/target/repo \
  --run-validation \
  --validation-command-template "pytest {test_file} -k {test_name}" \
  --apply-fixes \
  --create-pr \
  --pr-base main
```

Auto-request reviewers from `CODEOWNERS` for auto PRs:

```bash
uv run secagent \
  --repo /path/to/target/repo \
  --apply-fixes \
  --create-pr \
  --auto-reviewers-from-codeowners \
  --codeowners-path CODEOWNERS
```

Enable patch guardrails:

```bash
uv run secagent \
  --repo /path/to/target/repo \
  --apply-fixes \
  --guardrail-max-files 40 \
  --guardrail-max-lines 800 \
  --guardrail-protected-path auth/ \
  --guardrail-protected-path migrations/
```

Create multiple PRs split by vulnerability class/severity:

```bash
uv run secagent \
  --repo /path/to/target/repo \
  --run-validation \
  --apply-fixes \
  --create-pr \
  --multi-pr-mode class-severity \
  --multi-pr-limit 8 \
  --pr-base main
```

Or with python module invocation:

```bash
uv run python -m security_agents.cli --repo /path/to/target/repo --out security_report.json
```

Run tests:

```bash
uv sync --dev
uv run pytest
```

Benchmark fixtures:

```bash
uv run secagent --repo benchmarks/fixtures/python_idor --profile general --out benchmark_report.json
uv run secagent-bench --profile general --strict
```

## Config

Default config is in `skills/default_security_skills.yaml`.
Research notes and source repos are in `skills/research_sources.md`.
LLM/agent-specific deep profile is in `skills/llm_security_skills.yaml`.
LLM profile research notes are in `skills/llm_research_sources.md`.

Tune these for your environment:

- `vulnerability_classes`: detector specializations and manager checks
- `include_globs` / `exclude_globs`: repository scope
- `max_files` / `max_file_bytes`: context budget
- `model`: model name used by all agents
- selection controls: `min_severity`, `only_severity`, `min_confidence`, `max_fixes` (CLI flags)
- policy controls via `secagent.policy.yaml`
- suppressions via `secagent.ignore.yaml`

Use the deep LLM profile:

```bash
uv run secagent \
  --repo /path/to/target/repo \
  --config skills/llm_security_skills.yaml \
  --min-severity medium \
  --min-confidence 0.6
```

Export SARIF for GitHub code scanning workflows:

```bash
uv run secagent \
  --repo /path/to/target/repo \
  --profile llm \
  --sarif-out secagent.sarif
```

Control SARIF scope explicitly:

```bash
# default scope: accepted findings
uv run secagent --repo /path/to/target/repo --sarif-out secagent.sarif

# with validation enabled, default scope becomes validated findings
uv run secagent --repo /path/to/target/repo --run-validation --sarif-out secagent.sarif

# force scope
uv run secagent --repo /path/to/target/repo --sarif-out secagent.sarif --sarif-scope accepted
uv run secagent --repo /path/to/target/repo --run-validation --sarif-out secagent.sarif --sarif-scope validated
```

Validation gating:

```bash
# Require reproducibility before selecting fixes
uv run secagent --repo /path/to/target/repo --run-validation --validation-gate pre

# Local apply only: require reproducibility pre-fix and passing tests post-fix
uv run secagent --repo /path/to/target/repo --run-validation --validation-gate pre-post --apply-fixes
```

The LLM profile goes deep on:

- direct and indirect prompt injection
- tool/function authz bypass
- memory/session cross-tenant leakage
- system prompt/policy leakage
- insecure output handling to execution sinks
- RAG poisoning and trust failures
- unsafe autonomy and missing approvals
- model downgrade/routing risks
- secret/data exposure to providers/logs
- sandbox/code-exec escape surfaces
- package hallucination/dependency confusion
- multimodal injection paths
- denial-of-wallet resource abuse
- identity/session confusion
- missing safety regression gates in CI/CD

The default skills pack now includes deep coverage for:

- BOLA/IDOR and missing authorization
- Mass assignment
- SQL/NoSQL injection
- Command injection
- Path traversal
- SSRF
- XSS and CSRF
- XXE
- Insecure deserialization/eval
- Open redirect
- Broken crypto/token handling
- Sensitive logging and hardcoded secrets
- Race conditions on financial/quota flows
- Insecure file upload/processing
- Dedicated sector packs: fintech and health

## Output

`security_report.json` includes:

- metadata (`generated_at`, repo, model)
- scanned file list
- accepted findings
- rejected findings
- validation test plans
- fix plans with candidate diffs
- validation execution results (if `--run-validation`)
- fix application results (if `--apply-fixes`)
- PR metadata (if `--create-pr`)
- multi-PR metadata (if `--multi-pr-mode` is not `none`)
- stage timing artifacts and context-cache metadata
- incremental finding markers (`is_new`, `fingerprint`)
- telemetry JSONL at `.secagent_runs/metrics.jsonl`

## Notes

- Applying diffs requires the target repo to be a git repository.
- By default, fix application refuses dirty repos; use `--allow-dirty-repo` to override.
- PR creation runs in temporary git worktrees so your current working tree is not switched.
- If validator commands are missing, secagent infers fallback test commands for common stacks (`pytest`, `go test`, `jest`/`npm test`, `cargo test`).
- Run artifacts are written per execution to `.secagent_runs/<run_id>/report.json`.
- CI workflow is available at `.github/workflows/secagent.yml` for weekly + manual scans with SARIF upload.
- CI now uses split modes: fast diff-aware PR scans and deeper scheduled/manual scans.
