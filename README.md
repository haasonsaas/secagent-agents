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

CI gate example:

```bash
uv run secagent --repo /path/to/target/repo --fail-on-severity high
```

Run validator command execution (test-executor stage):

```bash
uv run secagent \
  --repo /path/to/target/repo \
  --run-validation \
  --validation-command-template "pytest {test_file} -k {test_name}"
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

## Config

Default config is in `skills/default_security_skills.yaml`.

Tune these for your environment:

- `vulnerability_classes`: detector specializations and manager checks
- `include_globs` / `exclude_globs`: repository scope
- `max_files` / `max_file_bytes`: context budget
- `model`: model name used by all agents

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

## Notes

- Applying diffs requires the target repo to be a git repository.
- By default, fix application refuses dirty repos; use `--allow-dirty-repo` to override.
- PR creation runs in temporary git worktrees so your current working tree is not switched.
- If validator commands are missing, secagent infers fallback test commands for common stacks (`pytest`, `go test`, `jest`/`npm test`, `cargo test`).
