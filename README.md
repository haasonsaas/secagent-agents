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

## Notes

- This version proposes patch diffs; it does not auto-apply changes.
- For production use, add sandboxed test execution and automated PR creation.
